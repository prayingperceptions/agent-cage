"""The cage: a fail-closed enforcement point for AI agent actions.

Every action passes through :meth:`Cage.guard`, which applies the kill switch,
actor identity, and the configured :class:`~cage.policy.Policy` in that order.
Actions the policy marks "ask" mint approval tickets; a second human must
approve them before they proceed (separation of duties). Everything is
append-only audit-logged on a hash chain.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field

from .audit import AuditLog
from .budget import Budget
from .policy import Policy
from .tickets import (
    ApprovalTicket,
    SelfApprovalError,
    TicketAlreadyResolved,
    TicketExpired,
    TicketStore,
    UnauthorizedApproverError,
    normalize_identity,
)


class CageKilled(Exception):
    """Signalled when code chooses to stop dead because the cage was killed.

    Note: :meth:`Cage.guard` itself never raises this — after the kill switch
    is thrown, guard returns ``Decision("deny", ...)`` instead. This exception
    exists for callers that prefer to halt execution on a killed cage rather
    than carry on with denials.
    """


@dataclass
class Decision:
    """The outcome of a single :meth:`Cage.guard` evaluation."""

    verdict: str  # "allow" | "ask" | "deny"
    reason: str
    action: str
    ticket_id: str | None = None


class Cage:
    """Fail-closed action enforcement point.

    Thread-safe. The kill flag is checked under a lock; no lock is held across
    user callbacks (there are none). guard() never blocks and never raises —
    after kill it returns deny decisions.
    """

    def __init__(
        self,
        policy: Policy,
        budget: Budget | float | int | None = None,
        audit_path: str | None = None,
        ticket_ttl: float = 3600.0,
        approvers: set[str] | frozenset[str] | list[str] | tuple[str, ...] | None = None,
        audit_key: bytes | None = None,
    ) -> None:
        self._policy = policy
        # Strict budget validation: bool/str slip past isinstance checks by
        # accident — reject them loudly instead of failing confusingly later.
        if isinstance(budget, bool) or not isinstance(
            budget, (Budget, int, float, type(None))
        ):
            raise TypeError(
                "budget must be a Budget, a number, or None, "
                f"got {type(budget).__name__}"
            )
        if isinstance(budget, (int, float)):
            budget = Budget(float(budget))
        self._budget = budget
        self._audit = AuditLog(audit_path, key=audit_key)
        self._tickets = TicketStore()
        # A zero/negative TTL would mint tickets that are born expired and can
        # never be approved — fail fast on misconfiguration instead.
        if float(ticket_ttl) <= 0:
            raise ValueError(
                f"ticket_ttl must be positive, got {ticket_ttl!r}"
            )
        self._ticket_ttl = float(ticket_ttl)
        # Approver allowlist: without it, the approver != requester check
        # compares two caller-supplied strings, which an in-process attacker
        # defeats by typing two different strings. With it, only named
        # identities may resolve tickets. None = no allowlist (advisory mode;
        # see README trust model).
        if approvers is not None:
            normalized = set()
            for a in approvers:
                normalized.add(normalize_identity(a))
            self._approvers: set[str] | None = normalized
        else:
            self._approvers = None
        self._lock = threading.Lock()
        self._killed = False
        self._kill_reason = ""

    # ------------------------------------------------------------------ guard
    @staticmethod
    def _context_hash(context: dict) -> str:
        """sha256 of canonical JSON (sorted keys, default=str) of the context."""
        blob = json.dumps(context, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _deny(self, reason: str, action: str, actor: str | None = None,
             ticket_id: str | None = None) -> Decision:
        """Build an audited deny decision (single choke point)."""
        decision = Decision("deny", reason=reason, action=action,
                            ticket_id=ticket_id)
        entry: dict = {
            "type": "guard",
            "action": action,
            "verdict": "deny",
            "reason": reason,
        }
        if actor is not None:
            entry["actor"] = actor
        if ticket_id is not None:
            entry["ticket_id"] = ticket_id
        self._audit.record(entry)
        return decision

    def guard(self, action: str, context: dict) -> Decision:
        """Evaluate *action* under *context*. Never blocks, never raises.

        Any unexpected internal error becomes a deny decision (fail-closed),
        never an exception propagating to the host loop.
        """
        try:
            return self._guard_inner(action, context)
        except Exception as exc:  # noqa: BLE001 - fail-closed by contract
            action_s = action if isinstance(action, str) else repr(action)
            decision = Decision(
                "deny",
                reason=f"guard internal error: {type(exc).__name__}",
                action=action_s,
            )
            try:
                self._audit.record(
                    {
                        "type": "guard",
                        "action": action_s,
                        "verdict": "deny",
                        "reason": decision.reason,
                    }
                )
            except Exception:
                pass  # audit must never break the fail-closed guarantee
            return decision

    def _guard_inner(self, action: str, context: dict) -> Decision:
        """Evaluate *action* under *context*.

        Order: kill switch -> input validation -> actor identity ->
        policy verdict -> ticket store.
        """
        # 1. Kill switch (checked under the same lock kill() uses).
        with self._lock:
            killed = self._killed
            kill_reason = self._kill_reason
        if killed:
            decision = Decision(
                "deny", reason=f"cage killed: {kill_reason}", action=action
            )
            self._audit.record(
                {
                    "type": "guard",
                    "action": action,
                    "verdict": "deny",
                    "reason": decision.reason,
                }
            )
            return decision

        # 2. Input validation: hostile types become denies, never exceptions.
        if not isinstance(action, str) or not action:
            return self._deny("invalid action: must be a non-empty string",
                              action=repr(action))
        if not isinstance(context, dict):
            return self._deny("invalid context: must be a dict", action=action)

        # 3. Actor identity is mandatory.
        actor = context.get("actor")
        if not isinstance(actor, str) or not actor.strip():
            return self._deny(
                "anonymous action: no actor in context", action=action
            )

        # 3. Policy verdict (fail-closed: unknown actions -> "deny").
        verdict = self._policy.match(action)
        if verdict == "allow":
            decision = Decision(
                "allow",
                reason=f"allowed by policy for action '{action}'",
                action=action,
            )
            self._audit.record(
                {
                    "type": "guard",
                    "action": action,
                    "actor": actor,
                    "verdict": "allow",
                    "reason": decision.reason,
                }
            )
            return decision
        if verdict == "deny":
            decision = Decision(
                "deny",
                reason=f"denied by policy for action '{action}'",
                action=action,
            )
            self._audit.record(
                {
                    "type": "guard",
                    "action": action,
                    "actor": actor,
                    "verdict": "deny",
                    "reason": decision.reason,
                }
            )
            return decision

        # 5. "ask": reuse an approved, unexpired ticket for this action+context
        #    if one exists; otherwise atomically get-or-mint a pending ticket
        #    (concurrent identical asks collapse to one ticket).
        context_hash = self._context_hash(context)
        ticket = self._tickets.find_approved(action, context_hash)
        if ticket is not None:
            decision = Decision(
                "allow",
                reason=f"approved via ticket {ticket.id}",
                action=action,
            )
            self._audit.record(
                {
                    "type": "guard",
                    "action": action,
                    "actor": actor,
                    "verdict": "allow",
                    "reason": decision.reason,
                    "ticket_id": ticket.id,
                }
            )
            return decision

        new_ticket, was_created = self._tickets.get_or_create(
            action=action,
            context=dict(context),
            context_hash=context_hash,
            requester=actor,
            ttl=self._ticket_ttl,
        )
        decision = Decision(
            "ask",
            reason=(
                f"action '{action}' requires human approval"
                + ("" if was_created else f" (ticket {new_ticket.id} already pending)")
            ),
            action=action,
            ticket_id=new_ticket.id,
        )
        self._audit.record(
            {
                "type": "guard",
                "action": action,
                "actor": actor,
                "verdict": "ask",
                "reason": decision.reason,
                "ticket_id": new_ticket.id,
            }
        )
        return decision

    # ------------------------------------------------------------ tickets
    def _check_approver(self, approver: str) -> str:
        """Validate the approver identity and the allowlist.

        Returns the normalized approver. Raises ValueError on empty/non-str,
        UnauthorizedApproverError when an allowlist is configured and the
        approver is not on it.
        """
        normalized = normalize_identity(approver)  # ValueError on empty/non-str
        if self._approvers is not None and normalized not in self._approvers:
            raise UnauthorizedApproverError(
                f"approver {approver!r} is not on the approver allowlist"
            )
        return normalized

    def _resolve(self, ticket_id: str, verdict: str, approver: str,
                 reason: str = "") -> ApprovalTicket:
        """Shared approve/deny path: kill check -> approver check ->
        atomic store resolution. All failures are audit-logged, then raised.
        """
        entry_base: dict = {
            "type": "approve" if verdict == "approved" else "deny",
            "ticket_id": ticket_id,
            "approver": approver,
        }
        try:
            approver_n = self._check_approver(approver)
            with self._lock:
                if self._killed:
                    raise CageKilled(
                        f"cage is killed ({self._kill_reason}): "
                        "ticket resolution refused"
                    )
            # Atomic compare-and-swap inside the store: exists -> pending ->
            # unexpired -> not self-approval, all under one lock (no TOCTOU).
            ticket = self._tickets.resolve(
                ticket_id,
                verdict,
                approver_n,
                resolution_reason=reason or None,
            )
        except Exception as exc:  # noqa: BLE001 - audit then re-raise
            self._audit.record(
                {**entry_base,
                 "outcome": "error",
                 "error": f"{type(exc).__name__}: {exc}"}
            )
            raise
        self._audit.record(
            {**entry_base,
             "outcome": verdict,
             "reason": reason or None}
        )
        return ticket

    def approve(self, ticket_id: str, approver: str) -> ApprovalTicket:
        """Approve a pending ticket.

        Enforces separation of duties (approver != requester, normalized)
        and, when configured, the approver allowlist. Refused after kill().
        Returns a snapshot — mutating it cannot affect the store.
        """
        return self._resolve(ticket_id, "approved", approver)

    def deny(self, ticket_id: str, approver: str, reason: str = "") -> ApprovalTicket:
        """Deny a pending ticket. Same checks as approve()."""
        return self._resolve(ticket_id, "denied", approver, reason=reason)

    # -------------------------------------------------------------------- kill
    def kill(self, reason: str = "") -> None:
        """Throw the kill switch. Irreversible, thread-safe, idempotent."""
        with self._lock:
            if self._killed:
                return  # double-kill is a no-op
            self._killed = True
            self._kill_reason = reason
        self._audit.record({"type": "kill", "reason": reason})

    @property
    def killed(self) -> bool:
        with self._lock:
            return self._killed

    @property
    def budget(self) -> Budget | None:
        """The configured Budget, or None if uncapped."""
        return self._budget

    # ------------------------------------------------------------------ budget
    def spend(self, amount: float, action: str = "") -> bool:
        """Attempt to spend against the budget cap.

        Returns False when over cap, on invalid amounts, or when the cage is
        killed; True when no budget is configured (still audit-logged).
        Failed attempts are audit-logged — never raise past the audit call.
        """
        with self._lock:
            killed = self._killed
        allowed = False
        error: str | None = None
        if killed:
            error = "cage killed"
        elif self._budget is None:
            allowed = True
        else:
            try:
                allowed = self._budget.spend(amount)
            except (ValueError, TypeError) as e:
                error = f"{type(e).__name__}: {e}"
        self._audit.record(
            {
                "type": "spend",
                "action": action,
                "amount": amount,
                "allowed": allowed,
                "error": error,
            }
        )
        return allowed

    # -------------------------------------------------------------------- audit
    def audit_log(self):
        """Iterate over audit entries (dicts, oldest first)."""
        return iter(self._audit)

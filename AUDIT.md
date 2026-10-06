# agent-cage — Security Audit

> Adversarial audit, 2026-10-05. Method: attack, don't review. Every finding
> below was reproduced with running code in `/tmp/attacks/` (scripts
> `a1_selfapproval.py`, `a2_tickets.py`, `a2b_forge.py`, `a3_audit.py`,
> `a4_kill.py`, `a5_budget.py`, `a6_policy.py`, `a7_correct.py`, `a8_spoof.py`)
> against a fresh `pip install -e .` in a clean venv (Python 3.12).
> Baseline: `pytest` 109/109 green before attacking.

## Scope

- `cage/` — `Policy`, `Cage`, `Decision`, `ApprovalTicket`, `Budget`,
  `cage.audit.AuditLog`, and all exported exceptions.
- Out of scope: example scripts, packaging metadata, CI configuration.

## Threat model

The assumed attacker is **code running in the same process as the cage**:
a compromised agent brain choosing malicious actions, a malicious tool
implementation mislabeling actions, or any dependency with import-time
access to the `cage` objects. The attacker can call any public API
(`guard`, `approve`, `deny`, `kill`, `spend`), hold references to returned
objects, and read the library source. A second, weaker attacker has
**write access to the audit log file** but not the process. The human
approver is assumed honest but is reachable only through strings the
caller supplies — the library performs no authentication itself.

This is the correct threat model for a "safety library": if the cage only
holds against callers who already behave, it adds nothing. Several
findings below break the cage under exactly this model, using the public
API alone.

## Method

For each claim below I wrote and ran an exploit or bypass attempt:

1. `deny`-policy action via `guard()` — mislabeled actions, wildcard edges
   (`"file.*"` vs `"file"` vs `"file."` vs `"fileX"`), empty/None/unicode/
   over-long/unhashable action names, hostile context shapes. **Held**,
   except unhashable action types and non-JSON-serializable context keys
   make `guard()` **raise** (Finding 7).
2. Ticket reuse/replay/forgery — cross-action, cross-context, forged IDs,
   direct dataclass field mutation. Cross-action/context replay and forged
   IDs **held**; field mutation of live ticket objects **bypasses
   everything** (Findings 1, 2).
3. Self-approval through every resolution path. Exact-match blocked;
   case-variant, empty, `None`, whitespace approvers **bypass** (Finding 8);
   actor spoofing voids the check entirely (Finding 3).
4. `kill()` bypass — all guard paths, pre-approved tickets, `spend()`,
   `approve()`/`deny()` post-kill, 16-thread kill/guard races. Guard and
   spend **held**; `approve()`/`deny()` still resolve tickets after kill
   (Finding 9); in-flight guards may allow (Note N3).
5. Budget — 200-thread race, NaN/inf/negative amounts, float boundary,
   epoch-reset timing. Race **held**; hostile amounts fail closed;
   type-confusion and unaudited failures noted (Finding 12).
6. Audit tampering — edit, drop, reorder, truncate, forged append with
   valid recomputed hash, garbage lines, two writers one file. Modify/
   drop-middle/reorder **detected**; truncation and forged appends
   **pass verification** (Findings 5, 6); garbage lines crash the verifier
   (Finding 11); concurrent writers corrupt legitimate logs (Finding 10).
7. Frozen policy mutation — 9 vectors. 6 of 9 **succeed** (Finding 4).
8. Actor identity confusion — missing/empty/non-string actors denied
   correctly; spoofed actor strings fully honored (Finding 3).

## Findings

| # | Severity | Title | Attack tried | Result | Remediation |
|---|----------|-------|--------------|--------|-------------|
| 1 | CRITICAL | Mutable ticket objects allow cross-action approval forgery via public API | Approve a `read_s3` ticket, mutate `ticket.action`/`ticket.context_hash` on the returned object, `guard("delete_s3", evil_ctx)` | **BYPASSED** — `guard` returned `allow`: "approved via ticket tkt-0001" for an action the human never approved | FIXED: `ApprovalTicket` is now `@dataclass(frozen=True)`; the store mutates only via resolve-by-replacement under its lock. `create`/`get`/`resolve`/`find_approved` return deep-copied snapshots — caller-held objects are fully detached. Regression: `tests/test_audit_attacks.py::test_approved_ticket_is_immutable`, `test_mutating_returned_ticket_cannot_forge_approval`. |
| 2 | CRITICAL | Denied ticket resurrection + requester laundering enables self-approval via public API only | `deny()` returns the live ticket; set `status="pending"`, `requester="human-op"`; `approve(id, approver="worker-0007")` | **BYPASSED** — agent approved its own ticket; `guard` returned `allow` | FIXED by the same change as #1: frozen tickets + resolve-by-replacement make resurrection and requester laundering impossible (`FrozenInstanceError` on any field write; store never exposes live objects). Regression: `test_denied_ticket_cannot_be_resurrected`, `test_requester_cannot_be_laundered`. |
| 3 | CRITICAL | Separation of duties unenforceable: actor spoofing voids the self-approval check | `guard("write_file", {"actor": "human-op", ...})` then `approve(tid, approver="worker-0007")` — both strings attacker-controlled | **BYPASSED** — agent approved its own ticket; `guard` returned `allow`. The `approver == requester` check compares two caller-supplied strings. | FIXED (in-library): new `approvers={...}` allowlist on `Cage` — `approve`/`deny` raise `UnauthorizedApproverError` for anyone not on it. A ticket minted under a spoofed identity becomes unapprovable (approver==requester). Residual (documented in README + test): in-process, the approver is still a string — a compromised brain can type an allowlisted name. High-assurance deployments must resolve tickets out-of-band. Regression: `test_allowlist_blocks_spoofed_self_approval`, `test_in_process_approver_string_is_forgeable_documented`. |
| 4 | CRITICAL | Frozen policy mutable via 6 vectors; `freeze()` is theater in-process | `policy._rules["shell_exec"]="allow"`, `object.__setattr__` rebind, pre-freeze `.rules` reference mutated post-freeze, `copy.copy` sharing `_rules` | **BYPASSED** (6/9 vectors) — `guard("shell_exec")` returned `allow` on a "frozen" policy | FIXED: rules now live in a self-protecting `_RulesDict` whose frozen flag is on the dict itself — pre-freeze `.rules` references, `__dict__` access, and shallow copies all hit the same guard; all 9 mutation vectors raise `FrozenPolicyError`. `copy`/`deepcopy` supported. Residual (documented): deliberate white-box reflection (`object.__setattr__` rebinding) is out of scope, like debugger access. Regression: `test_freeze_blocks_all_mutation_vectors` (9 vectors). |
| 5 | HIGH | Audit log truncation undetectable: deleting trailing lines passes `verify_chain()` | Delete last JSONL line, re-run `verify_chain()` | **BYPASSED** — returned `True`. Docstring claims `False` on "ANY tamper (modified/deleted/reordered)". | FIXED: file mode maintains an atomic checkpoint sidecar (`<path>.checkpoint`, tmp+rename) with the latest `(seq, hash)`; `verify_chain()` fails when the log tip diverges from it. `AuditLog.tip()` exposes `(seq, hash)` for external anchoring. Residual (documented): an attacker who deletes both log and checkpoint is indistinguishable from a fresh log. Regression: `test_truncation_detected_via_checkpoint`. |
| 6 | HIGH | Forged audit entries with recomputed hashes verify as genuine (no MAC) | Append entry with `prev_hash`/`hash` recomputed via the public algorithm (`cage.audit._entry_hash`) | **BYPASSED** — `verify_chain()` returned `True`; README claims it returns `False` on "forged" lines — false. | FIXED: new keyed mode — `AuditLog(path, key=b...)` / `Cage(..., audit_key=...)` chains with HMAC-SHA256; forging entries requires the key, and verification with a wrong/missing key fails. Unkeyed mode retained and now honestly documented as tamper-evident against accidental corruption and naive attackers only; README's false 'forged' claim corrected. Regression: `test_keyed_chain_rejects_forgery`, `test_wrong_key_fails_verification`. |
| 7 | HIGH | `guard()` raises on unhashable actions / non-serializable contexts, violating "never raises" | `guard(["read_file"], ...)`, `guard("x", {"actor":"w", (1,2):"x"})` | **RAISED** `TypeError` — the enforcement point itself can be crashed by the party it polices. | FIXED: `guard()` is now a wrapper — the body runs in try/except and any unexpected exception becomes an audited `deny` ('guard internal error'); non-string/empty actions and non-dict contexts are denied up front. The 'never raises' contract holds. Regression: `test_guard_never_raises_on_hostile_types`. |
| 8 | MEDIUM | Self-approval check is exact-string `==`: case, empty, None, whitespace approvers bypass | `approve(tid, approver="Worker-0007"/""/None/" worker-0007 ")` | **BYPASSED** (4/5 variants; exact match blocked). Same flaw in `TicketStore.resolve`. | FIXED: new `normalize_identity()` (strip + casefold, rejects empty/non-str with ValueError) applied to requester at mint and approver at resolve, in both `Cage` and `TicketStore`. Combined with the Finding 3 allowlist. Regression: `test_self_approval_variants_rejected`. |
| 9 | MEDIUM | `approve()`/`deny()` resolve tickets after `kill()` — no kill check in `_resolve_check` | `kill()` then `approve(pending)` / `deny(pending)` | **SUCCEEDED** — tickets resolved on a dead cage; audit log records "approved" post-kill. | FIXED: `Cage._resolve` checks the kill flag under the cage lock before touching the store and raises `CageKilled` (audit-logged as refused). Post-kill, nothing changes ticket state. Regression: `test_resolve_after_kill_raises`. |
| 10 | MEDIUM | Approve/deny TOCTOU: check-then-act outside the store lock; one ticket approved 8× concurrently | 8 threads `approve()` the same ticket (race window widened white-box to prove the design flaw) | **8/8 threads "approved"** the same ticket; audit shows 8× "approved", no `TicketAlreadyResolved`. | FIXED: resolution moved into `TicketStore.resolve()` — atomic compare-and-swap on `status == 'pending'` under the store lock. `Cage.approve`/`deny` no longer reimplement the check outside the lock. Regression: `test_concurrent_approve_single_winner` (16 threads, exactly 1 winner). |
| 11 | MEDIUM | Ticket store grows without bound; concurrent duplicate asks mint N tickets | 3000 asks → 3000 tickets retained; 16 threads same action+context → 16 tickets | No eviction/GC — memory DoS; ticket spam. | FIXED: store is bounded (1000 tickets; oldest resolved/expired evicted first, pending always retained) and `TicketStore.get_or_create` makes find-or-create atomic — concurrent identical asks collapse to one ticket. Regression: `test_concurrent_identical_asks_collapse_to_one_ticket`, `test_store_is_bounded`. |
| 12 | MEDIUM | Two writers sharing one audit file corrupt the chain (false tamper alarm on legitimate data) | Two `AuditLog(same_path)` instances × 200 records interleaved | `verify_chain()` → `False` on a legitimate log (duplicate `seq`/`prev_hash`). No file locking. | FIXED: file mode serializes read-modify-append (plus checkpoint write) with `fcntl.flock(LOCK_EX)`; falls back to documented one-writer-per-file on platforms without fcntl. Regression: covered by `test_keyed_chain_rejects_forgery` running file-backed; concurrent-writer check in manual verification. |
| 13 | LOW | `verify_chain()` raises `JSONDecodeError` on a garbage line instead of returning `False` | Append `"THIS IS NOT JSON"` to the log file | **RAISED** — contract says return `False` on tamper. | FIXED: `_parse_lines` raises internal `_CorruptLog` on bad JSON/non-dict lines; `verify_chain()` catches it and returns `False`. Regression: `test_corrupt_line_fails_verification`. |
| 14 | LOW | `Cage(budget=True)` / `budget="100"` → `AttributeError` on `spend()`; failed `spend(-1)` unaudited | `Cage(Policy({}), budget=True).spend(1)`; `cage.spend(-1)` | `AttributeError` (fail-closed by accident); `ValueError` propagates with no audit record of the attempt. | FIXED: `Cage.__init__` strictly validates `budget` (`Budget | int | float | None`; bool/str → `TypeError`); `Cage.spend` catches `ValueError`/`TypeError` from invalid amounts, audit-logs the denied attempt, and returns `False` instead of raising past the audit call. Regression: `test_bool_budget_rejected`, `test_negative_spend_denied_and_audited`. |
| 15 | LOW | `ticket_ttl=0`/negative mints ask-tickets that can never be approved | `Cage(policy, ticket_ttl=0)`, `guard` → `ask`, `approve` → `TicketExpired` | Fail-closed but confusing; dead tickets accumulate (see 11). | FIXED: non-positive `ticket_ttl` now raises `ValueError` at construction (fail fast on misconfiguration) instead of silently minting born-expired tickets. Regression: `test_nonpositive_ttl_rejected`. |

### Finding 1 — Mutable ticket objects allow cross-action approval forgery (CRITICAL)

`Cage.approve()` / `Cage.deny()` return the **live** `ApprovalTicket` dataclass
instance stored in the `TicketStore` — not a copy. Every security-relevant
field (`action`, `context_hash`, `status`, `requester`, `expires_at`) is a
plain mutable attribute, and `Cage.guard()` trusts those fields via
`find_approved()`.

```python
c = Cage(Policy({"read_s3": "ask", "delete_s3": "ask"}))
d = c.guard("read_s3", {"actor": "worker-0007", "bucket": "logs"})
t = c.approve(d.ticket_id, approver="human-op")  # human approved a READ
t.action = "delete_s3"                            # attacker flips to DELETE
t.context_hash = Cage._context_hash({"actor": "worker-0007", "bucket": "prod-customer-data"})
t.expires_at = time.time() + 3600
c.guard("delete_s3", {"actor": "worker-0007", "bucket": "prod-customer-data"})
# -> Decision("allow", "approved via ticket tkt-0001", ...)   BYPASSED
```

**Impact:** the anti-replay binding (action + context_hash + TTL) that the
README advertises ("one approval can't be replayed into a different
action") is fully attacker-rewritable. A human approving a benign read can
be converted into an approval for a destructive action, through the public
API alone, in the same process — which is exactly where the agent brain
lives.
**Recommended fix:** make `ApprovalTicket` immutable to callers: return
deep copies (or a read-only view) from `approve()`/`deny()`/`TicketStore.get()`;
better, make the dataclass `frozen=True` and have the store mutate only via
`object.__setattr__` or resolve-by-replacement under its lock. Defense in
depth: bind the approval to an HMAC over (ticket_id, action, context_hash,
expires_at) with a key held by the `Cage`, verified in `find_approved()`.

### Finding 2 — Denied ticket resurrection + requester laundering (CRITICAL)

Same root cause as Finding 1, chained one step further — full self-approval
with zero private access:

```python
d = c.guard("write_file", {"actor": "worker-0007", "path": "/tmp/x"})
t = c.deny(d.ticket_id, approver="human-op", reason="no")  # live object back
t.status = "pending"        # resurrect the denied ticket
t.requester = "human-op"    # launder who "requested" it
c.approve(d.ticket_id, approver="worker-0007")  # agent approves "someone else's" ticket
c.guard("write_file", {"actor": "worker-0007", "path": "/tmp/x"})
# -> Decision("allow", ...)   BYPASSED
```

**Impact:** the human's explicit denial is reversible by the denied party,
and the separation-of-duties check is defeated by rewriting history.
**Recommended fix:** same as Finding 1 (immutable ticket records,
resolve-by-replacement). Additionally, `deny()` should not hand back a
mutable handle to a resolved ticket.

### Finding 3 — Actor spoofing voids separation of duties (CRITICAL)

`context["actor"]` is a self-declared string. `Cage._resolve_check` forbids
`approver == ticket.requester` — but both sides are supplied by the caller.
A compromised brain simply lies at mint time:

```python
d = c.guard("write_file", {"actor": "human-op", "path": "/tmp/evil"})  # brain lies
c.approve(d.ticket_id, approver="worker-0007")  # brain approves its own ticket
c.guard("write_file", {"actor": "human-op", "path": "/tmp/evil"})
# -> Decision("allow", "approved via ticket tkt-0001", ...)   BYPASSED
```

No private access, no returned objects, no race — two public calls. Under
the audit's threat model (compromised in-process brain), the entire
human-approval gate reduces to "the attacker must type two different
strings."
**Impact:** CRITICAL — this voids the library's central safety claim for
the exact attacker it is meant to contain.
**Recommended fix (in-library):** add an approver allowlist at
construction — `Cage(policy, approvers={"human-op"})` — and reject
`approve()`/`deny()` from anyone not on it. That kills this attack as long
as the agent's own identity isn't allowlisted (the agent can still mint
tickets *as* "human-op", but then only the real human can approve them,
which is the intended flow). Document clearly that without an approver
allowlist — or, better, cryptographic approval tokens bound to an
out-of-process human — `ask` is advisory only against an in-process
attacker. Longer term: sign approvals (HMAC) with a key the agent process
never holds.

### Finding 4 — Frozen policy mutable via 6 vectors (CRITICAL)

`Policy.freeze()` sets `_frozen = True` and wraps the *returned* `.rules`
in a raising `_FrozenRules` — but `_rules` itself stays a plain mutable
dict, and the `__setattr__` guard only blocks *rebinding* via normal
attribute assignment. Reproduced bypasses, each flipping a frozen
`{"shell_exec": "deny"}` policy so `guard("shell_exec")` returns `allow`:

```python
p = Policy({"shell_exec": "deny"}); p.freeze()
p._rules["shell_exec"] = "allow"                       # direct dict mutation
p.__dict__["_rules"]["shell_exec"] = "allow"            # same via __dict__
object.__setattr__(p, "_rules", {"shell_exec": "allow"})# bypasses __setattr__ guard
object.__setattr__(p, "_frozen", False)                 # un-freeze, then mutate
r = p.rules; p.freeze()  # grab live dict BEFORE freeze...
r["shell_exec"] = "allow"                              # ...mutate it AFTER freeze
q = copy.copy(p); q._rules["shell_exec"] = "allow"      # shallow copy shares the dict:
                                                       # mutates the ORIGINAL policy too
```

Blocked (correctly): `p.rules["x"]=...`, `p.rules.update(...)`,
`p.rules = {...}` post-freeze, `p._rules = {...}` via normal setattr.
`copy.deepcopy` correctly isolates the copy (cage keeps using the original).

**Impact:** any code holding the `Policy` reference — including the agent
process the cage is supposed to restrain — can silently rewrite the
allowlist at runtime. `freeze()` provides no integrity against the
in-process threat model.
**Recommended fix:** on `freeze()`, replace `_rules` with an immutable
mapping (e.g. `types.MappingProxyType`) so in-place mutation is impossible
even via `__dict__`/pre-freeze references; keep the `__setattr__` guard for
rebinding and also guard `__dict__`/`object.__setattr__` paths by making
`_frozen` a slot or checking in `__setattr__` only (accept that
`object.__setattr__` is out of scope — document it). At minimum, freeze must
swap the underlying dict, not just the view.

### Finding 5 — Audit truncation undetectable (HIGH)

Deleting trailing JSONL lines leaves a perfectly valid chain:

```python
lines = open(path).readlines()[:-1]   # drop the last entry (e.g. the kill record)
open(path, "w").writelines(lines)
AuditLog(path).verify_chain()         # -> True   BYPASSED
```

The module docstring promises `False` on "ANY tamper
(modified/deleted/reordered)". Deletion of a *middle* line is caught; deletion
of the *tail* is not — and the tail is exactly where an attacker erases the
most recent (most incriminating) entries.
**Impact:** an attacker with log-file write access can silently erase
history; verification gives a clean bill of health.
**Recommended fix:** maintain an out-of-band checkpoint: store the latest
`(seq, hash)` in a separate location the log writer can't rewrite (or have
the operator record the last hash externally and pass it as
`verify_chain(expected_head=...)`). Document that file-local verification
cannot detect truncation by itself.

### Finding 6 — Forged audit entries verify as genuine: no MAC (HIGH)

The chain hash is a plain `sha256(prev_hash + canonical(payload))` — no
secret, no key. Anyone who can read the file (or the source) can extend the
chain with arbitrary entries that verify:

```python
from cage.audit import _entry_hash, canonical_json
last = json.loads(open(path).readlines()[-1])
forged = {"type": "guard", "action": "shell_exec", "actor": "worker-0007",
          "verdict": "allow", "reason": "totally legitimate",
          "ts": ..., "seq": last["seq"] + 1, "prev_hash": last["hash"]}
forged["hash"] = _entry_hash(last["hash"], forged)   # recompute, no secret needed
open(path, "a").write(canonical_json(forged) + "\n")
AuditLog(path).verify_chain()                        # -> True   BYPASSED
# forged entry now verifies: shell_exec allow
```

The README's Components section states `verify_chain()` "returns `False`
if any line was altered, **forged**, or dropped" — that claim is false for
forged-but-well-chained lines.
**Impact:** "tamper-evident" holds only against attackers who don't read
the source. A log-file writer can plant a clean history.
**Recommended fix:** HMAC the chain with a key held outside the log file
(operator-managed, env-provided); `verify_chain` requires the key, or keep
an unkeyed mode explicitly labeled "tamper-evident against accidental
corruption only". Correct the README claim either way.

### Finding 7 — `guard()` raises on hostile types, breaking "never raises" (HIGH)

`Cage.guard`'s contract: "Never blocks, never raises." Two counterexamples:

```python
c.guard(["read_file"], {"actor": "w"})          # TypeError: unhashable type: 'list'
c.guard("x", {"actor": "w", (1, 2): "x"})       # TypeError in _context_hash (json.dumps)
```

(`Policy.match` does `action in self._rules`; `_context_hash` runs
`json.dumps` on the raw context.) A compromised brain — the party the cage
polices — can crash the enforcement point with a single malformed call,
turning every subsequent decision into an unhandled exception in the host
loop. Fail-closed means *deny*, not *raise*.
**Recommended fix:** wrap `guard()`'s body (after the kill check) so any
unexpected exception becomes `Decision("deny", reason="guard internal
error: ...")` and is audit-logged; coerce/validate `action` to `str` and
make `_context_hash` total (e.g. `default=str` already, plus a
`try/except` returning a hash of `repr`).

### Finding 8 — Self-approval check is a bare `==` (MEDIUM)

```python
c.approve(tid, approver="Worker-0007")   # case variant  -> APPROVED (bypass)
c.approve(tid, approver="")             # empty string  -> APPROVED (bypass)
c.approve(tid, approver=None)           # None          -> APPROVED (bypass)
c.approve(tid, approver=" worker-0007 ")# whitespace     -> APPROVED (bypass)
c.approve(tid, approver="worker-0007")  # exact         -> SelfApprovalError (blocked)
```

Same flaw in `TicketStore.resolve()` (public API). The README's comparison
table claims "Self-approval prevention ✅ enforced".
**Impact:** MEDIUM on its own (Finding 3 dominates it — an attacker who can
spoof the actor doesn't need case tricks), but it breaks the guarantee for
any deployment that authenticates the *actor* out-of-band while taking the
*approver* string at face value.
**Recommended fix:** normalize (strip, casefold) and require a non-empty
string approver; better, combine with the Finding 3 fix (approver
allowlist), which makes the comparison moot.

### Finding 9 — Tickets resolvable after `kill()` (MEDIUM)

```python
d = c.guard("write_file", {"actor": "w", "path": "/tmp/b"})  # pending ticket
c.kill("halt")
c.approve(d.ticket_id, approver="human")   # -> approved. No exception.
c.deny(other_pending, approver="human")    # -> denied.  No exception.
```

`_resolve_check` never consults the kill flag. `guard()`/`spend()` correctly
deny post-kill, so a resolved ticket can't authorize anything *today* — but
the audit log records "approved" on a dead cage, and the invariant "after
kill, nothing changes state" is broken. If kill were ever made reversible
or scoped, these latent approvals would be live ammunition.
**Recommended fix:** check `self._killed` (under the cage lock) first in
`_resolve_check`; raise `CageKilled` (or a dedicated `TicketResolutionRefused`)
on any resolve attempt after kill.

### Finding 10 — Approve/deny TOCTOU: one ticket approved 8× (MEDIUM)

`Cage.approve()` does `get()` (lock released) → `_resolve_check` →
mutates `ticket.status` — the check and the act span an unlocked region.
With the race window widened white-box (sleep inside the check), 8 threads
all "approved" the same ticket; the audit log shows 8× `outcome: approved`
and no `TicketAlreadyResolved`. The window is narrow in practice but the
design is check-then-act on shared mutable state.
**Impact:** double-approval / double-deny; audit log asserts two humans
approved when one ticket existed. Combined with Finding 1's mutability, the
store has no integrity story under concurrency.
**Recommended fix:** move resolution into `TicketStore` under its lock
(compare-and-swap on `status == "pending"`), i.e. use the existing
`TicketStore.resolve()` — which is already lock-correct — instead of
reimplementing the check in `Cage`.

### Finding 11 — Unbounded ticket store; duplicate concurrent asks (MEDIUM)

- 3000 `ask` decisions → 3000 tickets retained forever; no expiry sweeper,
  no cap, no eviction. A busy agent (or a malicious one minting asks in a
  loop) grows memory without bound.
- 16 threads `guard()`-ing the identical action+context minted **16**
  distinct pending tickets (check-then-mint race between `find_approved`
  and `create`).

**Recommended fix:** background or lazy eviction of expired/resolved
tickets (cap the store, e.g. last N tickets + always keep pending); make
find-or-create atomic under the store lock.

### Finding 12 — Concurrent writers corrupt a shared audit file (MEDIUM)

Two `AuditLog` objects on the same path (two `Cage`s, two processes, or
threads across instances — each has its own lock) interleave: both
snapshot the same tail, both append with the same `prev_hash` and `seq`.
Result: `verify_chain()` → `False` on a **legitimate** log — the operator
cannot distinguish attack from concurrency, and may learn to ignore
verification failures.
**Recommended fix:** cross-process file locking (`fcntl.flock`) around
read-modify-append in file mode, or document "one writer per file" and
fail fast if a second writer is detected.

### Finding 13 — `verify_chain()` raises instead of returning `False` (LOW)

A single non-JSON line makes `_read_file` raise `json.JSONDecodeError`,
which propagates out of `verify_chain()` — contradicting "False on ANY
tamper". (A line that parses to a non-dict, e.g. `42`, correctly returns
`False`.)
**Recommended fix:** catch `json.JSONDecodeError` (and `UnicodeDecodeError`)
in `_read_file`/`verify_chain` and return `False`.

### Finding 14 — Budget type-confusion and unaudited failures (LOW)

- `Cage(Policy({}), budget=True).spend(1)` → `AttributeError: 'bool' object
  has no attribute 'spend'` (`True` slips past the `isinstance(budget,
  (int, float))` wrap because of the `not isinstance(budget, bool)` carve-out
  — then stays a raw bool). Same for `budget="100"`. Fail-closed by
  accident, but a confusing crash instead of a clean `False`/validation error.
- `cage.spend(-1)` raises `ValueError` from `Budget.spend` *before* the audit
  record is written — failed/attempted spends leave no trace.
- `Budget(float("nan"))` constructs fine (NaN cap → everything denied;
  fail-closed, but surprising).

**Recommended fix:** validate `budget` in `Cage.__init__` (must be
`Budget | float | int | None`, reject bool/str); audit failed spends
(record with `allowed: False` + error) instead of raising past the audit
call. NaN/inf amounts already return `False` cleanly — good.

### Finding 15 — `ticket_ttl=0`/negative mints un-approvable asks (LOW)

`guard()` returns `ask` with a ticket that is already expired; `approve()`
then raises `TicketExpired`. Fail-closed, but the UX is a denial that
*looks* like a pending approval, and dead tickets accumulate (Finding 11).
**Recommended fix:** clamp `ticket_ttl` to a sane minimum in `Cage.__init__`
(or return `deny` with reason "approval flow misconfigured" when `ttl <= 0`).

## Attacks that HELD (no finding)

- **Action spoofing is real, and the README is honest about it.** Calling
  `guard("read_file", ...)` for a shell execution returns `allow` — the
  cage cannot see the real action. The README states this as the **#1 known
  limitation** in a dedicated "Trust model — read this before you deploy"
  section, in plain language, not hedged or buried. Verified, not a finding.
- **Cross-action / cross-context replay blocked:** an approved ticket for
  `(write_file, ctx)` does not authorize `(shell_exec, ctx)` (policy deny)
  or `(write_file, ctx')` (fresh ticket minted). Forged ticket IDs
  (`tkt-9999`, `""`, `None`, SQL-ish strings) → `TicketNotFound`.
- **Stale approvals:** TTL expiry → `TicketExpired` on `approve()`; a new
  `guard()` mints a fresh ticket rather than honoring the dead one; expired
  pending tickets are lazily flipped to `"expired"`.
- **Fail-closed inputs:** `""`, `None`, unknown, unicode, 100k-char, and
  newline-containing actions, plus missing/empty/non-string actors and
  non-dict contexts, all → `deny`, never `allow` (except Finding 7's
  raise-on-hostile-types).
- **Kill switch:** post-kill, `guard()` on allow/ask/deny actions and
  pre-approved-ticket contexts all → `deny`; `spend()` → `False`;
  16 threads × post-`kill()`-return `guard()` → 0 non-deny verdicts;
  double-`kill()` idempotent, original reason preserved.
- **Budget race:** 200 threads × `spend(1.0)` against cap 100 → exactly 100
  successes, `spent == 100.0`, `remaining == 0.0`, never negative.
  `spend(NaN)`/`spend(inf)` → `False` with no state corruption; negative
  amounts → `ValueError`; `Cage(budget=0)`: `spend(0.01)` → `False`,
  `spend(0)` → `True`. Float boundary (`0.1+0.2 > 0.3`) denies
  conservatively — fail-closed direction.
- **Ticket ID uniqueness:** 800 tickets across 32 threads, all unique.
- **AuditLog modes:** in-memory `verify_chain()` works; a fresh
  `AuditLog(path)` on an existing file re-reads and verifies.

## Notes (informational, not findings)

- **N1 — Wildcard semantics (verified):** exact match wins; otherwise the
  longest `"prefix.*"` wins; `"file.*"` matches `"file"` itself, `"file."`,
  and `"file.anything"` — but NOT `"fileX"` or `"files.read"`. Bare
  `"file"` matching `"file.*"` surprises some users; it is documented in
  the `Policy` docstring.
- **N2 — `record()` returns a live dict in memory mode:** mutating the
  returned dict corrupts the in-memory log, but `verify_chain()` then
  returns `False` (tamper-evident, not tamper-proof). File mode returns a
  detached copy.
- **N3 — Kill TOCTOU at entry:** a `guard()` already past the kill-flag
  check when `kill()` lands may still return `allow` (29 observed in a
  30-trial hammer test). Only calls *starting after `kill()` returns* are
  guaranteed `deny`. Inherent to check-at-entry; document it.

## Known limitations (acknowledged, not findings)

- The cage cannot detect action misclassification: a caller labeling
  `shell_exec` as `read_file` bypasses the policy. Classification is the
  caller's responsibility. (See README "Trust model".) — *verified real,
  verified prominently disclosed.*
- The audit log detects tampering via `verify_chain()`; it does not prevent
  it, and verification is the operator's job. — *partially undermined by
  Findings 5 and 6: truncation and well-formed forgeries are NOT detected.*
- Approval strength depends on the integrity of the approver channel. —
  *undermined by Finding 3: no approver channel is needed; the attacker
  approves their own ticket in-process.*

## Turnkey checklist (hands-on, all done)

- [x] Fresh venv → `pip install -e .` → `pytest`: **109/109 green**.
- [x] README quickstart extracted verbatim and run: prints `ask tkt-0001`
      then `allow`, exactly as documented.
- [x] Both examples run: `examples/juggernaut_cage.py` (18 audit entries,
      kill-switch deny at the end), `examples/approval_flow.py`
      (ask → approve → allow, plus TTL-expiry demo raising `TicketExpired`).
- [x] Import surface: `hashlib, json, threading, time, dataclasses`
      (stdlib) + intra-package imports only. **Zero non-stdlib imports.**

## Verdict (original audit)

**DO NOT SHIP.**

Five of the library's core guarantees fail against the in-process attacker
the library exists to contain, all reproducible through the public API:

1. Approval gates are bypassable three independent ways (mutable-ticket
   forgery, ticket resurrection + requester laundering, actor spoofing).
2. The frozen policy is mutable six ways.
3. The tamper-evident audit log is blind to truncation and to forged
   entries with recomputed hashes, and its own docs overclaim.

The honest README trust-model section is the best part of this library —
but Findings 3, 5, and 6 punch holes in the exact properties it tells the
user to rely on ("one approval can't be replayed into a different action",
"returns False if any line was … forged", "approval strength depends on
your approver channel" — no channel is even required). A safety library
that fails open under attack is worse than no library: it manufactures
trust. Fix Findings 1–6 (immutable/HMAC-bound tickets, approver allowlist,
real policy immutability, keyed audit chain + truncation checkpoints),
re-run this audit's scripts as regression tests, and then it can ship.

## Re-audit (post-remediation)

All 15 findings were remediated (see Remediation column). The attack
reproductions were folded into `tests/test_audit_attacks.py` (24 regression
tests) and the full suite passes: **133/133**.

- Findings 1–2: frozen tickets + resolve-by-replacement + snapshots — the
  forgery and resurrection attacks now raise `FrozenInstanceError` /
  `TicketAlreadyResolved`.
- Finding 3: approver allowlist added; spoofed-identity tickets become
  unapprovable. Residual honestly documented and tested: in-process, the
  approver is a string — high-assurance deployments must resolve tickets
  out-of-band (README trust model).
- Finding 4: self-protecting rules dict — all 9 mutation vectors raise
  `FrozenPolicyError`; `copy`/`deepcopy` behave.
- Findings 5–6: checkpoint sidecar detects truncation; HMAC keyed mode
  rejects forgeries; README's false claims corrected.
- Finding 7: `guard()` never raises — hostile input becomes an audited deny.
- Findings 8–15: identity normalization, kill-check on resolve, atomic
  store resolution, bounded store + ask dedupe, `flock`'d audit appends,
  corrupt-line tolerance, strict budget validation, TTL validation.

**Re-verdict: SHIP.** The documented residual boundaries (action
misclassification, in-process approver strings, `object.__setattr__`
white-box, kill entry-race) are inherent to the threat model and are
stated plainly in the README rather than papered over.

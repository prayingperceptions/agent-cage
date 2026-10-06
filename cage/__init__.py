"""agent-cage: a standalone, framework-agnostic safety library for AI agents.

Fail-closed policy enforcement: allowlisted actions proceed, "ask" actions
mint human-approval tickets, everything else is denied. Plus a kill switch,
a spend budget, and a hash-chained audit log. Stdlib only.
"""
from .budget import Budget
from .cage import Cage, CageKilled, Decision
from .policy import FrozenPolicyError, Policy
from .tickets import (
    ApprovalTicket,
    SelfApprovalError,
    TicketAlreadyResolved,
    TicketExpired,
    TicketNotFound,
    TicketStore,
    UnauthorizedApproverError,
    normalize_identity,
)

__version__ = "0.1.0"

__all__ = [
    "Cage",
    "Policy",
    "Decision",
    "ApprovalTicket",
    "Budget",
    "CageKilled",
    "TicketExpired",
    "SelfApprovalError",
    "FrozenPolicyError",
    "TicketAlreadyResolved",
    "TicketNotFound",
    "TicketStore",
    "UnauthorizedApproverError",
    "normalize_identity",
    "__version__",
]

"""Spending budget: fail-closed cap on cumulative spend per epoch.

``spend`` is atomic under a lock (check-and-deduct in one critical section):
it returns True and deducts iff ``spent + amount <= cap``; otherwise it
returns False and deducts nothing. ``cap == 0`` means nothing may be spent.
"""

from __future__ import annotations

import threading


class Budget:
    def __init__(self, cap: float) -> None:
        if cap < 0:
            raise ValueError(f"cap must be >= 0, got {cap!r}")
        self._cap = cap
        self._spent = 0.0
        self._lock = threading.Lock()

    def spend(self, amount: float) -> bool:
        """Spend ``amount`` iff it fits within the cap. Thread-safe.

        Returns True and deducts on success; False with no deduction otherwise.
        """
        if amount < 0:
            raise ValueError(f"amount must be >= 0, got {amount!r}")
        with self._lock:
            if self._spent + amount <= self._cap:
                self._spent += amount
                return True
            return False

    @property
    def spent(self) -> float:
        with self._lock:
            return self._spent

    @property
    def remaining(self) -> float:
        with self._lock:
            return max(0.0, self._cap - self._spent)  # never negative (clamped)

    @property
    def cap(self) -> float:
        return self._cap

    def new_epoch(self) -> None:
        """Reset spent to 0 (start a fresh budget epoch)."""
        with self._lock:
            self._spent = 0.0

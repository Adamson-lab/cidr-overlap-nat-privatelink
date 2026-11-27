from dataclasses import dataclass
from datetime import datetime, timezone
import threading
import time
from typing import Any

from storage.audit_ledger import HashChainedLedger


class IpamLeaseConflict(Exception):
    pass


@dataclass
class PrefixLease:
    vpc_pair_key: str
    holder_id: str
    fencing_token: int
    expires_at_utc: float


class PrefixFencingLeaseManager:
    # Monotonic fencing tokens block stale workers from overwriting NAT or PrivateLink mappings after lease expiry.
    def __init__(self, ledger: HashChainedLedger | None = None, ttl_sec: float = 25.0) -> None:
        self._lock = threading.Lock()
        self._leases: dict[str, PrefixLease] = {}
        self._token_seq: int = 0
        self._ledger = ledger or HashChainedLedger()
        self._ttl_sec = ttl_sec

    def acquire(
        self,
        vpc_pair_key: str,
        holder_id: str,
        now_utc: float | None = None,
        grace_extension_sec: float = 0.0,
    ) -> PrefixLease:
        # Compare in UTC epoch seconds so local Daylight Saving Time shifts never alter lease windows.
        now = time.time() if now_utc is None else now_utc
        clamped_grace = min(max(grace_extension_sec, 0.0), 900.0)
        with self._lock:
            existing = self._leases.get(vpc_pair_key)
            if existing is not None and existing.expires_at_utc > now and existing.holder_id != holder_id:
                raise IpamLeaseConflict(f"pair {vpc_pair_key} actively leased by {existing.holder_id}")

            self._token_seq += 1
            lease = PrefixLease(
                vpc_pair_key=vpc_pair_key,
                holder_id=holder_id,
                fencing_token=self._token_seq,
                expires_at_utc=now + self._ttl_sec + clamped_grace,
            )
            self._leases[vpc_pair_key] = lease
            self._ledger.append(
                action="prefix_lease_acquired",
                fencing_token=lease.fencing_token,
                payload={
                    "vpc_pair_key": vpc_pair_key,
                    "holder_id": holder_id,
                    "expires_at_utc": lease.expires_at_utc,
                    "grace_sec": clamped_grace,
                    "recorded_at_utc": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                },
            )
            return lease

    def validate_token(self, vpc_pair_key: str, fencing_token: int, now_utc: float | None = None) -> bool:
        now = time.time() if now_utc is None else now_utc
        with self._lock:
            lease = self._leases.get(vpc_pair_key)
            if lease is None:
                return False
            if lease.expires_at_utc <= now:
                return False
            return fencing_token == lease.fencing_token

    def ledger(self) -> HashChainedLedger:
        return self._ledger

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "leases": {
                    k: {
                        "holder_id": v.holder_id,
                        "fencing_token": v.fencing_token,
                        "expires_at_utc": v.expires_at_utc,
                    }
                    for k, v in self._leases.items()
                },
                "ledger_length": len(self._ledger.entries()),
            }

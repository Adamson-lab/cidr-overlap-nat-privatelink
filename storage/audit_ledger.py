from dataclasses import dataclass
import hashlib
import json
from typing import Any


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    prev_hash: str
    action: str
    fencing_token: int
    payload_json: str
    entry_hash: str


def compute_link_hash(seq: int, prev_hash: str, action: str, fencing_token: int, payload_json: str) -> str:
    raw = f"{seq}|{prev_hash}|{action}|{fencing_token}|{payload_json}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class HashChainedLedger:
    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []

    def append(self, action: str, fencing_token: int, payload: dict[str, Any]) -> LedgerEntry:
        seq = len(self._entries) + 1
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        entry_hash = compute_link_hash(seq, prev_hash, action, fencing_token, payload_json)
        entry = LedgerEntry(
            seq=seq,
            prev_hash=prev_hash,
            action=action,
            fencing_token=fencing_token,
            payload_json=payload_json,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, str]:
        prev = "0" * 64
        for idx, e in enumerate(self._entries, start=1):
            if e.seq != idx:
                return False, f"sequence gap at {idx}"
            if e.prev_hash != prev:
                return False, f"prev_hash broken at seq {e.seq}"
            expected = compute_link_hash(e.seq, e.prev_hash, e.action, e.fencing_token, e.payload_json)
            if expected != e.entry_hash:
                return False, f"hash mismatch at seq {e.seq}"
            prev = e.entry_hash
        return True, "ok"

    def entries(self) -> list[LedgerEntry]:
        return list(self._entries)

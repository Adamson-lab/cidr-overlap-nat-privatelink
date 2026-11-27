# ADR 002: SHA-256 Hash-Chained Ledger for CIDR Resolutions

## Context
Network engineers and auditors need verifiable ordering across CIDR lease acquisitions and NAT/PrivateLink resolution records.

## Decision
Append each event as a `LedgerEntry` in `storage/audit_ledger.py` linking `entry_hash` to `prev_hash` via SHA-256.

## Consequences
Any tampering or gap breaks `HashChainedLedger.verify()`. Records are held in memory and written per resolution to S3.

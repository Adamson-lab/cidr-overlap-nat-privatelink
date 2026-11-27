# ADR 001: Monotonic Fencing Tokens for Overlapping CIDR Mappings

## Context
Two IPAM/network workers can race when assigning NAT translation CIDRs or PrivateLink endpoint mappings for the same overlapping VPC pair.

## Decision
Assign a monotonic `fencing_token` per lease acquisition in `PrefixFencingLeaseManager` and verify it in `OverlapResolutionEngine.resolve_overlap` prior to EC2 or S3 calls.

## Consequences
Delayed workers carrying an expired or superseded token receive `ResolutionError` and cannot overwrite active mappings. Lease state is stored in single-process memory in this implementation.

# Design Notes: Overlapping CIDR Resolution with NAT and PrivateLink

This service separates lease management and hash-chained audit logging (`controlplane/ipam_lease.py`, `controlplane/server.py`, `storage/audit_ledger.py`) from CIDR overlap validation and AWS EC2/S3 recording (`dataplane/resolver.py`) with Open Policy Agent (OPA) policy enforcement.

## Trust-Boundary and Network Enclave Topology

```mermaid
flowchart TB
    subgraph ExternalIngress["External Untrusted Ingress"]
        Caller["Caller"]
    end

    subgraph ControlPlaneEnclave["Control Plane Enclave"]
        API["FastAPI Server :8080"]
        LeaseMgr["PrefixFencingLeaseManager"]
        Ledger["HashChainedLedger"]
        API --> LeaseMgr
        LeaseMgr --> Ledger
    end

    subgraph PolicyAndCloud["Policy and Cloud Plane"]
        OPA["OPA :8181"]
        AWS["LocalStack EC2 & S3 :4566"]
    end

    subgraph DataPlane["Data Plane"]
        Engine["OverlapResolutionEngine"]
    end

    Caller -->|"HTTP + HMAC-SHA256 :8080"| API
    API -->|"HTTP REST Rego Eval :8181"| OPA
    API --> Engine
    Engine -->|"validate_token"| LeaseMgr
    Engine -->|"boto3 EC2 & S3 :4566"| AWS
```

## Distributed Concurrency and Resolution Sequence

```mermaid
sequenceDiagram
    autonumber
    participant C as Caller
    participant S as FastAPI Server :8080
    participant O as OPA :8181
    participant L as PrefixFencingLeaseManager
    participant E as OverlapResolutionEngine

    C->>S: POST /v1/cidr/resolve
    S->>S: verify_payload
    alt Invalid HMAC or expired timestamp
        S-->>C: 401 Unauthorized
    else Signature valid
        par Policy evaluation
            S->>O: POST /v1/data/cidr/resolution
            S->>O: POST /v1/data/cidr/window
        end
        alt Policy denied
            S-->>C: 403 Forbidden
        else Policy allowed
            critical Lease acquisition
                S->>L: acquire(vpc_pair_key, holder_id)
            option Active conflict
                S-->>C: 409 Conflict
            end
            S->>E: resolve_overlap(fencing_token)
            alt Stale token or invalid CIDR mapping
                E-->>S: ResolutionError
                S-->>C: 409 Conflict
            else Valid mapping
                E-->>S: ResolvedMapping
                S-->>C: 200 OK
            end
        end
    end
```

## Prefix Lease State Machine

```mermaid
stateDiagram-v2
    [*] --> Available
    Available --> ActiveLease: acquire() increments fencing_token
    note right of ActiveLease: Token validated before EC2 endpoint check and S3 write
    ActiveLease --> ActiveLease: same holder re-acquires or extends grace
    ActiveLease --> Expired: expires_at_utc reached
    Expired --> ActiveLease: new holder acquires higher fencing_token
    ActiveLease --> [*]
```

## Resolution and Ledger Data Flow

```mermaid
flowchart LR
    Lease["PrefixLease (fencing_token)"] --> Engine["OverlapResolutionEngine"]
    Engine --> Ledger["LedgerEntry (seq, prev_hash, entry_hash)"]
    Engine --> S3["S3 Resolution JSON"]
```

## Trade-Offs and Limitations

Lease TTLs and UTC change windows use UTC timestamps so Daylight Saving Time transitions do not alter cutoffs. Off-window resolutions support up to a 15-minute grace extension with a valid incident ID. AWS requests retry transient throttling and HTTP `429`/`502`/`503`/`504` responses up to 4 times with per-attempt sleep capped at `2.0s`.

Limitations: `PrefixFencingLeaseManager` and `HashChainedLedger` are held in single-process memory rather than a shared database, and `describe_vpc_endpoints` does not paginate across `NextToken`.

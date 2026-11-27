from datetime import datetime, timezone
import json
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
import httpx

from controlplane.ipam_lease import IpamLeaseConflict, PrefixFencingLeaseManager
from dataplane.resolver import OverlapResolutionEngine, ResolutionError, verify_payload
from storage.audit_ledger import HashChainedLedger

app = FastAPI(title="cidr-overlap-nat-privatelink", version="0.1.0")

LEDGER = HashChainedLedger()
LEASES = PrefixFencingLeaseManager(ledger=LEDGER, ttl_sec=25.0)


def _eval_opa(opa_url: str, opa_input: dict[str, Any]) -> tuple[bool, str]:
    base = opa_url.rstrip("/")
    with httpx.Client(timeout=3.0) as client:
        r1 = client.post(f"{base}/v1/data/cidr/resolution", json={"input": opa_input})
        r1.raise_for_status()
        d1 = r1.json().get("result") or {}
        if not d1.get("allow", False):
            return False, d1.get("reason", "denied by resolution policy")

        r2 = client.post(f"{base}/v1/data/cidr/window", json={"input": opa_input})
        r2.raise_for_status()
        d2 = r2.json().get("result") or {}
        if not d2.get("allow", False):
            return False, d2.get("reason", "denied by change window policy")

        return True, d2.get("reason", "allowed")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    ok, msg = LEDGER.verify()
    return {
        "status": "ok" if ok else "degraded",
        "ledger_status": msg,
        "utc_time": datetime.now(timezone.utc).isoformat(),
        "state": LEASES.snapshot(),
    }


@app.post("/v1/cidr/resolve")
async def resolve_cidr_overlap(
    request: Request,
    x_signature_256: str | None = Header(default=None, alias="X-Signature-256"),
    x_timestamp: str | None = Header(default=None, alias="X-Timestamp"),
) -> dict[str, Any]:
    raw_body = await request.body()
    secret = os.getenv("WEBHOOK_HMAC_SECRET", "local-dev-cidr-secret")
    valid, reason = verify_payload(secret, x_signature_256, x_timestamp, raw_body)
    if not valid:
        raise HTTPException(status_code=401, detail={"error": reason})

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "malformed json payload"})

    source_vpc = str(payload.get("source_vpc", "vpc-a"))
    target_vpc = str(payload.get("target_vpc", "vpc-b"))
    source_cidr = str(payload.get("source_cidr", "10.10.0.0/16"))
    target_cidr = str(payload.get("target_cidr", "10.10.0.0/16"))
    translated_cidr = str(payload.get("translated_cidr", "100.64.10.0/16"))
    strategy = str(payload.get("strategy", "privatelink_endpoint"))
    holder_id = str(payload.get("holder_id", "resolver-1"))
    role = str(payload.get("actor_role", "net-architect"))
    grace_ext = payload.get("grace_extension") or {}
    grace_mins = int(grace_ext.get("extra_minutes", 0)) if grace_ext.get("active") else 0
    now_utc = datetime.now(timezone.utc)

    opa_url = os.getenv("OPA_URL", "http://localhost:8181")
    try:
        allowed, policy_reason = _eval_opa(
            opa_url,
            {
                "source_vpc": source_vpc,
                "target_vpc": target_vpc,
                "translated_cidr": translated_cidr,
                "strategy": strategy,
                "actor_role": role,
                "utc_hour": now_utc.hour,
                "grace_extension": grace_ext,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail={"error": f"opa evaluation failed: {exc}"})

    if not allowed:
        raise HTTPException(status_code=403, detail={"error": policy_reason})

    pair_key = f"{source_vpc}->{target_vpc}"
    try:
        lease = LEASES.acquire(
            vpc_pair_key=pair_key,
            holder_id=holder_id,
            now_utc=now_utc.timestamp(),
            grace_extension_sec=grace_mins * 60.0,
        )
    except IpamLeaseConflict as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc)})

    engine = OverlapResolutionEngine(
        lease_manager=LEASES,
        region=os.getenv("AWS_REGION", "us-east-1"),
        endpoint_url=os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566"),
        bucket=os.getenv("OVERLAP_AUDIT_BUCKET", "cidr-overlap-resolution-audit"),
    )
    try:
        res = engine.resolve_overlap(
            source_vpc=source_vpc,
            target_vpc=target_vpc,
            source_cidr=source_cidr,
            target_cidr=target_cidr,
            translated_cidr=translated_cidr,
            strategy=strategy,
            fencing_token=lease.fencing_token,
            now_utc=now_utc.timestamp(),
        )
    except ResolutionError as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc)})
    except Exception as exc:
        raise HTTPException(status_code=502, detail={"error": f"resolution failed: {exc}"})

    chain_ok, _ = LEDGER.verify()
    return {
        "status": "resolved",
        "policy_reason": policy_reason,
        "fencing_token": lease.fencing_token,
        "ledger_valid": chain_ok,
        "mapping": {
            "source_vpc": res.source_vpc,
            "target_vpc": res.target_vpc,
            "overlapping_cidr": res.overlapping_cidr,
            "translated_cidr": res.translated_cidr,
            "strategy": res.strategy,
            "s3_bucket": res.s3_bucket,
            "s3_key": res.s3_key,
            "ledger_hash": res.ledger_hash,
        },
    }

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import logging
import time
from typing import Any

from controlplane.ipam_lease import PrefixFencingLeaseManager

logger = logging.getLogger("cidr_resolver.dataplane")


class ResolutionError(Exception):
    pass


def sign_payload(secret: str, ts_unix: int, body: bytes) -> str:
    msg = f"{ts_unix}.".encode("utf-8") + body
    digest = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_payload(
    secret: str,
    signature: str | None,
    timestamp: str | None,
    body: bytes,
    max_skew_sec: int = 300,
    now_unix: int | None = None,
) -> tuple[bool, str]:
    if not signature or not timestamp:
        return False, "missing X-Signature-256 or X-Timestamp header"
    try:
        ts = int(timestamp.strip())
    except ValueError:
        return False, "invalid X-Timestamp header"

    now = int(time.time()) if now_unix is None else now_unix
    if abs(now - ts) > max_skew_sec:
        return False, "timestamp outside replay window"

    expected = sign_payload(secret, ts, body)
    if not hmac.compare_digest(expected, signature.strip()):
        return False, "hmac signature mismatch"
    return True, "ok"


def _retryable_aws(exc: Any) -> bool:
    resp = getattr(exc, "response", {}) or {}
    code = resp.get("Error", {}).get("Code", "")
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    return code in {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
    } or status in {429, 502, 503, 504}


def _call_aws(op: str, fn: Any, exc_cls: Any, attempts: int = 4) -> Any:
    backoff = 0.1
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except exc_cls as exc:
            if not _retryable_aws(exc) or attempt == attempts:
                raise
            # Cap per-retry delay at 2.0s so EC2/S3 throttling does not exceed caller timeouts.
            pause = min(backoff, 2.0)
            logger.warning("retrying aws op=%s attempt=%d pause_s=%.2f err=%s", op, attempt, pause, exc)
            time.sleep(pause)
            backoff *= 2.0


def prefixes_overlap(cidr_a: str, cidr_b: str) -> bool:
    net_a = ipaddress.ip_network(cidr_a, strict=False)
    net_b = ipaddress.ip_network(cidr_b, strict=False)
    return bool(net_a.overlaps(net_b))


@dataclass
class ResolvedMapping:
    source_vpc: str
    target_vpc: str
    overlapping_cidr: str
    translated_cidr: str
    strategy: str
    fencing_token: int
    s3_bucket: str
    s3_key: str
    ledger_hash: str


class OverlapResolutionEngine:
    def __init__(
        self,
        lease_manager: PrefixFencingLeaseManager,
        region: str = "us-east-1",
        endpoint_url: str | None = "http://localhost:4566",
        bucket: str = "cidr-overlap-resolution-audit",
        ec2_client: Any | None = None,
        s3_client: Any | None = None,
        client_error_cls: Any | None = None,
    ) -> None:
        self.leases = lease_manager
        self.region = region
        self.bucket = bucket

        if client_error_cls is not None:
            self._client_error = client_error_cls
            boto3_mod = None
        else:
            try:
                import boto3
                from botocore.exceptions import ClientError

                boto3_mod = boto3
                self._client_error = ClientError
            except ImportError:
                boto3_mod = None

                class _FallbackError(Exception):
                    response: dict[str, Any] = {}

                self._client_error = _FallbackError

        client_kwargs: dict[str, Any] = {"region_name": region}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
            client_kwargs["aws_access_key_id"] = "test"
            client_kwargs["aws_secret_access_key"] = "test"

        if ec2_client is not None:
            self.ec2 = ec2_client
        else:
            if boto3_mod is None:
                raise RuntimeError("boto3 is required when ec2_client is not supplied")
            self.ec2 = boto3_mod.client("ec2", **client_kwargs)

        if s3_client is not None:
            self.s3 = s3_client
        else:
            if boto3_mod is None:
                raise RuntimeError("boto3 is required when s3_client is not supplied")
            self.s3 = boto3_mod.client("s3", **client_kwargs)

    def _ensure_bucket(self) -> None:
        try:
            self.s3.head_bucket(Bucket=self.bucket)
        except self._client_error:
            try:
                self.s3.create_bucket(Bucket=self.bucket)
            except self._client_error as exc:
                code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
                if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                    raise

    def resolve_overlap(
        self,
        source_vpc: str,
        target_vpc: str,
        source_cidr: str,
        target_cidr: str,
        translated_cidr: str,
        strategy: str,
        fencing_token: int,
        now_utc: float | None = None,
    ) -> ResolvedMapping:
        pair_key = f"{source_vpc}->{target_vpc}"
        # Reject stale or expired tokens before querying EC2 or committing audit state.
        if not self.leases.validate_token(vpc_pair_key=pair_key, fencing_token=fencing_token, now_utc=now_utc):
            raise ResolutionError(f"fencing token {fencing_token} rejected for {pair_key}")

        if not prefixes_overlap(source_cidr, target_cidr):
            raise ResolutionError(f"cidrs {source_cidr} and {target_cidr} do not overlap")

        src_net = ipaddress.ip_network(source_cidr, strict=False)
        dst_net = ipaddress.ip_network(target_cidr, strict=False)
        xlat_net = ipaddress.ip_network(translated_cidr, strict=False)
        if xlat_net.prefixlen != max(src_net.prefixlen, dst_net.prefixlen):
            raise ResolutionError("translated_cidr prefix length must match the narrower overlapping prefix")

        _call_aws(
            "ec2:describe_vpc_endpoints",
            lambda: self.ec2.describe_vpc_endpoints(),
            self._client_error,
        )
        self._ensure_bucket()

        overlap_str = str(src_net.supernet(new_prefix=min(src_net.prefixlen, dst_net.prefixlen)))
        ts = time.time() if now_utc is None else now_utc
        dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
        entry = self.leases.ledger().append(
            action="overlap_resolved",
            fencing_token=fencing_token,
            payload={
                "source_vpc": source_vpc,
                "target_vpc": target_vpc,
                "overlapping_cidr": overlap_str,
                "translated_cidr": str(xlat_net),
                "strategy": strategy,
                "resolved_at_utc": dt_utc.isoformat(),
            },
        )
        key = f"resolutions/{dt_utc.strftime('%Y-%m-%d')}/{source_vpc}-{target_vpc}-tok{fencing_token}.json"
        doc = {
            "source_vpc": source_vpc,
            "target_vpc": target_vpc,
            "overlapping_cidr": overlap_str,
            "translated_cidr": str(xlat_net),
            "strategy": strategy,
            "fencing_token": fencing_token,
            "ledger_hash": entry.entry_hash,
        }
        _call_aws(
            "s3:put_object",
            lambda: self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=json.dumps(doc, indent=2).encode("utf-8"),
                ContentType="application/json",
            ),
            self._client_error,
        )
        return ResolvedMapping(
            source_vpc=source_vpc,
            target_vpc=target_vpc,
            overlapping_cidr=overlap_str,
            translated_cidr=str(xlat_net),
            strategy=strategy,
            fencing_token=fencing_token,
            s3_bucket=self.bucket,
            s3_key=key,
            ledger_hash=entry.entry_hash,
        )

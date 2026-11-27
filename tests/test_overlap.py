import os
import sys
import time
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from controlplane.ipam_lease import IpamLeaseConflict, PrefixFencingLeaseManager
from dataplane.resolver import OverlapResolutionEngine, ResolutionError, sign_payload, verify_payload
from storage.audit_ledger import HashChainedLedger


class TestCidrOverlapResolution(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = HashChainedLedger()
        self.leases = PrefixFencingLeaseManager(ledger=self.ledger, ttl_sec=25.0)
        self.fake_ec2 = MagicMock()
        self.fake_ec2.describe_vpc_endpoints.return_value = {"VpcEndpoints": []}
        self.fake_s3 = MagicMock()
        self.engine = OverlapResolutionEngine(
            lease_manager=self.leases,
            region="us-east-1",
            endpoint_url=None,
            bucket="test-cidr-bucket",
            ec2_client=self.fake_ec2,
            s3_client=self.fake_s3,
        )

    def test_resolve_overlapping_cidr_and_verify_ledger(self) -> None:
        t0 = 1764267000.0
        lease = self.leases.acquire("vpc-a->vpc-b", "resolver-1", now_utc=t0, grace_extension_sec=300.0)
        res = self.engine.resolve_overlap(
            source_vpc="vpc-a",
            target_vpc="vpc-b",
            source_cidr="10.10.0.0/16",
            target_cidr="10.10.0.0/16",
            translated_cidr="100.64.0.0/16",
            strategy="privatelink_endpoint",
            fencing_token=lease.fencing_token,
            now_utc=t0 + 1,
        )
        self.assertEqual(res.translated_cidr, "100.64.0.0/16")
        ok, msg = self.ledger.verify()
        self.assertTrue(ok, msg)
        self.fake_s3.put_object.assert_called_once()

    def test_lease_conflict_and_non_overlapping_rejection(self) -> None:
        t0 = 1764267000.0
        lease = self.leases.acquire("vpc-a->vpc-c", "resolver-1", now_utc=t0)
        with self.assertRaises(IpamLeaseConflict):
            self.leases.acquire("vpc-a->vpc-c", "resolver-2", now_utc=t0 + 5)

        with self.assertRaises(ResolutionError):
            self.engine.resolve_overlap(
                source_vpc="vpc-a",
                target_vpc="vpc-c",
                source_cidr="10.10.0.0/16",
                target_cidr="10.20.0.0/16",
                translated_cidr="100.64.20.0/16",
                strategy="nat_1to1",
                fencing_token=lease.fencing_token,
                now_utc=t0 + 2,
            )

    def test_chaos_stale_token_rejected_after_takeover(self) -> None:
        t0 = 1764267000.0
        old_lease = self.leases.acquire("vpc-a->vpc-b", "resolver-1", now_utc=t0)
        # Resolver-1 stalls past TTL and resolver-2 acquires a new lease after expiry.
        new_lease = self.leases.acquire("vpc-a->vpc-b", "resolver-2", now_utc=t0 + 30)
        self.assertGreater(new_lease.fencing_token, old_lease.fencing_token)

        with self.assertRaises(ResolutionError):
            self.engine.resolve_overlap(
                source_vpc="vpc-a",
                target_vpc="vpc-b",
                source_cidr="10.10.0.0/16",
                target_cidr="10.10.0.0/16",
                translated_cidr="100.64.0.0/16",
                strategy="nat_1to1",
                fencing_token=old_lease.fencing_token,
                now_utc=t0 + 31,
            )

    def test_hmac_and_skew(self) -> None:
        secret = "cidr-secret"
        body = b'{"source_vpc":"vpc-a","target_vpc":"vpc-b"}'
        now = 1764267000
        sig = sign_payload(secret, now, body)
        ok, _ = verify_payload(secret, sig, str(now), body, now_unix=now)
        self.assertTrue(ok)
        expired, _ = verify_payload(secret, sig, str(now - 301), body, now_unix=now)
        self.assertFalse(expired)

    def test_bench_lease_and_ledger(self) -> None:
        ledger = HashChainedLedger()
        mgr = PrefixFencingLeaseManager(ledger=ledger, ttl_sec=30.0)
        base = 1764267000.0
        iters = 2000
        t0 = time.perf_counter()
        for i in range(iters):
            key = f"vpc-{i % 8}->vpc-tgt"
            lease = mgr.acquire(key, f"r-{i % 3}", now_utc=base + (i * 35.0))
            self.assertTrue(mgr.validate_token(key, lease.fencing_token, now_utc=base + (i * 35.0)))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        ok, _ = ledger.verify()
        self.assertTrue(ok)
        print(f"BENCH lease+validate+ledger ({iters} ops): {elapsed_ms:.2f} ms ({(elapsed_ms / iters) * 1000:.2f} us/op)")


if __name__ == "__main__":
    unittest.main()

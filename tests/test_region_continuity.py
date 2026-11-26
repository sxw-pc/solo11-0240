import pathlib
import tempfile
import unittest

from cloudroll.cli import apply_command, audit
from cloudroll.store import open_db, one, rows


class RegionContinuityBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.temp.name) / "region.sqlite"))
        self.seq = 0

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def do(self, op, **arguments):
        self.seq += 1
        if op in ("artifact.plan", "artifact.revoke"):
            arguments.setdefault("event_id", f"decision-{self.seq}")
        return apply_command(self.db, op, arguments, f"command-{self.seq}")

    def assert_audit(self):
        result = audit(self.db)
        self.assertTrue(result["verified"], result["mismatches"])
        return result

    def seed_generations(self):
        self.do("artifact.register", artifact_id="old7", digest="old7hash",
                min_api=3, max_api=3, format="old")
        self.do("artifact.register", artifact_id="old8-east", digest="east8oldhash",
                min_api=3, max_api=3, format="old")
        self.do("artifact.register", artifact_id="new8-south", digest="south8newhash",
                min_api=3, max_api=4, format="new")
        self.do("recovery.region_stable", service="svc", region="east",
                artifact_id="old7", generation=7, api=3)
        self.do("recovery.region_stable", service="svc", region="south",
                artifact_id="new8-south", generation=8, api=3)
        self.do("stage.link_down", link_id="cut", service="svc",
                region_a="east", region_b="south", at=100)
        # While parted, East checks out its OWN generation 8 in the old format.
        self.do("recovery.region_stable", service="svc", region="east",
                artifact_id="old8-east", generation=8, api=3, at=101)


class FixedScenarioTest(RegionContinuityBase):
    def test_single_region_write_keeps_only_w1_and_never_confirms_w2(self):
        self.seed_generations()
        self.assertEqual(
            self.do("stage.policy", service="svc", mode="single_writer",
                    writer_region="east"), "recorded")
        w1 = self.do("write.submit", global_id="W1", service="svc", region="east",
                     customer="C", payload={"v": 1}, format="old")
        self.assertEqual(w1, "confirmed")

        w2 = self.do("write.submit", global_id="W2", service="svc", region="south",
                     customer="C", payload={"v": 2}, format="new")
        # South write can never be a successful customer acknowledgement.
        self.assertNotEqual(w2, "confirmed")
        self.assertNotEqual(w2, "committed")
        self.assertTrue(
            w2 in ("rejected", "read_only", "region_read_only", "staged", "queued"),
            str(w2))

        durable = rows(self.db,
                       "SELECT global_id FROM write_record "
                       "WHERE service='svc' AND committed=1 ORDER BY global_id")
        self.assertEqual([r["global_id"] for r in durable], ["W1"])
        # W2 was either not stored at all or stored explicitly un-committed.
        w2_rows = rows(self.db, "SELECT committed,status FROM write_record WHERE global_id='W2'")
        for r in w2_rows:
            self.assertFalse(r["committed"])
        self.assert_audit()

    def test_single_region_write_explicit_staging_is_not_confirmation(self):
        self.seed_generations()
        self.do("stage.policy", service="svc", mode="single", writer_region="east",
                handling="stage")
        w2 = self.do("write.stage", global_id="W2", service="svc", region="south",
                     customer="C", payload={"v": 2}, format="new")
        self.assertEqual(w2, "staged")
        durable = rows(self.db,
                       "SELECT global_id FROM write_record WHERE committed=1")
        self.assertEqual([r["global_id"] for r in durable], [])
        staged = one(self.db, "SELECT status,committed FROM write_record WHERE global_id='W2'")
        self.assertEqual(staged["status"], "staged")
        self.assertFalse(staged["committed"])
        self.assert_audit()

    def test_bridge_mode_preserves_both_confirmed_writes(self):
        self.seed_generations()
        self.do("artifact.bridge", bridge_id="old-new", from_format="old",
                to_format="new", reversible=True)
        self.do("stage.policy", service="svc", mode="dual_write",
                writer_region="east", bridge_id="old-new")

        w1 = self.do("write.submit", global_id="W1", service="svc", region="east",
                     customer="C", payload="one", format="old")
        w2 = self.do("write.submit", global_id="W2", service="svc", region="south",
                     customer="C", payload="two", format="new")
        self.assertEqual(w1, "confirmed")
        self.assertEqual(w2, "confirmed")

        self.do("region.reconnect", link_id="heal", service="svc", at=200)
        result = self.do("recovery.reconcile", service="svc")
        ids = sorted(item["global_id"] for item in result["merged"])
        self.assertEqual(ids, ["W1", "W2"])
        self.assertFalse(result["conflicts"])
        # Both regional generation-8 issuances survive reconciliation evidence.
        digests = sorted(i["digest"] for i in result["issuances"] if i["generation"] == 8)
        self.assertEqual(digests, ["east8oldhash", "south8newhash"])
        self.assert_audit()

    def test_confirmed_w2_cannot_be_rewritten_into_single_region_history(self):
        self.seed_generations()
        self.do("stage.policy", service="svc", mode="bridge")
        self.do("write.submit", global_id="W1", service="svc", region="east", format="old")
        self.do("write.submit", global_id="W2", service="svc", region="south", format="new")
        # Operator later tries to declare the incident single-writer only.
        changed = self.do("stage.policy", service="svc", mode="single_writer",
                          writer_region="east")
        self.assertGreaterEqual(changed["protected_commitments"], 2)
        # A client retry of confirmed W2 via the now read-only South still
        # resolves to its original promise rather than a fresh rejection.
        retry = self.do("write.submit", global_id="W2", service="svc", region="south")
        self.assertEqual(retry, "confirmed")
        durable = rows(self.db,
                       "SELECT global_id FROM write_record WHERE committed=1 ORDER BY global_id")
        self.assertEqual([r["global_id"] for r in durable], ["W1", "W2"])
        self.assert_audit()


class SameGenerationDifferentDigestTest(RegionContinuityBase):
    def test_both_issuances_and_source_sequences_preserved(self):
        self.do("artifact.register", artifact_id="a8", digest="digest-A",
                min_api=3, max_api=3)
        self.do("artifact.register", artifact_id="b8", digest="digest-B",
                min_api=3, max_api=4)
        self.assertEqual(self.do("recovery.region_stable", service="svc",
                                 region="east", artifact_id="a8", generation=8, api=3),
                         "recorded")
        self.assertEqual(self.do("recovery.region_stable", service="svc",
                                 region="south", artifact_id="b8", generation=8, api=3),
                         "recorded")
        issuances = rows(self.db,
                         "SELECT region,digest FROM region_stable "
                         "WHERE service='svc' AND generation=8 ORDER BY region")
        self.assertEqual([(r["region"], r["digest"]) for r in issuances],
                         [("east", "digest-A"), ("south", "digest-B")])
        # Global pointer is not silently chosen by generation alone.
        self.assertIsNone(one(self.db, "SELECT * FROM stable WHERE service='svc'"))
        self.assert_audit()


class ReconnectAndSequenceTest(RegionContinuityBase):
    def test_missing_source_sequence_is_backfill_obligation(self):
        self.do("write.submit", global_id="A", service="svc", region="south", source_seq=1)
        self.do("write.submit", global_id="C", service="svc", region="south", source_seq=3)
        result = self.do("recovery.reconcile", service="svc")
        missing = [item["source_seq"] for item in result["missing_sequences"]]
        self.assertIn(2, missing)
        blocked = self.do("recovery.switch_pointer", service="svc")
        self.assertEqual(blocked, "backfill_required")
        # Resend the missing sequence.
        self.do("write.submit", global_id="B", service="svc", region="south", source_seq=2)
        healed = self.do("recovery.reconcile", service="svc")
        self.assertEqual(healed["missing_sequences"], [])
        self.assert_audit()

    def test_reconnect_required_before_reconcile(self):
        self.do("stage.link_down", link_id="cut", service="svc")
        self.do("write.submit", global_id="W1", service="svc", region="east")
        parted = self.do("recovery.reconcile", service="svc")
        self.assertEqual(parted["status"], "partitioned")
        self.do("stage.link_up", link_id="heal", service="svc")
        self.assertEqual(self.do("recovery.reconcile", service="svc")["status"], "merged")
        self.assert_audit()


class UnknownCommitRecoveryTest(RegionContinuityBase):
    def test_lost_ack_receipt_still_finds_promised_commit(self):
        # Gateway object + regional sequence committed, acknowledgement lost.
        self.do("write.commit", global_id="W2", service="svc", region="south",
                customer="C", payload="sale", format="new", ack=False)
        probe = self.do("write.recover", global_id="W2", service="svc")
        self.assertEqual(probe["status"], "committed")
        self.assertTrue(probe["promised"])
        self.assertEqual(probe["decision"], "honor_and_backfill")
        self.assertIn("south", probe["source_sequences"])
        # A genuinely unknown identity is safe to reject / retry.
        unknown = self.do("commit.status", global_id="WX", service="svc")
        self.assertEqual(unknown["status"], "unknown")
        self.assertFalse(unknown["promised"])
        self.assert_audit()

    def test_duplicate_confirmation_consumes_one_sequence(self):
        first = self.do("write.ack", ack_id="ack-1", global_id="W1")
        # No write exists yet with this id, so acknowledge the write first.
        self.do("write.submit", global_id="W1", service="svc", region="east")
        self.do("write.ack", ack_id="ack-2", global_id="W1")
        again_same_id = self.do("write.ack", ack_id="ack-2", global_id="W1")
        again_business = self.do("write.confirm", global_id="W1")
        self.assertEqual(again_same_id, "duplicate")
        self.assertEqual(again_business, "duplicate")
        seqs = rows(self.db, "SELECT source_seq FROM write_record WHERE global_id='W1'")
        self.assertEqual(len(seqs), 1)
        self.assert_audit()


class RegionLeaseTest(RegionContinuityBase):
    def test_only_locally_deployed_correct_digest_enters_rw_route(self):
        self.do("artifact.register", artifact_id="a8", digest="good", min_api=3, max_api=4)
        bad = self.do("stage.deploy", deployment_id="dep-bad", service="svc",
                      region="south", artifact_id="a8", digest="tampered")
        self.assertEqual(bad, "digest_mismatch")
        denied = self.do("stage.lease", lease_id="lease-bad", service="svc",
                         region="south", generation=8, digest="good", role="rw")
        self.assertEqual(denied, "region_not_deployed")
        self.do("stage.deploy", deployment_id="dep-good", service="svc",
                region="south", artifact_id="a8", digest="good", generation=8)
        lease = self.do("region.lease", lease_id="lease-good", service="svc",
                        region="south", generation=8, digest="good", role="rw")
        self.assertEqual(lease, "active")
        routes = self.do("stage.routing", service="svc")
        self.assertIn("south", routes["writers"])
        self.assert_audit()


class FormatBridgeGuardTest(RegionContinuityBase):
    def test_old_format_copy_cannot_overwrite_new_format_record(self):
        self.do("stage.policy", service="svc", mode="bridge")
        self.do("write.submit", global_id="W2", service="svc", region="east", format="old")
        self.do("write.submit", global_id="W2", service="svc", region="south", format="new")
        self.do("artifact.bridge", bridge_id="one-way", from_format="old",
                to_format="new", reversible=False)
        blocked = self.do("write.replicate", global_id="W2",
                          from_region="east", to_region="south")
        self.assertEqual(blocked, "old_overwrites_new")
        # A per-record proof of the same business operation unblocks the copy.
        self.assertEqual(self.do("bridge.prove", proof_id="proof-1", global_id="W2",
                                 region_a="east", region_b="south"), "proven")
        self.assertEqual(self.do("write.deliver", global_id="W2",
                                 from_region="east", to_region="south"), "delivered")
        self.assert_audit()


class OldProxyBandwidthTest(RegionContinuityBase):
    def test_unexpired_commitment_without_bandwidth_is_not_eligible(self):
        self.do("artifact.register", artifact_id="cand", digest="h", min_api=1, max_api=4)
        # Contract covers protocols 1..3, so population on protocol 0 needs proxy.
        self.do("artifact.contract", artifact_id="cand", min_protocol=1, max_protocol=3)
        self.do("artifact.population", service="svc", protocol=0, count=5)
        # Time coverage alone used to be enough; now placement + band matter.
        self.do("artifact.proxy", commitment_id="px", service="svc", protocol=0,
                until_ts=10, region="east", bandwidth=100)
        self.do("artifact.proxy_path", path_id="px-path", commitment_id="px",
                service="svc", region="east", bandwidth=5,
                required_bandwidth=50, at=5)
        result = __import__("cloudroll.artifact", fromlist=["client_eligibility"]) \
            .client_eligibility(self.db, "svc", "cand", 10, required_bandwidth=50)
        self.assertEqual(result, "proxy_bandwidth_insufficient")
        self.assert_audit()


if __name__ == "__main__":
    unittest.main()

import itertools
import pathlib
import tempfile
import unittest

import cloudroll
from cloudroll.cli import apply_command, audit
from cloudroll.store import open_db, one, rows


class ReleasePaths(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.temp.name) / "release.sqlite"))
        self.sequence = itertools.count(1)
        self.assertTrue(pathlib.Path(cloudroll.__file__).resolve().is_relative_to(
            pathlib.Path(__file__).resolve().parents[1]))

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def do(self, operation, **arguments):
        ordinal = next(self.sequence)
        if operation in ("artifact.plan", "artifact.revoke"):
            arguments.setdefault("event_id", f"decision-{ordinal}")
        return apply_command(self.db, operation, arguments, f"command-{ordinal}")

    def foundation(self, protocol=1):
        self.do("artifact.baseline", service="svc", api=3, generation=1)
        self.do("artifact.register", artifact_id="stable", digest="oldhash", min_api=2, max_api=4)
        self.do("artifact.register", artifact_id="candidate", digest="newhash", min_api=2, max_api=4)
        self.do("artifact.contract", artifact_id="candidate", min_protocol=1, max_protocol=3)
        self.do("artifact.population", service="svc", protocol=protocol, count=5)

    def locked_stage(self, members=None, start=2, end=6):
        self.foundation()
        self.assertEqual(self.do("artifact.plan", plan_id="plan", service="svc",
                                 artifact_id="candidate", start_ts=1, end_ts=10), "locked")
        self.assertEqual(self.do("stage.start", stage_id="stage", plan_id="plan",
                                 members=members or [{"replica": "a", "generation": 1},
                                                     {"replica": "b", "generation": 1}],
                                 start_ts=start, end_ts=end), "started")

    def assert_audit(self):
        result = audit(self.db)
        self.assertTrue(result["verified"], result["mismatches"])

    def test_client_contract_proxy_must_cover_release_window(self):
        self.foundation(protocol=0)
        self.assertEqual(self.do("artifact.plan", plan_id="plan", service="svc",
                                 artifact_id="candidate", start_ts=1, end_ts=10),
                         "unsupported_active_clients")
        self.do("artifact.proxy", commitment_id="short", service="svc", protocol=0, until_ts=9)
        self.assertEqual(self.do("artifact.plan", plan_id="plan", service="svc",
                                 artifact_id="candidate", start_ts=1, end_ts=10),
                         "unsupported_active_clients")
        self.do("artifact.proxy", commitment_id="full", service="svc", protocol=0, until_ts=10)
        self.assertEqual(self.do("artifact.plan", plan_id="plan", service="svc",
                                 artifact_id="candidate", start_ts=1, end_ts=10), "locked")
        self.assert_audit()

    def test_baseline_generation_change_blocks_old_locked_plan_stage(self):
        self.foundation()
        self.do("artifact.plan", plan_id="plan", service="svc", artifact_id="candidate",
                start_ts=1, end_ts=10)
        self.do("artifact.baseline", service="svc", api=4, generation=2)
        self.assertEqual(self.do("stage.start", stage_id="stage", plan_id="plan",
                                 members=[{"replica": "a", "generation": 1}],
                                 start_ts=2, end_ts=6), "baseline_or_artifact_changed")
        self.assertEqual(one(self.db, "SELECT COUNT(*) AS n FROM stage")["n"], 0)
        self.assert_audit()

    def test_client_population_change_between_plan_and_stage_blocks_activation(self):
        self.foundation(protocol=1)
        self.do("artifact.plan", plan_id="plan", service="svc", artifact_id="candidate",
                start_ts=1, end_ts=10)
        self.do("artifact.population", service="svc", protocol=0, count=3)
        self.assertEqual(self.do("stage.start", stage_id="stage", plan_id="plan",
                                 members=[{"replica": "a", "generation": 1}],
                                 start_ts=2, end_ts=6), "client_contract_no_longer_covered")
        self.do("artifact.proxy", commitment_id="proxy", service="svc", protocol=0, until_ts=10)
        self.assertEqual(self.do("stage.start", stage_id="stage", plan_id="plan",
                                 members=[{"replica": "a", "generation": 1}],
                                 start_ts=2, end_ts=6), "started")
        self.assert_audit()

    def test_invalid_release_window_and_duplicate_plan_id_do_not_change_other_service(self):
        self.foundation()
        self.assertEqual(self.do("artifact.plan", plan_id="plan", service="svc",
                                 artifact_id="candidate", start_ts=10, end_ts=1),
                         "invalid_release_window")
        self.assertEqual(self.do("artifact.plan", plan_id="plan", service="svc",
                                 artifact_id="candidate", start_ts=1, end_ts=10), "locked")
        self.do("artifact.baseline", service="other", api=3, generation=1)
        self.do("artifact.population", service="other", protocol=1, count=2)
        self.assertEqual(self.do("artifact.plan", plan_id="plan", service="other",
                                 artifact_id="candidate", start_ts=1, end_ts=10),
                         "plan_identity_conflict")
        self.assertEqual(one(self.db, "SELECT service FROM plan WHERE id='plan'")["service"], "svc")
        self.assert_audit()

    def test_member_snapshot_prevents_late_replica_from_satisfying_missing_receipt(self):
        self.locked_stage()
        self.assertEqual(self.do("stage.receipt", receipt_id="late", stage_id="stage",
                                 replica="c", generation=1, digest="newhash"), "not_a_fixed_member")
        self.do("stage.receipt", receipt_id="a-ack", stage_id="stage", replica="a",
                generation=1, digest="newhash")
        self.do("stage.sample", sample_id="a-health", stage_id="stage", replica="a",
                at=4, digest="newhash", healthy=True)
        self.assertIn("b", self.do("stage.decide", stage_id="stage", at=7))
        self.assertEqual(one(self.db, "SELECT status FROM stage WHERE id='stage'")["status"], "failed")
        self.assert_audit()

    def test_latest_in_window_health_sample_controls_failure_budget(self):
        self.locked_stage(members=[{"replica": "a", "generation": 1}])
        self.do("stage.receipt", receipt_id="a-ack", stage_id="stage", replica="a",
                generation=1, digest="newhash")
        self.do("stage.sample", sample_id="healthy", stage_id="stage", replica="a",
                at=3, digest="newhash", healthy=True)
        self.do("stage.sample", sample_id="unhealthy", stage_id="stage", replica="a",
                at=5, digest="newhash", healthy=False)
        self.assertTrue(self.do("stage.decide", stage_id="stage", at=5).startswith("failed"))
        self.assertEqual(one(self.db, "SELECT status FROM recovery WHERE id='rec-stage'")["status"], "open")
        self.assert_audit()

    def test_two_stage_release_cannot_skip_wave_and_only_final_wave_passes_plan(self):
        self.foundation()
        self.assertEqual(self.do("artifact.plan", plan_id="plan", service="svc",
                                 artifact_id="candidate", start_ts=1, end_ts=20,
                                 stage_count=2), "locked")
        member=[{"replica":"a","generation":1}]
        self.assertEqual(self.do("stage.start", stage_id="second", plan_id="plan", members=member,
                                 start_ts=11, end_ts=16, ordinal=2), "previous_stage_not_passed")
        self.do("stage.start", stage_id="first", plan_id="plan", members=member,
                start_ts=2, end_ts=8, ordinal=1)
        self.do("stage.receipt", receipt_id="ack1", stage_id="first", replica="a",
                generation=1, digest="newhash")
        self.do("stage.sample", sample_id="health1", stage_id="first", replica="a",
                at=5, digest="newhash", healthy=True)
        self.assertEqual(self.do("stage.decide", stage_id="first", at=8), "passed")
        self.assertEqual(one(self.db,"SELECT status FROM plan WHERE id='plan'")["status"],"locked")
        self.assertEqual(self.do("stage.start", stage_id="second", plan_id="plan", members=member,
                                 start_ts=11, end_ts=16, ordinal=2), "started")
        self.do("stage.receipt", receipt_id="ack2", stage_id="second", replica="a",
                generation=1, digest="newhash")
        self.do("stage.sample", sample_id="health2", stage_id="second", replica="a",
                at=13, digest="newhash", healthy=True)
        self.assertEqual(self.do("stage.decide", stage_id="second", at=16), "passed")
        self.assertEqual(one(self.db,"SELECT status FROM plan WHERE id='plan'")["status"],"passed")
        self.assert_audit()

    def test_revocation_blocks_stage_without_erasing_deployment_receipts(self):
        self.locked_stage(members=[{"replica": "a", "generation": 1}])
        self.do("stage.receipt", receipt_id="a-ack", stage_id="stage", replica="a",
                generation=1, digest="newhash")
        self.assertEqual(self.do("artifact.revoke", artifact_id="candidate", seq=4), "revoked")
        self.assertEqual(self.do("stage.decide", stage_id="stage", at=4), "blocked_revoked")
        self.assertEqual(one(self.db, "SELECT digest FROM receipt WHERE id='a-ack'")["digest"], "newhash")
        self.assert_audit()

    def test_recovery_selects_compatible_historical_version_not_latest_number(self):
        self.locked_stage(members=[{"replica": "a", "generation": 1}])
        self.do("stage.decide", stage_id="stage", at=7)
        self.do("recovery.stable", service="svc", artifact_id="stable", api=3, generation=1)
        self.do("artifact.register", artifact_id="incompatible", digest="bad", min_api=5, max_api=7)
        self.assertEqual(self.do("recovery.stable", service="svc", artifact_id="incompatible",
                                 api=5, generation=2), "no_passed_release_or_stale_generation")
        self.assertEqual(self.do("recovery.choose", case_id="rec-stage"), "stable")
        self.assert_audit()

    def test_rollback_skips_newer_passed_history_after_runtime_baseline_downgrade(self):
        self.foundation()
        self.do("recovery.stable", service="svc", artifact_id="stable", api=3, generation=1)
        self.do("artifact.register", artifact_id="modern", digest="modernhash", min_api=5, max_api=7)
        self.do("artifact.contract", artifact_id="modern", min_protocol=1, max_protocol=3)
        self.do("artifact.baseline", service="svc", api=5, generation=2)
        self.assertEqual(self.do("artifact.plan", plan_id="modern-plan", service="svc",
                                 artifact_id="modern", start_ts=20, end_ts=30), "locked")
        self.do("stage.start", stage_id="modern-stage", plan_id="modern-plan",
                members=[{"replica": "a", "generation": 1}], start_ts=21, end_ts=25)
        self.do("stage.receipt", receipt_id="modern-ack", stage_id="modern-stage",
                replica="a", generation=1, digest="modernhash")
        self.do("stage.sample", sample_id="modern-health", stage_id="modern-stage",
                replica="a", at=23, digest="modernhash", healthy=True)
        self.assertEqual(self.do("stage.decide", stage_id="modern-stage", at=25), "passed")
        self.assertEqual(self.do("recovery.stable", service="svc", artifact_id="modern",
                                 api=5, generation=2), "recorded")
        self.do("artifact.baseline", service="svc", api=3, generation=3)
        self.do("artifact.plan", plan_id="failed-plan", service="svc",
                artifact_id="candidate", start_ts=40, end_ts=50)
        self.do("stage.start", stage_id="failed-stage", plan_id="failed-plan",
                members=[{"replica": "b", "generation": 1}], start_ts=41, end_ts=45)
        self.do("stage.decide", stage_id="failed-stage", at=46)
        self.assertEqual(self.do("recovery.choose", case_id="rec-failed-stage"), "stable")
        self.assertEqual(one(self.db, "SELECT target_artifact FROM recovery WHERE id='rec-failed-stage'")["target_artifact"],
                         "stable")
        self.assert_audit()

    def test_recovery_closure_requires_every_correct_member_and_service_orphan(self):
        self.locked_stage()
        self.do("stage.decide", stage_id="stage", at=7)
        self.do("recovery.stable", service="svc", artifact_id="stable", api=3, generation=1)
        self.do("recovery.choose", case_id="rec-stage")
        self.assertEqual(self.do("recovery.compensate", receipt_id="wrong", case_id="rec-stage",
                                 replica="a", generation=1, digest="bad"), "wrong_target_digest")
        self.do("recovery.compensate", receipt_id="a-back", case_id="rec-stage",
                replica="a", generation=1, digest="oldhash")
        self.assertEqual(self.do("recovery.close", case_id="rec-stage"), "incomplete_compensation")
        self.do("recovery.compensate", receipt_id="b-back", case_id="rec-stage",
                replica="b", generation=1, digest="oldhash")
        self.do("recovery.orphan", orphan_id="foreign", service="another", digest="bad", generation=1)
        self.assertEqual(self.do("recovery.close", case_id="rec-stage"), "closed")
        self.assertEqual(one(self.db, "SELECT artifact_id FROM stable WHERE service='svc'")["artifact_id"],
                         "stable")
        self.assert_audit()

    def test_orphan_in_failed_stage_cannot_be_adopted_even_with_matching_digest(self):
        self.locked_stage(members=[{"replica": "a", "generation": 1}])
        self.do("stage.decide", stage_id="stage", at=7)
        self.do("recovery.stable", service="svc", artifact_id="stable", api=3, generation=1)
        self.assertEqual(self.do("recovery.orphan", orphan_id="a", service="svc",
                                 digest="oldhash", generation=1), "quarantined")
        self.assertEqual(self.do("recovery.resolve_orphan", orphan_id="a", service="svc",
                                 digest="oldhash", generation=1,
                                 proof_artifact="stable"), "failed_stage_identity_conflict")
        self.assert_audit()

    def test_evidence_replay_detects_unlogged_state_change(self):
        self.foundation()
        self.assert_audit()
        self.db.execute("UPDATE baseline SET api=99 WHERE service='svc'")
        result = audit(self.db)
        self.assertFalse(result["verified"])
        self.assertTrue(any(item.get("table") == "baseline" for item in result["mismatches"]))


if __name__ == "__main__":
    unittest.main()

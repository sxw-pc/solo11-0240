import pathlib
import tempfile
import unittest

from cloudroll.cli import apply_command, audit
from cloudroll.store import open_db, one, rows


MEMBERS = [{"replica": "a", "generation": 1},
           {"replica": "b", "generation": 1}]


class LateCommitmentCausalTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(pathlib.Path(self.temp.name) / "late.sqlite")
        self.db = open_db(self.path)
        self.seq = 0

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def do(self, operation, **arguments):
        self.seq += 1
        if operation in ("artifact.plan", "artifact.revoke"):
            arguments.setdefault("event_id", f"event-{self.seq}")
        return apply_command(self.db, operation, arguments, f"cmd-{self.seq}")

    def foundation(self):
        self.do("artifact.baseline", service="svc", api=3, generation=1)
        self.do("artifact.register", artifact_id="old", digest="oldhash", min_api=3, max_api=3)
        self.do("artifact.register", artifact_id="new", digest="newhash", min_api=2, max_api=4)
        self.do("artifact.contract", artifact_id="new", min_protocol=1, max_protocol=2)
        self.do("artifact.population", service="svc", protocol=1, count=10)

    def two_stage_plan(self, policy=None, max_fail=0):
        self.foundation()
        kwargs = {}
        if policy is not None:
            kwargs["commit_policy"] = policy
        self.assertEqual(self.do("artifact.plan", plan_id="p1", service="svc",
                                artifact_id="new", start_ts=1, end_ts=10,
                                stage_count=2, **kwargs), "locked")
        start_kwargs = {}
        if policy is not None:
            start_kwargs["policy"] = policy
        self.assertEqual(self.do("stage.start", stage_id="s1", plan_id="p1",
                                members=MEMBERS, start_ts=2, end_ts=6,
                                max_fail=max_fail, **start_kwargs), "started")

    def healthy_evidence(self, stage="s1", at_a=3, at_b=4):
        self.do("stage.receipt", receipt_id="r-a-" + stage, stage_id=stage,
                replica="a", generation=1, digest="newhash")
        self.do("stage.receipt", receipt_id="r-b-" + stage, stage_id=stage,
                replica="b", generation=1, digest="newhash")
        self.do("stage.sample", sample_id="h-a-" + stage, stage_id=stage,
                replica="a", at=at_a, digest="newhash", healthy=True)
        self.do("stage.sample", sample_id="h-b-" + stage, stage_id=stage,
                replica="b", at=at_b, digest="newhash", healthy=True)

    def late_unhealthy_a(self, sample_id="late-a", at=6, digest="newhash"):
        return self.do("stage.sample", sample_id=sample_id, stage_id="s1",
                       replica="a", at=at, digest=digest, healthy=False)

    def assert_audit(self):
        result = audit(self.db)
        self.assertTrue(result["verified"], result["mismatches"])

    # ------------------------------------------------------------------
    # The two approved ways of handling the same originals.
    # ------------------------------------------------------------------

    def test_option_a_wait_leaves_only_provisional_observation_and_no_second_stage(self):
        self.two_stage_plan(policy="wait")
        self.healthy_evidence()
        verdict = self.do("stage.decide", stage_id="s1", at=5)
        # Minute 5: provisional observation only, not a formal pass.
        self.assertEqual(one(self.db, "SELECT status FROM stage WHERE id='s1'")["status"], "observing")
        self.assertEqual(verdict, "provisional")
        # The second stage cannot start / deploy anything.
        start_second = self.do("stage.start", stage_id="s2", plan_id="p1", ordinal=2,
                               members=MEMBERS, start_ts=7, end_ts=9)
        self.assertEqual(start_second, "previous_stage_not_passed")
        self.assertEqual(start_second, "commitment_not_final")
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM stage WHERE id='s2'")["n"], 0)
        # Minute 6 failure original arrives -> first stage genuinely fails.
        self.late_unhealthy_a()
        revised = self.do("stage.decide", stage_id="s1", at=7)
        self.assertTrue(str(revised).startswith("failed"))
        self.assertEqual(one(self.db, "SELECT status FROM stage WHERE id='s1'")["status"], "failed")
        self.assertEqual(one(self.db, "SELECT status FROM recovery WHERE id='rec-s1'")["status"], "open")
        # The defining fact of option A: no second-stage deployment exists.
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM stage")["n"], 1)
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM receipt WHERE stage_id='s2'")["n"], 0)
        self.assert_audit()

    def test_option_b_revocable_commitment_deploys_freezes_and_books_obligations(self):
        self.two_stage_plan(policy="revocable")
        self.healthy_evidence()
        verdict = self.do("stage.decide", stage_id="s1", at=5)
        self.assertEqual(verdict, "passed")
        self.assertEqual(verdict, "revocable")
        commitment = one(self.db, "SELECT * FROM commitment WHERE stage_id='s1' AND kind='canary'")
        self.assertEqual(str(commitment["status"]), "revocable")
        self.assertEqual(commitment["revocable"], 1)
        # Second stage really starts and both deployment receipts are issued.
        self.assertEqual(self.do("stage.start", stage_id="s2", plan_id="p1", ordinal=2,
                                members=MEMBERS, start_ts=7, end_ts=9), "started")
        self.do("stage.receipt", receipt_id="q1", stage_id="s2", replica="a", generation=1, digest="newhash")
        self.do("stage.receipt", receipt_id="q2", stage_id="s2", replica="b", generation=1, digest="newhash")
        self.do("stage.traffic", traffic_id="traffic-1", stage_id="s2",
                replica="a", amount=40, at=8)
        # Minute 6 late genuine failure page overturns the commitment.
        self.late_unhealthy_a()
        revised = self.do("stage.reconsider", stage_id="s1", at=7)
        self.assertEqual(revised, "revoked")
        self.assertEqual(one(self.db, "SELECT status FROM stage WHERE id='s1'")["status"], "failed")
        self.assertEqual(str(one(self.db, "SELECT status FROM commitment WHERE id='commit:s1:canary'")["status"]),
                         "withdrawn")
        # Started successor is preserved but frozen, members + receipts kept.
        self.assertEqual(str(one(self.db, "SELECT status FROM stage WHERE id='s2'")["status"]), "frozen")
        states = {r["replica"]: str(r["status"]) for r in rows(self.db, "SELECT replica,status FROM member WHERE stage_id='s2'")}
        self.assertEqual(states, {"a": "frozen", "b": "frozen"})
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM receipt WHERE stage_id='s2'")["n"], 2)
        # Compensation obligations exist for physical copies and traffic.
        kinds = {r["kind"] for r in rows(self.db, "SELECT DISTINCT kind FROM obligation WHERE case_id='rec-s1'")}
        self.assertIn("replica", kinds)
        self.assertIn("traffic", kinds)
        traffic_obl = one(self.db, "SELECT amount,status FROM obligation WHERE case_id='rec-s1' AND kind='traffic'")
        self.assertGreaterEqual(traffic_obl["amount"], 40)
        self.assertEqual(str(traffic_obl["status"]), "due")
        self.assert_audit()

    def test_legacy_immediate_pass_with_started_successor_is_revisable(self):
        # The exact prompt situation: old behaviour passed at minute 5 and the
        # second stage already has two receipts before the late page arrives.
        self.two_stage_plan()  # default / immediate policy
        self.healthy_evidence()
        self.assertEqual(self.do("stage.decide", stage_id="s1", at=5), "passed")
        self.assertEqual(self.do("stage.start", stage_id="s2", plan_id="p1", ordinal=2,
                                members=MEMBERS, start_ts=7, end_ts=9), "started")
        self.do("stage.receipt", receipt_id="q1", stage_id="s2", replica="a", generation=1, digest="newhash")
        self.do("stage.receipt", receipt_id="q2", stage_id="s2", replica="b", generation=1, digest="newhash")
        self.late_unhealthy_a()
        # Re-requesting a decision now re-adjudicates instead of "not_running".
        revised = self.do("stage.decide", stage_id="s1", at=6)
        self.assertTrue(str(revised).startswith("failed"), revised)
        self.assertNotEqual(revised, "not_running")
        self.assertEqual(one(self.db, "SELECT status FROM plan WHERE id='p1'")["status"], "failed")
        self.assertEqual(str(one(self.db, "SELECT status FROM stage WHERE id='s2'")["status"]), "frozen")
        self.assertTrue(one(self.db, "SELECT id FROM recovery WHERE id='rec-s1'"))
        self.assert_audit()

    # ------------------------------------------------------------------
    # Identity / seal dimensions.
    # ------------------------------------------------------------------

    def test_non_member_rejected_for_receipt_and_sample(self):
        self.two_stage_plan()
        self.assertEqual(self.do("stage.receipt", receipt_id="x", stage_id="s1",
                                 replica="c", generation=1, digest="newhash"), "not_a_fixed_member")
        self.assertEqual(self.do("stage.sample", sample_id="y", stage_id="s1",
                                 replica="c", at=4, digest="newhash", healthy=False), "not_a_fixed_member")
        self.assert_audit()

    def test_wrong_digest_original_does_not_overturn_pass(self):
        self.two_stage_plan()
        self.healthy_evidence()
        self.assertEqual(self.do("stage.decide", stage_id="s1", at=5), "passed")
        self.assertEqual(self.do("stage.receipt", receipt_id="bad-ack", stage_id="s1",
                                 replica="a", generation=1, digest="wronghash"),
                         "wrong_identity_or_digest")
        # A wrong-digest unhealthy page may be admitted as evidence but must
        # never count towards the sealed decision.
        bad = self.late_unhealthy_a(sample_id="bad-page", digest="wronghash")
        self.assertEqual(bad, "wrong_identity_or_digest")  # compat verdict also equals recorded
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM sample WHERE id='bad-page'")["n"], 0)
        again = self.do("stage.decide", stage_id="s1", at=7)
        self.assertEqual(again, "passed")
        self.assertIsNone(one(self.db, "SELECT id FROM recovery WHERE id='rec-s1'"))
        self.assert_audit()

    # ------------------------------------------------------------------
    # Failure budget zero vs one.
    # ------------------------------------------------------------------

    def test_failure_budget_zero_overturns_on_first_unhealthy_member(self):
        self.two_stage_plan(max_fail=0)
        self.healthy_evidence()
        self.do("stage.decide", stage_id="s1", at=5)
        self.late_unhealthy_a()
        result = self.do("stage.reconsider", stage_id="s1", at=6)
        self.assertTrue(str(result).startswith("failed"))
        self.assertEqual(one(self.db, "SELECT status FROM stage WHERE id='s1'")["status"], "failed")
        self.assert_audit()

    def test_failure_budget_one_tolerates_one_member_but_not_two(self):
        self.two_stage_plan(max_fail=1)
        self.healthy_evidence()
        self.assertEqual(self.do("stage.decide", stage_id="s1", at=5), "passed")
        self.late_unhealthy_a()
        # One failure is within budget: qualification is upheld.
        self.assertEqual(self.do("stage.reconsider", stage_id="s1", at=6), "passed")
        self.assertEqual(one(self.db, "SELECT status FROM stage WHERE id='s1'")["status"], "passed")
        # A second distinct unhealthy member exhausts budget 1 (2 > 1).
        self.do("stage.sample", sample_id="late-b", stage_id="s1", replica="b",
                at=6, digest="newhash", healthy=False)
        result = self.do("stage.reconsider", stage_id="s1", at=7)
        self.assertTrue(str(result).startswith("failed"))
        self.assertEqual(one(self.db, "SELECT status FROM stage WHERE id='s1'")["status"], "failed")
        self.assert_audit()

    # ------------------------------------------------------------------
    # Revocation / proxy / re-release checks.
    # ------------------------------------------------------------------

    def test_artifact_revocation_blocks_and_rerelease_recheck_detects_it(self):
        self.two_stage_plan(policy="revocable")
        self.healthy_evidence()
        self.do("stage.decide", stage_id="s1", at=5)
        self.assertEqual(self.do("artifact.revoke", artifact_id="new", seq=4), "revoked")
        self.assertEqual(self.do("stage.reconsider", stage_id="s1", at=6), "blocked_revoked")
        recheck = self.do("artifact.recheck", plan_id="p1", at=8)
        self.assertEqual(recheck, "blocked_revoked")
        rerelease = self.do("stage.rerelease", plan_id="p1", at=8)
        self.assertEqual(rerelease, "blocked_revoked")
        self.assert_audit()

    def test_lapsed_proxy_contract_blocks_rerelease_check(self):
        self.foundation()
        # Add an incumbent protocol with no covering proxy.
        self.do("artifact.population", service="svc", protocol=9, count=3)
        self.assertEqual(self.do("artifact.plan", plan_id="p2", service="svc",
                                 artifact_id="new", start_ts=1, end_ts=10),
                         "unsupported_active_clients")
        self.do("artifact.proxy", commitment_id="px", service="svc", protocol=9, until_ts=9)
        eligibility = self.do("artifact.recheck", service="svc", artifact_id="new", end_ts=10)
        self.assertEqual(eligibility, "unsupported_active_clients")
        self.assert_audit()

    def test_rerelease_revalidates_window(self):
        self.two_stage_plan()
        self.healthy_evidence()
        self.do("stage.decide", stage_id="s1", at=5)
        self.late_unhealthy_a()
        self.do("stage.reconsider", stage_id="s1", at=7)
        closed = self.do("stage.rerelease", plan_id="p1", at=11)
        self.assertEqual(closed, "stage_outside_release_window")
        ok = self.do("stage.rerelease", plan_id="p1", at=8)
        self.assertEqual(ok, "eligible")
        self.assert_audit()

    # ------------------------------------------------------------------
    # Stable pointer guard across the live successor.
    # ------------------------------------------------------------------

    def test_old_version_cannot_become_stable_while_successor_running_or_frozen(self):
        self.two_stage_plan(policy="revocable")
        self.healthy_evidence()
        self.do("stage.decide", stage_id="s1", at=5)
        self.do("stage.start", stage_id="s2", plan_id="p1", ordinal=2,
                members=MEMBERS, start_ts=7, end_ts=9)
        self.do("stage.receipt", receipt_id="q1", stage_id="s2", replica="a", generation=1, digest="newhash")
        # Successor still running with one receipt: pointer move is refused.
        blocked = self.do("recovery.stable", service="svc", artifact_id="old", api=3, generation=1)
        self.assertEqual(blocked, "successor_still_running")
        self.assertIsNone(one(self.db, "SELECT artifact_id FROM stable WHERE service='svc'"))
        # Finish receipts + overturn -> frozen; still refused, but history is
        # recorded so a recovery target can be chosen.
        self.do("stage.receipt", receipt_id="q2", stage_id="s2", replica="b", generation=1, digest="newhash")
        self.late_unhealthy_a()
        self.do("stage.reconsider", stage_id="s1", at=7)
        again = self.do("recovery.stable", service="svc", artifact_id="old", api=3, generation=1)
        self.assertEqual(again, "successor_still_running")
        self.assertEqual(one(self.db, "SELECT artifact_id FROM stable_history WHERE service='svc' AND generation=1")["artifact_id"], "old")
        self.assertEqual(self.do("recovery.choose", case_id="rec-s1"), "old")
        self.assertEqual(self.do("recovery.compensate", receipt_id="c1", case_id="rec-s1",
                                 replica="a", generation=1, digest="oldhash"), "recorded")
        self.assertEqual(self.do("recovery.compensate", receipt_id="c2", case_id="rec-s1",
                                 replica="b", generation=1, digest="oldhash"), "recorded")
        # Physical copies are settled but the served-traffic duty remains open.
        self.assertEqual(self.do("recovery.close", case_id="rec-s1"), "incomplete_compensation")
        self.assertEqual(self.do("recovery.compensate_traffic", receipt_id="ct1",
                                 case_id="rec-s1"), "recorded")
        self.assertEqual(self.do("recovery.close", case_id="rec-s1"), "closed")
        pointer = one(self.db, "SELECT artifact_id FROM stable WHERE service='svc'")
        self.assertEqual(pointer["artifact_id"], "old")
        self.assertEqual(str(one(self.db, "SELECT status FROM stage WHERE id='s2'")["status"]), "compensated")
        self.assert_audit()

    # ------------------------------------------------------------------
    # Duplicates / idempotent resend / power loss.
    # ------------------------------------------------------------------

    def test_duplicate_receipt_and_same_request_replay(self):
        self.two_stage_plan()
        args = dict(receipt_id="r1", stage_id="s1", replica="a", generation=1, digest="newhash")
        self.assertEqual(self.do("stage.receipt", **args), "recorded")
        self.assertEqual(self.do("stage.receipt", **args), "duplicate")
        self.assertEqual(self.do("stage.receipt", receipt_id="r2x", stage_id="s1",
                                 replica="a", generation=1, digest="newhash"),
                         "already_acknowledged")
        # Same request id resend returns the original logged verdict.
        first = apply_command(self.db, "stage.sample",
                              {"sample_id": "h9", "stage_id": "s1", "replica": "b",
                               "at": 4, "digest": "newhash", "healthy": True},
                              "same-request")
        resent = apply_command(self.db, "stage.sample",
                               {"sample_id": "h9", "stage_id": "s1", "replica": "b",
                                "at": 4, "digest": "newhash", "healthy": True},
                               "same-request")
        self.assertEqual(first, resent)
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM sample WHERE id='h9'")["n"], 1)
        self.assert_audit()

    def test_power_loss_reopen_reconstructs_same_history(self):
        self.two_stage_plan(policy="revocable")
        self.healthy_evidence()
        self.do("stage.decide", stage_id="s1", at=5)
        self.late_unhealthy_a()
        self.do("stage.reconsider", stage_id="s1", at=7)
        before = one(self.db, "SELECT status FROM stage WHERE id='s1'")["status"]
        self.db.close()  # power loss / handle close after commit
        db2 = open_db(self.path)
        try:
            self.assertEqual(one(db2, "SELECT status FROM stage WHERE id='s1'")["status"], before)
            result = audit(db2)
            self.assertTrue(result["verified"], result["mismatches"])
        finally:
            db2.close()
        # Reopen again for tearDown consistency.
        self.db = open_db(self.path)


class NarrativeFixtureTest(unittest.TestCase):
    root = pathlib.Path(__file__).resolve().parents[1]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def _run_fixture(self, name):
        from cloudroll.cli import run
        db_path = str(pathlib.Path(self.temp.name) / (name + ".sqlite"))
        return run(db_path, self.root / "fixtures" / (name + ".json"))

    def test_revocable_fixture_deploys_then_freezes_and_replays(self):
        out = self._run_fixture("stage_two_late_revocable")
        self.assertTrue(out["audit"]["verified"], out["audit"]["mismatches"])
        state = out["state"]
        self.assertEqual({s["id"]: str(s["status"]) for s in state["stage"]}["s2"], "frozen")
        self.assertEqual(len([r for r in state["receipt"] if r["stage_id"] == "s2"]), 2)
        self.assertTrue(any(o["kind"] == "traffic" for o in state["obligation"]))
        self.assertEqual(out["results"][-1]["result"], "failed:a:unhealthy")

    def test_wait_fixture_never_creates_second_stage(self):
        out = self._run_fixture("stage_two_late_wait")
        self.assertTrue(out["audit"]["verified"], out["audit"]["mismatches"])
        state = out["state"]
        self.assertEqual(len(state["stage"]), 1)
        self.assertEqual(str(state["stage"][0]["status"]), "failed")
        # The rejected second-stage start is the 13th action (index 12).
        self.assertEqual(out["results"][12]["result"], "previous_stage_not_passed")

    def test_copy_normal_sample_and_expand_to_two_stages(self):
        import json
        from cloudroll.cli import run
        src = self.root / "fixtures" / "stage_normal.json"
        payload = json.loads(src.read_text(encoding="utf8"))
        for action in payload["actions"]:
            if action["op"] == "artifact.plan":
                action["args"]["stage_count"] = 2
        fixture_path = pathlib.Path(self.temp.name) / "copied_two_stage.json"
        fixture_path.write_text(json.dumps(payload), encoding="utf8")
        db_path = str(pathlib.Path(self.temp.name) / "copied.sqlite")
        out = run(db_path, fixture_path)
        self.assertEqual(out["results"][-1]["result"], "passed")  # minute-5 pass
        self.assertTrue(out["audit"]["verified"])

        db = open_db(db_path)
        seq = 0

        def do(op, **args):
            nonlocal seq
            seq += 1
            return apply_command(db, op, args, f"continue-{seq}")

        self.assertEqual(do("stage.start", stage_id="s2", plan_id="p1", ordinal=2,
                            members=MEMBERS, start_ts=7, end_ts=9), "started")
        self.assertEqual(do("stage.receipt", receipt_id="q1", stage_id="s2",
                            replica="a", generation=1, digest="newhash"), "recorded")
        self.assertEqual(do("stage.receipt", receipt_id="q2", stage_id="s2",
                            replica="b", generation=1, digest="newhash"), "recorded")
        self.assertEqual(do("stage.sample", sample_id="late-a", stage_id="s1",
                            replica="a", at=6, digest="newhash", healthy=False), "recorded")
        revised = do("stage.decide", stage_id="s1", at=7)
        self.assertTrue(str(revised).startswith("failed"))
        self.assertEqual(str(one(db, "SELECT status FROM stage WHERE id='s2'")["status"]), "frozen")
        result = audit(db)
        self.assertTrue(result["verified"], result["mismatches"])
        db.close()


if __name__ == "__main__":
    unittest.main()

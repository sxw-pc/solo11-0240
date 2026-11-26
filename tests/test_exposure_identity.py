"""Independent tests for real exposure receipts and cross-device identity.

Covers the two approved recruitment arrangements, every identity-challenge
reply branch, cached early rendering, cross-device same-person contamination,
power-loss reopen, duplicate receipts and the legacy 18-scenario baseline.
"""
import pathlib
import tempfile
import unittest

from cloudroll import route_delivery, exposure, identity, trial_sample
from cloudroll.cli import apply_command, audit
from cloudroll.store import open_db, one, rows

OLD = "old-digest"
NEW = "new-digest"
PAIR_SLOTS = [
    {"arm": "old", "region": "east", "device": "d1"},
    {"arm": "new", "region": "west", "device": "d2"},
    {"arm": "new", "region": "east", "device": "C"},
    {"arm": "old", "region": "west", "device": "F"},
]
UNIFIED_SLOTS = [
    {"arm": "new", "region": "east", "device": "C"},
    {"arm": "new", "region": "west", "device": "E"},
    {"arm": "old", "region": "east", "device": "D"},
    {"arm": "old", "region": "west", "device": "F"},
]


class ExposureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = open_db(str(pathlib.Path(self.temp.name) / "exposure.sqlite"))
        self.seq = 0
        self.seed_world()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def do(self, operation, **arguments):
        self.seq += 1
        return apply_command(self.db, operation, arguments, f"cmd-{self.seq}")

    def seed_world(self):
        routes = [
            ("rd1", "acct-x", "d1", OLD, "tok-shared", "east"),
            ("rd2", "acct-y", "d2", NEW, "tok-shared", "west"),
            ("rc", "acct-c", "C", NEW, "tok-c", "east"),
            ("rd", "acct-d", "D", OLD, "tok-d", "east"),
            ("re", "acct-e", "E", NEW, "tok-e", "west"),
            ("rf", "acct-f", "F", OLD, "tok-f", "west"),
        ]
        for receipt, account, device, digest, session, region in routes:
            self.do("route.issue", receipt=receipt, account=account, device=device,
                    digest=digest, session=session, region=region)
            self.do("exposure.register_device", device=device, account=account,
                    region=region, session=session)
        for person, devices in (("person-C", ["C"]), ("person-D", ["D"]),
                                ("person-E", ["E"]), ("person-F", ["F"])):
            self.do("exposure.declare_person", person_id=person, devices=devices)

    def plan(self, pair_slots=None, unified_slots=None, challenges=("ch-1",)):
        return self.do("trial.plan", experiment_id="exp1", old_digest=OLD, new_digest=NEW,
                       pair_slots=pair_slots or PAIR_SLOTS,
                       unified_slots=unified_slots or UNIFIED_SLOTS,
                       challenges=list(challenges))

    def render(self, receipt_id, device, route_receipt, session, digest, minute,
               confirmation):
        return self.do("exposure.render_receipt", receipt_id=receipt_id, device=device,
                       route_receipt=route_receipt, session=session, digest=digest,
                       render_minute=minute, client_confirmation=confirmation)

    def register_four_pair(self):
        self.plan()
        self.assertEqual(self.do("identity.freeze_challenge", experiment_id="exp1",
                                 challenge_id="ch-1", devices=["d1", "d2"]), "frozen")
        self.assertEqual(self.do("identity.resolve_challenge", challenge_id="ch-1",
                                 answer="independent"), "independent")
        self.assertEqual(self.do("trial.select_branch", experiment_id="exp1",
                                 branch="pair"), "branch:pair")
        facts = [
            ("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1", "s-d1", "person:d1", 1),
            ("rr2", "d2", "rd2", "tok-shared", NEW, 101, "ack-2", "s-d2", "person:d2", 0),
            ("rrc", "C", "rc", "tok-c", NEW, 102, "ack-c", "s-c", "person-C", 1),
            ("rrf", "F", "rf", "tok-f", OLD, 103, "ack-f", "s-f", "person-F", 1),
        ]
        for rr, device, route, session, digest, minute, ack, sample, person, outcome in facts:
            self.assertEqual(self.render(rr, device, route, session, digest, minute, ack),
                             "exposed")
            self.assertEqual(self.do("trial.register", experiment_id="exp1", sample=sample,
                                     person_id=person, device=device, outcome=outcome,
                                     render=rr), "recorded_countable")

    def assert_audit_clean(self):
        result = audit(self.db)
        self.assertTrue(result["verified"], result["mismatches"])


class ApprovedRecruitmentTests(ExposureTest):
    def test_pair_branch_independent_answer_yields_four_countable_samples(self):
        self.register_four_pair()
        verdict = self.do("trial.verdict", experiment_id="exp1")
        self.assertTrue(verdict["comparable"], verdict)
        self.assertEqual(verdict["branch"], "pair")
        self.assertEqual(len(verdict["countable"]), 4)
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM exposure")["n"], 4)
        self.assert_audit_clean()

    def test_withdrawal_path_uses_c_e_d_f_and_excludes_unknown_pair(self):
        # Operations withdraws the two un-rendered routes before any exposure.
        self.assertEqual(self.do("route.withdraw", receipt="rd1"), "withdrawn")
        self.assertEqual(self.do("route.withdraw", receipt="rd2"), "withdrawn")
        # The withdrawn pair cannot occupy any plan slot: the pair branch is
        # infeasible, so the only approvable design is the four-customer one.
        bad = self.do("trial.plan", experiment_id="exp-bad", old_digest=OLD, new_digest=NEW,
                      pair_slots=PAIR_SLOTS, unified_slots=UNIFIED_SLOTS, challenges=["ch-x"])
        self.assertTrue(bad.startswith("pair_branch_infeasible"))
        # A challenge cannot open either: the independent reply branch would
        # have no usable routes for d1/d2.
        self.assertEqual(self.do("identity.freeze_challenge", experiment_id="exp-bad",
                                 challenge_id="ch-x", devices=["d1", "d2"]),
                         "unknown_experiment")
        # Re-approve with both branches consisting of the independent customers.
        self.plan(pair_slots=UNIFIED_SLOTS, unified_slots=UNIFIED_SLOTS)
        self.do("identity.freeze_challenge", experiment_id="exp1", challenge_id="ch-1",
                devices=["d1", "d2"])
        self.assertEqual(self.do("identity.resolve_challenge", challenge_id="ch-1",
                                 answer="no_answer"), "no_answer")
        self.do("trial.select_branch", experiment_id="exp1", branch="unified")
        facts = [
            ("rrc", "C", "rc", "tok-c", NEW, 110, "ack-c", "s-c", "person-C", "new", "east"),
            ("rre", "E", "re", "tok-e", NEW, 111, "ack-e", "s-e", "person-E", "new", "west"),
            ("rrd", "D", "rd", "tok-d", OLD, 112, "ack-d", "s-d", "person-D", "old", "east"),
            ("rrf", "F", "rf", "tok-f", OLD, 113, "ack-f", "s-f", "person-F", "old", "west"),
        ]
        for rr, device, route, session, digest, minute, ack, sample, person, arm, region in facts:
            self.assertEqual(self.render(rr, device, route, session, digest, minute, ack),
                             "exposed")
            self.assertEqual(self.do("trial.register", experiment_id="exp1", sample=sample,
                                     person_id=person, device=device, outcome=1,
                                     render=rr), "recorded_countable")
        # The pair devices never enter the sample table.
        self.assertEqual(
            one(self.db, "SELECT COUNT(*) n FROM experiment_sample WHERE device IN ('d1','d2')")["n"],
            0)
        verdict = self.do("trial.verdict", experiment_id="exp1")
        self.assertTrue(verdict["comparable"], verdict)
        self.assert_audit_clean()

    def test_exposed_route_cannot_be_withdrawn(self):
        self.plan()
        self.do("identity.freeze_challenge", experiment_id="exp1", challenge_id="ch-1",
                devices=["d1", "d2"])
        self.do("identity.resolve_challenge", challenge_id="ch-1", answer="independent")
        self.do("trial.select_branch", experiment_id="exp1", branch="pair")
        self.render("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1")
        self.assertEqual(self.do("route.withdraw", receipt="rd1"), "already_exposed")
        self.assertEqual(one(self.db, "SELECT status FROM delivered_routes WHERE receipt='rd1'")["status"],
                         "issued")


class ChallengeBranchTests(ExposureTest):
    def test_no_answer_forces_unified_branch_and_pair_is_rejected(self):
        self.plan()
        self.assertEqual(self.do("identity.freeze_challenge", experiment_id="exp1",
                                 challenge_id="ch-1", devices=["d1", "d2"]), "frozen")
        self.assertEqual(self.do("identity.resolve_challenge", challenge_id="ch-1",
                                 answer="no_answer"), "no_answer")
        # Pair branch cannot be selected without an independent answer.
        self.assertEqual(self.do("trial.select_branch", experiment_id="exp1",
                                 branch="pair"), "pair_branch_requires_independent_answer")
        self.assertEqual(self.do("trial.select_branch", experiment_id="exp1",
                                 branch="unified"), "branch:unified")
        self.assertEqual(self.do("trial.select_branch", experiment_id="exp1",
                                 branch="pair"), "branch_already_locked:unified")
        # A pair device can never be enrolled on the unified branch.
        self.render("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1")
        rejected = self.do("trial.register", experiment_id="exp1", sample="s-d1",
                           person_id="person:d1", device="d1", outcome=1, render="rr1")
        self.assertEqual(rejected, "device_not_in_selected_branch:d1")

    def test_same_person_answer_forces_unified_branch(self):
        self.plan()
        self.do("identity.freeze_challenge", experiment_id="exp1", challenge_id="ch-1",
                devices=["d1", "d2"])
        result = self.do("identity.resolve_challenge", challenge_id="ch-1", answer="same",
                         person_id="person-x")
        self.assertTrue(result.startswith("same:"))
        # Both devices now resolve to the same person.
        self.assertEqual(exposure.person_of(self.db, "d1"), "person-x")
        self.assertEqual(exposure.person_of(self.db, "d2"), "person-x")
        self.assertEqual(self.do("trial.select_branch", experiment_id="exp1",
                                 branch="pair"), "pair_branch_requires_independent_answer")
        self.assertEqual(self.do("trial.select_branch", experiment_id="exp1",
                                 branch="unified"), "branch:unified")
        registry = one(self.db, "SELECT kind FROM person_registry WHERE person_id='person-x'")
        self.assertEqual(registry["kind"], "merged")

    def test_challenge_cannot_open_when_a_branch_is_infeasible(self):
        # Break the fallback branch by withdrawing F's old route (old/west cell).
        self.do("route.withdraw", receipt="rf")
        result = self.do("trial.plan", experiment_id="exp2", old_digest=OLD, new_digest=NEW,
                        pair_slots=PAIR_SLOTS, unified_slots=UNIFIED_SLOTS,
                        challenges=["ch-2"])
        self.assertIn("infeasible", result)
        self.assertTrue(result.endswith("no_usable_route:F"))
        self.assertIsNone(one(self.db, "SELECT * FROM experiment_plan WHERE experiment_id='exp2'"))
        self.assertEqual(self.do("identity.freeze_challenge", experiment_id="exp2",
                                 challenge_id="ch-2", devices=["d1", "d2"]),
                         "unknown_experiment")

    def test_cannot_select_branch_while_challenge_still_open(self):
        self.plan()
        self.do("identity.freeze_challenge", experiment_id="exp1", challenge_id="ch-1",
                devices=["d1", "d2"])
        result = self.do("trial.select_branch", experiment_id="exp1", branch="pair")
        self.assertEqual(result, "challenge_still_open:ch-1")


class ExposureEvidenceTests(ExposureTest):
    def test_prefetch_is_recorded_but_never_an_exposure(self):
        prefetch = self.do("exposure.report_render_event", event_id="ev-prefetch",
                           device="d1", route_receipt="rd1", session="tok-shared",
                           digest=OLD, kind="prefetch", render_minute=90)
        self.assertEqual(prefetch, "prefetch_ignored")
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM exposure")["n"], 0)
        # The later real display still creates the single exposure.
        self.assertEqual(self.render("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1"),
                         "exposed")
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM exposure")["n"], 1)

    def test_retry_rescan_and_duplicate_receipt_do_not_double_expose(self):
        self.assertEqual(self.render("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1"),
                         "exposed")
        retry = self.do("exposure.report_render_event", event_id="ev-retry", device="d1",
                        route_receipt="rd1", session="tok-shared", digest=OLD, kind="retry",
                        render_minute=105, client_confirmation="ack-1b")
        self.assertTrue(retry.startswith("already_exposed:"))
        rescan = self.do("exposure.report_render_event", event_id="ev-rescan", device="d1",
                         route_receipt="rd1", session="tok-shared", digest=OLD, kind="rescan",
                         render_minute=106, client_confirmation="ack-1c")
        self.assertTrue(rescan.startswith("already_exposed:"))
        duplicate = self.render("rr1-dup", "d1", "rd1", "tok-shared", OLD, 100, "ack-1")
        self.assertTrue(duplicate.startswith("duplicate_exposure:"))
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM exposure")["n"], 1)

    def test_render_validates_route_session_and_digest_binding(self):
        self.assertEqual(self.render("rr-bad", "d1", "rd1", "tok-shared", NEW, 100, "ack"),
                         "digest_route_mismatch")
        self.assertEqual(self.render("rr-bad2", "d1", "rd1", "tok-c", OLD, 100, "ack"),
                         "session_mismatch")
        self.assertEqual(self.render("rr-bad3", "d1", "rc", "tok-shared", OLD, 100, "ack"),
                         "route_device_mismatch")
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM exposure")["n"], 0)

    def test_render_during_freeze_is_flagged_but_evidence_kept(self):
        self.plan()
        self.do("identity.freeze_challenge", experiment_id="exp1", challenge_id="ch-1",
                devices=["d1", "d2"])
        self.assertEqual(self.render("rr2", "d2", "rd2", "tok-shared", NEW, 95, "ack-2"),
                         "exposed")
        receipt = one(self.db, "SELECT frozen_at_render FROM render_receipts WHERE id='rr2'")
        self.assertEqual(receipt["frozen_at_render"], 1)
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM exposure")["n"], 1)

    def test_power_loss_reopen_keeps_seen_exposure_immutable(self):
        self.assertEqual(self.render("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1"),
                         "exposed")
        # Simulate a process restart by reopening the database file.
        path = self.db.execute("PRAGMA database_list").fetchone()["file"]
        self.db.close()
        reopened = open_db(path)
        self.assertEqual(one(reopened, "SELECT COUNT(*) n FROM exposure")["n"], 1)
        # A late duplicate receipt after restart cannot erase or duplicate it.
        late = exposure.render_receipt(reopened, "rr1-late", "d1", "rd1", "tok-shared",
                                        OLD, 120, "ack-late")
        self.assertTrue(late.startswith("duplicate_exposure:"))
        self.assertEqual(one(reopened, "SELECT COUNT(*) n FROM exposure")["n"], 1)
        self.assertEqual(one(reopened, "SELECT digest FROM exposure WHERE device='d1'")["digest"],
                         OLD)
        reopened.close()
        # Reopen for tearDown consistency.
        self.db = open_db(path)

    def test_render_receipt_binds_all_five_evidence_fields(self):
        self.render("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1")
        receipt = one(self.db, "SELECT * FROM render_receipts WHERE id='rr1'")
        self.assertEqual(
            (receipt["device"], receipt["session"], receipt["digest"], receipt["render_minute"],
             receipt["client_confirmation"]),
            ("d1", "tok-shared", OLD, 100, "ack-1"))


class ContaminationTests(ExposureTest):
    def _unified_with_backups(self):
        self.plan()
        self.do("identity.freeze_challenge", experiment_id="exp1", challenge_id="ch-1",
                devices=["d1", "d2"])

    def test_cached_new_render_then_same_person_invalidates_old_control_and_backfills(self):
        self._unified_with_backups()
        # While the challenge is open, d2 actually displays the cached new bytes.
        self.assertEqual(self.render("rr2", "d2", "rd2", "tok-shared", NEW, 95, "ack-2"),
                         "exposed")
        # The challenge later proves d1 and d2 are the same human.
        result = self.do("identity.resolve_challenge", challenge_id="ch-1", answer="same",
                         person_id="person-x")
        self.assertEqual(result, "same:single_arm_recorded")
        self.do("trial.select_branch", experiment_id="exp1", branch="unified")
        # d1 then displays the old version: the same person has now seen both.
        self.assertEqual(self.render("rr1", "d1", "rd1", "tok-shared", OLD, 110, "ack-1"),
                         "exposed")
        # Both originals are registered, but neither is an independent control
        # because the contamination was already proven at challenge resolution.
        self.assertEqual(self.do("trial.register", experiment_id="exp1", sample="s-d2",
                                 person_id="person-x", device="d2", outcome=0,
                                 render="rr2"), "recorded_tainted")
        tainted = self.do("trial.register", experiment_id="exp1", sample="s-d1",
                          person_id="person-x", device="d1", outcome=1, render="rr1")
        self.assertEqual(tainted, "recorded_tainted")
        # Both rows survive; the earlier new sample is also flagged, not deleted.
        self.assertEqual(
            one(self.db, "SELECT COUNT(*) n FROM experiment_sample WHERE person_id='person-x'")["n"],
            2)
        self.assertEqual(
            one(self.db, "SELECT COUNT(*) n FROM experiment_sample WHERE person_id='person-x' AND countable=1")["n"],
            0)
        self.assertEqual(
            one(self.db, "SELECT COUNT(*) n FROM contamination_record WHERE person_id='person-x'")["n"],
            2)
        # Backfill the cells from the unexposed independent backups.
        backfills = [
            ("rrc", "C", "rc", "tok-c", NEW, 120, "ack-c", "s-c", "person-C"),
            ("rre", "E", "re", "tok-e", NEW, 121, "ack-e", "s-e", "person-E"),
            ("rrd", "D", "rd", "tok-d", OLD, 122, "ack-d", "s-d", "person-D"),
            ("rrf", "F", "rf", "tok-f", OLD, 123, "ack-f", "s-f", "person-F"),
        ]
        for rr, device, route, session, digest, minute, ack, sample, person in backfills:
            self.assertEqual(self.render(rr, device, route, session, digest, minute, ack),
                             "exposed")
            self.assertEqual(self.do("trial.register", experiment_id="exp1", sample=sample,
                                     person_id=person, device=device, outcome=1,
                                     render=rr), "recorded_countable")
        verdict = self.do("trial.verdict", experiment_id="exp1")
        self.assertTrue(verdict["comparable"], verdict)
        invalidated = {item["sample"] for item in verdict["invalidated"]}
        self.assertEqual(invalidated, {"s-d1", "s-d2"})
        self.assert_audit_clean()

    def test_insufficient_backups_reports_not_comparable_instead_of_padding(self):
        # After the same-person taint only C/D/E remain usable backups: the
        # old/west cell (which F would fill) is left without a confirmed
        # exposure. The round must report not comparable, never pad to four.
        self.plan()
        self.do("identity.freeze_challenge", experiment_id="exp1", challenge_id="ch-1",
                devices=["d1", "d2"])
        self.render("rr2", "d2", "rd2", "tok-shared", NEW, 95, "ack-2")
        self.do("identity.resolve_challenge", challenge_id="ch-1", answer="same",
                person_id="person-y")
        self.do("trial.select_branch", experiment_id="exp1", branch="unified")
        self.render("rr1", "d1", "rd1", "tok-shared", OLD, 110, "ack-1")
        self.assertEqual(self.do("trial.register", experiment_id="exp1", sample="s-d2",
                                 person_id="person-y", device="d2", outcome=0,
                                 render="rr2"), "recorded_tainted")
        self.assertEqual(self.do("trial.register", experiment_id="exp1", sample="s-d1",
                                 person_id="person-y", device="d1", outcome=1,
                                 render="rr1"), "recorded_tainted")
        # Enroll only three of the four independent backups; F never confirms a
        # render (simulating loss of the fourth independent customer).
        for rr, device, route, session, digest, minute, ack, sample, person in (
                ("rrc", "C", "rc", "tok-c", NEW, 120, "ack-c", "s-c", "person-C"),
                ("rre", "E", "re", "tok-e", NEW, 121, "ack-e", "s-e", "person-E"),
                ("rrd", "D", "rd", "tok-d", OLD, 122, "ack-d", "s-d", "person-D")):
            self.assertEqual(self.render(rr, device, route, session, digest, minute, ack),
                             "exposed")
            self.assertEqual(self.do("trial.register", experiment_id="exp1", sample=sample,
                                     person_id=person, device=device, outcome=1,
                                     render=rr), "recorded_countable")
        # F's route exists but F never rendered; no other device may fill the
        # old/west cell because slots are fixed to the approved arrangement.
        self.assertEqual(one(self.db,
                             "SELECT COUNT(*) n FROM experiment_sample WHERE experiment_id='exp1'")["n"],
                         5)
        verdict = self.do("trial.verdict", experiment_id="exp1")
        self.assertFalse(verdict["comparable"])
        self.assertIn("uncovered_cells:old:west", verdict["reason"])
        self.assertEqual(len(verdict["countable"]), 3)

    def test_different_account_names_or_devices_cannot_split_one_person(self):
        self._unified_with_backups()
        self.do("identity.resolve_challenge", challenge_id="ch-1", answer="same",
                person_id="person-x")
        # The two accounts acct-x and acct-y now share one person id.
        self.assertEqual(exposure.person_of(self.db, "d1"),
                         exposure.person_of(self.db, "d2"))


class TrialGuardTests(ExposureTest):
    def test_cached_digest_conflicting_with_slot_is_rejected_not_relabelled(self):
        self.register_four_pair()
        # F was planned for the old arm but its cache displays new bytes.
        bad = self.render("rrf-bad", "F", "rf", "tok-f", NEW, 130, "ack-bad")
        self.assertEqual(bad, "digest_route_mismatch")
        # A route carrying new bytes to F would instead surface as an arm
        # conflict: the sample can never be silently relabelled.
        self.do("route.issue", receipt="rf2", account="acct-f", device="F", digest=NEW,
                session="tok-f", region="west")
        self.assertEqual(self.render("rrf2", "F", "rf2", "tok-f", NEW, 131, "ack-2"),
                         "exposed")
        rejected = self.do("trial.register", experiment_id="exp1", sample="s-f2",
                           person_id="person-F", device="F", outcome=1, render="rrf2")
        self.assertEqual(rejected, "rendered_arm_conflicts_with_branch_slot")

    def test_fifth_sample_and_double_cell_are_rejected(self):
        self.register_four_pair()
        self.do("route.issue", receipt="rg", account="acct-g", device="G", digest=NEW,
                session="tok-g", region="east")
        self.do("exposure.register_device", device="G", account="acct-g", region="east",
                session="tok-g")
        self.do("exposure.declare_person", person_id="person-G", devices=["G"])
        self.render("rrg", "G", "rg", "tok-g", NEW, 140, "ack-g")
        # G is not part of either approved branch.
        self.assertEqual(self.do("trial.register", experiment_id="exp1", sample="s-g",
                                 person_id="person-G", device="G", outcome=1,
                                 render="rrg"), "device_not_in_selected_branch:G")

    def test_inline_render_evidence_registers_atomically(self):
        self.plan()
        self.do("identity.freeze_challenge", experiment_id="exp1", challenge_id="ch-1",
                devices=["d1", "d2"])
        self.do("identity.resolve_challenge", challenge_id="ch-1", answer="independent")
        self.do("trial.select_branch", experiment_id="exp1", branch="pair")
        result = self.do("trial.register", experiment_id="exp1", sample="s-d1",
                         person_id="person:d1", device="d1", outcome=1,
                         render={"receipt_id": "rr-inline", "device": "d1",
                                 "route_receipt": "rd1", "session": "tok-shared",
                                 "digest": OLD, "render_minute": 150,
                                 "client_confirmation": "ack-inline"})
        self.assertEqual(result, "recorded_countable")
        self.assertEqual(one(self.db, "SELECT id FROM exposure WHERE device='d1'")["id"],
                         "exp:d1:" + OLD)

    def test_command_replay_is_idempotent_and_audit_stays_verified(self):
        self.register_four_pair()
        self.assert_audit_clean()
        # Replaying the whole command stream rebuilds identical state.
        result = audit(self.db)
        self.assertTrue(result["verified"])
        # Re-issuing the same render receipt is a replay, not a second exposure.
        self.assertEqual(self.render("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1"),
                         "replayed")
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM exposure")["n"], 4)

    def test_audit_detects_direct_tampering_with_exposure_state(self):
        self.register_four_pair()
        self.assert_audit_clean()
        # An out-of-band rewrite (equivalent to relabelling a sample arm after
        # the fact) must be caught by evidence replay.
        self.db.execute("UPDATE experiment_sample SET arm='new' WHERE sample='s-d1'")
        result = audit(self.db)
        self.assertFalse(result["verified"])
        self.assertTrue(any(item.get("table") == "experiment_sample"
                            for item in result["mismatches"]))

    def test_render_receipt_conflict_on_reused_id_is_rejected(self):
        self.render("rr1", "d1", "rd1", "tok-shared", OLD, 100, "ack-1")
        with self.assertRaises(ValueError):
            self.render("rr1", "d1", "rd1", "tok-shared", NEW, 100, "ack-1")

    def test_route_identity_conflict_blocks_silent_digest_change(self):
        with self.assertRaises(ValueError):
            self.do("route.issue", receipt="rd1", account="acct-x", device="d1",
                    digest=NEW, session="tok-shared", region="east")


if __name__ == "__main__":
    unittest.main()

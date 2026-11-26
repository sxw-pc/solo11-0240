import contextlib
import copy
import io
import json
import pathlib
import tempfile
import unittest

from cloudroll import external_attest as ea
from cloudroll.cli import apply_command, audit
from cloudroll.privacy_release import (
    InferenceGuard,
    PrivacyPolicy,
    difference_attack,
    prove_interval_context,
    verify_interval_context,
)
from cloudroll.store import open_db, one


class ExternalAttestationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = str(pathlib.Path(self.temp.name) / "attest.sqlite")
        self.db = open_db(self.db_path)
        self.seq = 0

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def do(self, op, **args):
        self.seq += 1
        return apply_command(self.db, op, args, f"request-{self.seq}")

    def seed_two_protocols(self, *, old_count=1, add_proxy=True, revise_old_to=None):
        self.do("artifact.baseline", service="svc", api=3, generation=1)
        self.do("artifact.register", artifact_id="new", digest="newhash", min_api=2, max_api=4)
        self.do("artifact.contract", artifact_id="new", min_protocol=2, max_protocol=2)
        self.do("artifact.population", service="svc", protocol=1, count=old_count)
        self.do("artifact.population", service="svc", protocol=2, count=9)
        rejected = self.do(
            "artifact.plan", event_id="decision-rejected", plan_id="plan-rejected",
            service="svc", artifact_id="new", start_ts=0, end_ts=18)
        if add_proxy:
            self.do("artifact.proxy", commitment_id="P", service="svc", protocol=1, until_ts=20)
        locked = self.do(
            "artifact.plan", event_id="decision-locked", plan_id="plan-locked",
            service="svc", artifact_id="new", start_ts=0, end_ts=18)
        if revise_old_to is not None:
            self.do("artifact.population", service="svc", protocol=1, count=revise_old_to)
        return rejected, locked

    def test_fixed_two_protocol_decisions_replay_and_bind_state_root(self):
        rejected, locked = self.seed_two_protocols()
        self.assertEqual(rejected, "unsupported_active_clients")
        self.assertEqual(locked, "locked")

        result = audit(self.db)
        self.assertTrue(result["verified"], result["mismatches"])
        self.assertTrue(result["state_roots_match"])
        self.assertEqual(result["event_count"], 8)

        cert = ea.issue_audited_certificate(self.db, "aud-fixed", service="svc")
        verification = ea.verify_certificate(cert)
        self.assertTrue(verification, verification.get("errors"))
        verdicts = [d["verdict"] for d in cert["decisions"]]
        self.assertEqual(verdicts, ["unsupported_active_clients", "locked"])
        self.assertTrue(cert["internal_audit"]["audit_verified"])
        self.assertEqual(cert["internal_audit"]["state_root"], result["state_root"])
        self.assertEqual(cert["command_chain"]["root"], ea.command_chain(self.db)[1])

    def test_audited_certificate_has_exact_service_scope_but_tampering_fails(self):
        self.seed_two_protocols()
        cert = ea.issue_audited_certificate(self.db, "aud-service", service="svc")
        text = ea.serialize_certificate(cert).decode("utf-8")

        # Regulated buyer copy has the exact per-protocol values and service.
        self.assertIn('"service": "svc"', text)
        self.assertIn('"protocol": 1', text)
        self.assertIn('"population": 1', text)
        self.assertIn('"population": 9', text)
        self.assertTrue(ea.verify_certificate(cert).valid)

        tampered = copy.deepcopy(cert)
        tampered["decisions"][0]["verdict"] = "locked"
        bad = ea.verify_certificate(tampered)
        self.assertFalse(bad.valid)
        self.assertTrue(any("witness recomputation" in e or "replayed result" in e
                            for e in bad["errors"]), bad["errors"])

    def test_named_buyer_copy_keeps_service_but_not_exact_population(self):
        self.seed_two_protocols()
        buyer = ea.issue_buyer_certificate(self.db, "buyer-svc", service="svc")
        result = ea.verify_certificate(buyer)
        self.assertTrue(result, result.get("errors"))
        text = ea.serialize_certificate(buyer).decode("utf-8")
        self.assertIn('"service": "svc"', text)
        self.assertNotIn('"population": 1', text)
        self.assertNotIn('"population": 9', text)
        self.assertNotIn("commands_for_independent_replay", text)
        self.assertEqual(len(buyer["privacy_proofs"]), 2)

    def test_public_certificate_hides_singleton_but_proofs_verify(self):
        self.seed_two_protocols()
        cert = ea.issue_public_certificate(
            self.db, "pub-fixed", batch_id="release-batch", window_id="coarse-week")
        result = ea.verify_certificate(cert)
        self.assertTrue(result, result.get("errors"))

        text = ea.serialize_certificate(cert).decode("utf-8")
        self.assertNotIn('"population": 1', text)
        self.assertNotIn('"population": 9', text)
        self.assertNotIn('"service": "svc"', text)
        self.assertNotIn('"protocol": 1', text)
        self.assertFalse(cert["claims"]["exact_populations_visible"])

        proofs = cert["decision_proofs"]
        self.assertEqual([p["verdict"] for p in proofs],
                         ["unsupported_active_clients", "locked"])
        locked_proof = proofs[1]
        unsupported_slots = [s for s in locked_proof["slots"] if "coverage_proof" in s]
        self.assertEqual(len(unsupported_slots), 1)
        self.assertTrue(ea.verify_confidential_coverage(
            unsupported_slots[0]["coverage_proof"], 18))

        tampered = copy.deepcopy(cert)
        slot = next(s for p in tampered["decision_proofs"] if p["verdict"] == "locked"
                    for s in p["slots"] if "coverage_proof" in s)
        slot["coverage_proof"]["max_population"] = slot["coverage_proof"]["max_population"] + 1
        self.assertFalse(ea.verify_certificate(tampered).valid)

    def test_range_proof_is_publicly_verifiable_and_tamper_evident(self):
        proof = prove_interval_context(9, 0, 100, context="unit/range")
        self.assertTrue(verify_interval_context(proof))
        bad = copy.deepcopy(proof)
        bad["lo"] = 10
        self.assertFalse(verify_interval_context(bad))

    def test_total_ten_and_new_nine_identifies_old_one(self):
        bounds = difference_attack([
            {"terms": {"old": 1, "new": 1}, "lo": 10, "hi": 10},
            {"terms": {"new": 1}, "lo": 9, "hi": 9},
        ], ["old", "new"])
        self.assertEqual(bounds["old"], (1, 1))
        self.assertEqual(bounds["new"], (9, 9))

        guard = InferenceGuard(PrivacyPolicy(min_possible_values=3))
        first = {
            "release_id": "total", "window": "w18", "visible_scope": "global",
            "visible_grain": "batch",
            "constraints": [{"terms": {"old": 1, "new": 1}, "lo": 10, "hi": 10}],
        }
        decision = guard.evaluate(first)
        self.assertTrue(decision.allowed, decision.reason)
        guard.commit(first, decision)
        second = {
            "release_id": "new-nine", "window": "w18-drilldown",
            "visible_scope": "global", "visible_grain": "batch",
            "constraints": [{"terms": {"new": 1}, "lo": 9, "hi": 9}],
        }
        blocked = guard.evaluate(second)
        self.assertFalse(blocked.allowed)
        self.assertEqual(blocked.reason, "cross_release_exact_population_inference")
        self.assertEqual(blocked.risk["exact"]["old"], [1, 1])

    def test_fine_grained_protocol_and_temporal_unsubscribe_release_is_blocked(self):
        coarse = InferenceGuard(PrivacyPolicy())
        denied = coarse.evaluate({
            "window": "minute-18", "visible_scope": "protocol",
            "visible_grain": "protocol",
            "predicates": [{"cohort": "svc|1", "kind": "positive"}],
        })
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason, "service_granularity_not_authorized")

        policy = PrivacyPolicy(visible_scope="protocol", visible_grain="protocol")
        guard = InferenceGuard(policy)
        first = {
            "release_id": "t18", "window": "minute-18",
            "visible_scope": "protocol", "visible_grain": "protocol",
            "predicates": [{"cohort": "old-protocol", "kind": "positive", "window": "minute-18"}],
        }
        d1 = guard.evaluate(first)
        self.assertTrue(d1.allowed, d1.reason)
        guard.commit(first, d1)
        second = {
            "release_id": "t21", "window": "minute-21",
            "visible_scope": "protocol", "visible_grain": "protocol",
            "predicates": [{"cohort": "old-protocol", "kind": "zero", "window": "minute-21"}],
        }
        d2 = guard.evaluate(second)
        self.assertFalse(d2.allowed)
        self.assertEqual(d2.reason, "cross_time_active_status_transition")

    def test_public_second_window_requires_joint_release(self):
        self.seed_two_protocols(revise_old_to=0)
        first = ea.issue_public_certificate(self.db, "public-w18", window_id="coarse-a")
        self.assertTrue(ea.verify_certificate(first))
        with self.assertRaises(PermissionError) as ctx:
            ea.issue_public_certificate(self.db, "public-w21", window_id="coarse-b")
        self.assertIn("subsequent_public_window_requires_joint_control", str(ctx.exception))

        joint = ea.issue_public_certificate(
            self.db, "public-joint", window_id="coarse-a-b-joint", joint_release=True)
        self.assertTrue(ea.verify_certificate(joint))

    def test_later_population_revision_does_not_rewrite_old_witness(self):
        self.seed_two_protocols(revise_old_to=0)
        history = ea.population_history(self.db, "svc", 1)
        self.assertEqual([r["population"] for r in history], [1, 0])
        self.assertEqual([r["revision_no"] for r in history], [1, 2])

        cert = ea.issue_audited_certificate(self.db, "aud-revision", service="svc")
        lock_decision = next(d for d in cert["decisions"] if d["plan_id"] == "plan-locked")
        old_row = next(p for p in lock_decision["witness"]["populations"] if p["protocol"] == 1)
        self.assertEqual(old_row["population"], 1)
        self.assertEqual(old_row["current_revision"], 1)
        self.assertTrue(old_row["revision_hash"])
        current = one(self.db, "SELECT population FROM clients WHERE service='svc' AND protocol=1")
        self.assertEqual(current["population"], 0)
        self.assertTrue(ea.verify_certificate(cert))
        self.assertTrue(audit(self.db)["verified"])

    def test_zero_population_and_full_proxy_are_two_ways_to_lock(self):
        # Path A: replace the singleton with zero after the rejection.
        self.do("artifact.baseline", service="svc", api=3, generation=1)
        self.do("artifact.register", artifact_id="new", digest="h", min_api=1, max_api=4)
        self.do("artifact.contract", artifact_id="new", min_protocol=2, max_protocol=2)
        self.do("artifact.population", service="svc", protocol=1, count=1)
        self.assertEqual(self.do(
            "artifact.plan", event_id="e1", plan_id="p", service="svc",
            artifact_id="new", start_ts=1, end_ts=18), "unsupported_active_clients")
        self.do("artifact.population", service="svc", protocol=1, count=0)
        self.assertEqual(self.do(
            "artifact.plan", event_id="e2", plan_id="p2", service="svc",
            artifact_id="new", start_ts=1, end_ts=18), "locked")

        # Path B: keep the singleton and add P through minute 20.
        db_b = open_db(":memory:")
        try:
            for op, args in [
                ("artifact.baseline", {"service": "svc", "api": 3, "generation": 1}),
                ("artifact.register", {"artifact_id": "new", "digest": "h", "min_api": 1, "max_api": 4}),
                ("artifact.contract", {"artifact_id": "new", "min_protocol": 2, "max_protocol": 2}),
                ("artifact.population", {"service": "svc", "protocol": 1, "count": 1}),
            ]:
                apply_command(db_b, op, args, op + "-1")
            self.assertEqual(apply_command(db_b, "artifact.plan", {
                "event_id": "e1", "plan_id": "p", "service": "svc",
                "artifact_id": "new", "start_ts": 1, "end_ts": 18}, "plan-1"),
                "unsupported_active_clients")
            apply_command(db_b, "artifact.proxy", {
                "commitment_id": "P", "service": "svc", "protocol": 1, "until_ts": 20}, "proxy-1")
            self.assertEqual(apply_command(db_b, "artifact.plan", {
                "event_id": "e2", "plan_id": "p2", "service": "svc",
                "artifact_id": "new", "start_ts": 1, "end_ts": 18}, "plan-2"),
                "locked")
            self.assertTrue(audit(db_b)["verified"])
        finally:
            db_b.close()

    def test_publish_retry_conflict_revocation_and_reissue_preserve_bytes(self):
        self.seed_two_protocols()
        cert = ea.issue_public_certificate(self.db, "pub-ledger", publish=False)
        first = ea.publish_certificate(self.db, cert, submission_id="network-request-1")
        self.assertTrue(first["published"])
        retry = ea.publish_certificate(self.db, cert, submission_id="network-request-1")
        self.assertTrue(retry["duplicate"])
        self.assertEqual(first["certificate_hash"], retry["certificate_hash"])
        self.assertEqual(ea.get_certificate_bytes(self.db, "pub-ledger"),
                         ea.serialize_certificate(cert))

        contradictory = copy.deepcopy(cert)
        contradictory["subject"]["batch_id"] = "different-batch"
        with self.assertRaises(ValueError):
            ea.publish_certificate(self.db, contradictory, submission_id="network-request-1")

        revocation = ea.revoke_certificate(self.db, "pub-ledger", "published in error")
        self.assertTrue(revocation["revocation_id"])
        row = one(self.db, "SELECT status FROM attestation_certificate WHERE certificate_id='pub-ledger' AND version=1")
        self.assertEqual(row["status"], "revoked")
        # Revocation does not overwrite the original external bytes.
        self.assertEqual(ea.get_certificate_bytes(self.db, "pub-ledger", 1),
                         ea.serialize_certificate(cert))

        replacement = ea.reissue_certificate(self.db, "pub-ledger")
        self.assertEqual(replacement["version"], 2)
        self.assertEqual(replacement["parent_hash"], first["certificate_hash"])
        self.assertTrue(ea.verify_certificate(replacement))
        history = ea.certificate_history(self.db, "pub-ledger")
        self.assertEqual([h["version"] for h in history], [1, 2])
        ledger = ea.external_byte_ledger(self.db, "pub-ledger")
        self.assertIn("revocation", [item["kind"] for item in ledger])
        self.assertTrue(all(item["bytes"] for item in ledger))

    def test_proxy_outage_returns_exact_intersection_and_scoped_revocations(self):
        self.seed_two_protocols()
        aud = ea.issue_audited_certificate(self.db, "aud-outage", service="svc")
        pub = ea.issue_public_certificate(self.db, "pub-outage", window_id="outage-batch")
        self.assertTrue(ea.verify_certificate(aud))
        self.assertTrue(ea.verify_certificate(pub))

        recorded = ea.record_proxy_outage(
            self.db, "outage-1", "svc", 1, 10, 15, commitment_id="P",
            reason="proxy process down")
        affected = recorded["scope"]["affected"]
        self.assertEqual(len(affected), 1)
        item = affected[0]
        self.assertEqual(item["plan_id"], "plan-locked")
        self.assertEqual(item["withdraw_window"], [10, 15])
        self.assertEqual(item["plan_window"], [0, 18])
        cert_ids = {c["certificate_id"] for c in item["certificates"]}
        self.assertEqual(cert_ids, {"aud-outage", "pub-outage"})

        revoked = ea.revoke_for_outage(self.db, "outage-1")
        self.assertEqual(len(revoked["revocations"]), 2)
        for cid in ("aud-outage", "pub-outage"):
            status = one(self.db, "SELECT status FROM attestation_certificate WHERE certificate_id=? AND version=1", (cid,))["status"]
            self.assertEqual(status, "partially_revoked")

        # The historical verdict is not rewritten to erase the original lock.
        plan = one(self.db, "SELECT status FROM plan WHERE id='plan-locked'")
        self.assertEqual(plan["status"], "locked")
        verdict = one(self.db, "SELECT verdict FROM plan_decision_witness WHERE plan_id='plan-locked'")
        self.assertEqual(verdict["verdict"], "locked")

        late = ea.record_proxy_outage(
            self.db, "outage-late", "svc", 1, 19, 22, commitment_id="P")
        self.assertEqual(late["scope"]["affected"], [])

        late_inside = ea.record_proxy_outage(
            self.db, "outage-late-inside", "svc", 1, 17, 19, commitment_id="P")
        self.assertEqual(len(late_inside["scope"]["affected"]), 1)
        self.assertEqual(late_inside["scope"]["affected"][0]["withdraw_window"], [17, 18])

    def test_attestation_issue_is_a_replayable_command(self):
        self.seed_two_protocols()
        cert = self.do("attest.issue", certificate_id="command-public", mode="public",
                       window_id="command-batch")
        self.assertEqual(cert["certificate_id"], "command-public")
        self.assertTrue(ea.verify_certificate(cert).valid)
        replay = audit(self.db)
        self.assertTrue(replay["verified"], replay["mismatches"])

    def test_external_cli_verify_file(self):
        self.seed_two_protocols()
        cert = ea.issue_public_certificate(self.db, "pub-cli", window_id="cli-batch")
        path = pathlib.Path(self.temp.name) / "pub-cli.json"
        digest = ea.write_certificate_file(cert, str(path))
        self.assertEqual(len(digest), 64)
        def run_cli(args):
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = ea.external_cli(args)
            return code, buffer.getvalue()

        code, output = run_cli(["verify", str(path)])
        self.assertEqual(code, 0)
        self.assertIn('"verified": true', output)

        bad_path = pathlib.Path(self.temp.name) / "bad.json"
        bad = copy.deepcopy(cert)
        bad["internal_audit"]["audit_verified"] = False
        ea.write_certificate_file(bad, str(bad_path))
        # The proof body still verifies; audit-status tampering is informational
        # unless a trusted replay/root policy is supplied to the verifier.
        code, _ = run_cli(["verify", str(bad_path)])
        self.assertEqual(code, 2)

        tampered = copy.deepcopy(cert)
        tampered["decision_proofs"][1]["slots"][0]["coverage_proof"]["time_slack"] += 1
        bad_proof_path = pathlib.Path(self.temp.name) / "bad-proof.json"
        ea.write_certificate_file(tampered, str(bad_proof_path))
        code, output = run_cli(["verify", str(bad_proof_path)])
        self.assertEqual(code, 2)
        self.assertIn("invalid confidential coverage proof", output)


if __name__ == "__main__":
    unittest.main()

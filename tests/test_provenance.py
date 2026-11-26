import json
import pathlib
import tempfile
import unittest

from cloudroll import artifact, provenance, signature, stage, transparency
from cloudroll.cli import apply_command, audit, run
from cloudroll.store import one, open_db, rows


SEEDS = {"K1": "11", "K2": "22", "BW": "33", "W1": "44", "W2": "55", "BW2": "66"}

RECIPE = {"toolchain": "gcc-12", "flags": ["-O2"], "command": "make release"}
SNAPSHOT_D = {"sources": ["S@sha256:aaa", "compiler@sha256:bbb"]}
SNAPSHOT_E = {"sources": ["S@sha256:aaa", "compiler@sha256:ccc"]}
D_CONTENT = {"artifact": "D", "bytes": "original"}
E_CONTENT = {"artifact": "E", "bytes": "rebuilt"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry(value):
    return canonical(value)


class ProvenanceHarness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(pathlib.Path(self.temp.name) / "release.sqlite")
        self.db = open_db(self.path)
        self.keys = {name: signature.generate_keypair(seed * 32)
                     for name, seed in SEEDS.items()}
        for key_id in ("K1", "K2", "BW", "BW2"):
            self.assertEqual(
                signature.register_key(self.db, key_id, self.keys[key_id]["public_key"],
                                       "release-authority"),
                "registered")
        for key_id in ("K1", "K2"):
            self.assertEqual(signature.authorize(self.db, key_id, "release-authority",
                                                 not_after=100), "authorized")
        for key_id in ("BW", "BW2"):
            self.assertEqual(signature.authorize(self.db, key_id, "build-witness",
                                                 scope="build.attest", not_after=100),
                             "authorized")
        for witness_id in ("W1", "W2"):
            self.assertEqual(
                transparency.register_witness(self.db, witness_id,
                                              self.keys[witness_id]["public_key"]),
                "registered")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    # -- helpers ---------------------------------------------------------

    def private(self, key_id):
        return self.keys[key_id]["private_key"]

    def sign(self, page_id, key_id, kind, subject, statement, at):
        return signature.make_signature(self.db, page_id, key_id, kind, subject, at,
                                        statement=statement,
                                        private_key=self.private(key_id))

    def build_d(self, build_id="build-d", name="release.bin", content=None,
                builder="old-builder", at=1, snapshot=None, isolated=False,
                rebuilt_from=None, digest=None):
        return provenance.build(
            self.db, build_id, name, builder, at,
            content=content if content is not None else D_CONTENT,
            recipe=RECIPE, snapshot=snapshot or SNAPSHOT_D,
            output_files=[name], isolated=isolated, rebuilt_from=rebuilt_from,
            digest=digest, min_api=2, max_api=4)

    def seal(self, seal_id, build_id, signer, release_at, at=None):
        statement = provenance.seal_statement(provenance.build_record(self.db, build_id),
                                              release_at)
        page_id = "sig:" + seal_id + ":" + signer
        result = self.sign(page_id, signer, "artifact.seal", seal_id, statement, release_at)
        self.assertIn(result["decision"], ("recorded", "already_recorded"))
        return provenance.seal(self.db, seal_id, build_id, [page_id], release_at,
                               at=at if at is not None else release_at)

    def head(self, head_id, log_id, witness, entries, at, anchor=False):
        root = transparency.merkle_root(entries)
        status = transparency.submit_head(self.db, head_id, log_id, witness, len(entries),
                                          root, at, entries=entries,
                                          private_key=self.private( witness))
        if anchor:
            self.assertEqual(transparency.anchor(self.db, head_id), "anchored")
        return status, root

    def release_d(self, seal_id="seal-d", log_id="L", head_id="head-d",
                  release_at=10, log_known=False, entry_value=None, signer="K1"):
        self.build_d()
        if log_known:
            self.assertTrue(entry_value)
            statement = provenance.seal_statement(
                provenance.build_record(self.db, "build-d"), release_at)
            page_id = "sig:" + seal_id + ":" + signer
            self.sign(page_id, signer, "artifact.seal", seal_id, statement, release_at)
            return provenance.seal(self.db, seal_id, "build-d", [page_id], release_at,
                                   log_id=log_id, log_entry=entry_value, log_known=True)
        return self.seal(seal_id, "build-d", signer, release_at)

    def admitted(self, artifact_ref, seal_id=None, plan_id="p1", start=1, end=10):
        artifact.baseline(self.db, "svc", 3, 1)
        artifact.contract(self.db, artifact_ref, 1, 3)
        artifact.population(self.db, "svc", 1, 5)
        return artifact.plan(self.db, "ev:" + plan_id, plan_id, "svc", artifact_ref,
                             start, end, seal_id=seal_id)

    def stage(self, stage_id, plan_id, replicas=("a", "b"), start=2, end=6, members=None):
        members = members or [{"replica": replica, "generation": 1} for replica in replicas]
        return stage.start(self.db, stage_id, plan_id, members, start, end)


class ProvenanceTest(ProvenanceHarness):
    # 1. Bytes, not names, define identity.

    def test_digest_is_recomputed_from_canonical_bytes(self):
        first = self.build_d("d1", "release.bin", {"artifact": "D", "bytes": "original"})
        self.assertEqual(first["decision"], "registered")
        digest = first["digest"]
        self.assertEqual(len(digest), 64)
        self.assertEqual(one(self.db, "SELECT digest FROM artifact WHERE id=?",
                             (digest,))["digest"], digest)

        tampered = self.build_d("d2", "release.bin", {"artifact": "D", "bytes": "original"},
                                digest="0" * 64)
        self.assertEqual(tampered["decision"], "digest_mismatch")
        self.assertNotEqual(tampered["computed"], "0" * 64)

        wrong = self.build_d("d3", "release.bin", {"artifact": "D", "bytes": "tampered"})
        self.assertNotEqual(wrong["digest"], digest)

    def test_same_name_different_bytes_are_two_artifacts(self):
        a = self.build_d("a1", "release.bin", b"alpha-bytes")
        b = self.build_d("a2", "release.bin", b"beta-bytes")
        self.assertNotEqual(a["digest"], b["digest"])
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM artifact")["n"], 2)

    def test_same_bytes_different_names_collapse_to_one_artifact(self):
        a = self.build_d("a1", "release.bin", b"identical-bytes")
        b = self.build_d("a2", "renamed.bin", b"identical-bytes")
        self.assertEqual(a["digest"], b["digest"])
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM artifact")["n"], 1)
        # A name is not an identity; a name shared by two byte streams is
        # ambiguous and must not be silently resolved.
        self.assertIsNotNone(artifact.resolve_artifact(self.db, "release.bin"))
        ambiguous = self.build_d("a3", "release.bin", b"other-bytes")
        self.assertIsNone(artifact.resolve_artifact(self.db, "release.bin"))
        self.assertEqual(ambiguous["decision"], "registered")

    # 2. Signature scope.

    def test_signature_covers_digest_authority_and_release_time(self):
        build = self.build_d()
        statement = provenance.seal_statement(provenance.build_record(self.db, "build-d"), 10)
        self.assertEqual(statement["artifact_digest"], build["digest"])
        self.assertEqual(statement["builder_authority"], "old-builder")
        self.assertEqual(statement["release_at"], 10)
        signed = signature.sign_statement(self.private("K1"), statement)
        self.assertTrue(signature.verify_statement(
            self.keys["K1"]["public_key"], statement, signed))
        for field, value in (("artifact_digest", "e" * 64),
                             ("builder_authority", "other"),
                             ("release_at", 11)):
            changed = dict(statement)
            changed[field] = value
            self.assertFalse(signature.verify_statement(
                self.keys["K1"]["public_key"], changed, signed), field)

    def test_seal_rejects_signature_over_a_different_statement(self):
        build = self.build_d()
        statement = provenance.seal_statement(provenance.build_record(self.db, "build-d"), 10)
        other = dict(statement)
        other["release_at"] = 20
        self.sign("sig-wrong", "K1", "artifact.seal", "seal-wrong", other, 10)
        result = provenance.seal(self.db, "seal-wrong", "build-d", ["sig-wrong"], 10)
        self.assertEqual(result["decision"], "statement_mismatch")

    # 3. Witnesses are independent.

    def test_witness_cannot_sign_for_another_witness(self):
        entries = [entry({"kind": "release", "digest": "d"})]
        root = transparency.merkle_root(entries)
        forged = transparency.submit_head(
            self.db, "forged", "L", "W2", 1, root, 5, entries=entries,
            private_key=self.private("W1"))
        self.assertEqual(forged, "invalid_witness_signature")
        self.assertIsNone(one(self.db, "SELECT * FROM tree_head WHERE id='forged'"))
        honest = transparency.submit_head(
            self.db, "honest", "L", "W2", 1, root, 5, entries=entries,
            private_key=self.private("W2"))
        self.assertIn(honest, ("recorded", "forked"))

    # 4. Forked heads are both preserved; neither wins by arrival order.

    def test_two_forked_heads_are_kept_and_never_anchored_by_order(self):
        authorized = [entry({"kind": "key.authorization", "key_id": "K1", "at": 0}),
                      entry({"kind": "release", "digest": "D"})]
        revoked = [entry({"kind": "key.revocation", "key_id": "K1", "at": 5}),
                   entry({"kind": "release", "digest": "D"})]
        first_status, first_root = self.head("page-a", "L", "W1", authorized, 10)
        self.assertEqual(first_status, "recorded")
        second_status, second_root = self.head("page-b", "L", "W2", revoked, 10)
        self.assertEqual(second_status, "forked")
        self.assertNotEqual(first_root, second_root)
        stored = {row["id"]: row for row in rows(self.db, "SELECT * FROM tree_head")}
        self.assertEqual(stored["page-a"]["root"], first_root)
        self.assertEqual(stored["page-b"]["root"], second_root)
        self.assertEqual(json.loads(stored["page-a"]["statement"])["entries"], authorized)
        self.assertEqual(json.loads(stored["page-b"]["statement"])["entries"], revoked)
        # No page may be anchored by arrival order while the fork is open.
        self.assertEqual(transparency.anchor(self.db, "page-a"), "fork_detected")
        self.assertEqual(transparency.anchor(self.db, "page-b"), "fork_detected")
        self.assertEqual(transparency.log_status(self.db, "L"), "forked")
        self.assertEqual(transparency.trusted_entries(self.db, "L"), set())
        # The revocation page is still seen: K1 may not be treated as clean.
        self.assertTrue(transparency.key_contested(self.db, "K1", 10))

    def test_consistency_proof_is_required_to_promote_a_head(self):
        entries = ["a", "b", "c"]
        self.head("genesis", "L", "W1", entries[:1], 1, anchor=True)
        self.head("next", "L", "W1", entries, 2)
        self.assertNotEqual(transparency.log_status(self.db, "L"), "consistency")
        wrong = transparency.consistency(self.db, "p1", "L", "genesis", "next",
                                         ["00" * 32], 2)
        self.assertEqual(wrong, "inconsistent")
        self.assertFalse(one(self.db, "SELECT trusted FROM tree_head WHERE id='next'")["trusted"])
        good = transparency.consistency(self.db, "p2", "L", "genesis", "next",
                                        transparency.consistency_path(1, entries), 2)
        self.assertEqual(good, "consistent")
        self.assertTrue(one(self.db, "SELECT trusted FROM tree_head WHERE id='next'")["trusted"])
        self.assertEqual(transparency.trusted_entries(self.db, "L"), set(entries))

    # 5. Seals, plans, receipts.

    def test_plan_requires_a_trusted_seal_and_receipt_names_seal_and_digest(self):
        self.build_d()
        digest = one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"]
        # No seal at all: a provenance artifact cannot be planned.
        self.assertEqual(self.admitted(digest, plan_id="no-seal"), "provenance_seal_required")
        result = self.seal("seal-d", "build-d", "K1", 10)
        self.assertEqual(result["decision"], "sealed")
        self.assertEqual(self.admitted(digest, plan_id="p1"), "locked")
        plan = one(self.db, "SELECT * FROM plan WHERE id='p1'")
        self.assertEqual(plan["seal_id"], "seal-d")
        self.assertEqual(plan["sealed_digest"], digest)
        self.assertEqual(self.stage("s1", "p1"), "started")
        self.assertEqual(stage.receipt(self.db, "r1", "s1", "a", 1, digest, seal_id="other"),
                         "wrong_seal")
        self.assertEqual(stage.receipt(self.db, "r2", "s1", "a", 1, "f" * 64, seal_id="seal-d"),
                         "wrong_identity_or_digest")
        self.assertEqual(stage.receipt(self.db, "r3", "s1", "a", 1, digest, seal_id="seal-d"),
                         "recorded")
        recorded = one(self.db, "SELECT * FROM receipt WHERE id='r3'")
        self.assertEqual(recorded["seal_id"], "seal-d")
        self.assertEqual(recorded["digest"], digest)

    def test_old_replica_reporting_d_is_not_relabelled_as_e(self):
        self.release_d()
        d_digest = one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"]
        self.assertEqual(self.admitted(d_digest, plan_id="p-d"), "locked")
        self.assertEqual(self.stage("s-d", "p-d", replicas=("a",)), "started")
        self.assertEqual(stage.receipt(self.db, "r-d", "s-d", "a", 1, d_digest,
                                       seal_id="seal-d"), "recorded")

        e = self.build_d("build-e", "release.bin", E_CONTENT, builder="isolated-builder",
                         at=12, snapshot=SNAPSHOT_E, isolated=True, rebuilt_from="build-d")
        self.assertEqual(e["decision"], "registered")
        self.assertNotEqual(e["digest"], d_digest)
        self.seal("seal-e", "build-e", "K2", 14)
        self.assertEqual(self.admitted(e["digest"], plan_id="p-e", start=20, end=30), "locked")
        # The old plan is not deliverable for E, and no receipt is rewritten.
        self.assertEqual(one(self.db, "SELECT status FROM plan WHERE id='p-d'")["status"],
                         "superseded_rebuild")
        self.assertEqual(stage.receipt(self.db, "r-e", "s-d", "a", 1, e["digest"],
                                       seal_id="seal-e"), "wrong_identity_or_digest")
        reported = one(self.db, "SELECT * FROM receipt WHERE id='r-d'")
        self.assertEqual(reported["digest"], d_digest)
        self.assertEqual(reported["seal_id"], "seal-d")

    # 6. Late revocation keeps evidence and names replicas.

    def test_late_revocation_keeps_seal_and_lists_affected_replicas(self):
        self.release_d()
        d_digest = one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"]
        self.admitted(d_digest, plan_id="p1")
        self.stage("s1", "p1")
        stage.receipt(self.db, "r1", "s1", "a", 1, d_digest, seal_id="seal-d")
        stage.receipt(self.db, "r2", "s1", "b", 1, d_digest, seal_id="seal-d")
        entries = [entry({"kind": "release", "digest": d_digest})]
        self.head("seal-head", "L", "W1", entries, 10, anchor=True)
        late = [entry({"kind": "release", "digest": d_digest}),
                entry({"kind": "key.revocation", "key_id": "K1", "at": 15})]
        self.head("late-head", "L", "W1", late, 16)
        applied = signature.sign_key_revocation(
            self.db, "L", "late-head", "W1", "K1", 15,
            private_key=self.private("W1"),
            path=transparency.consistency_path(1, late), from_head="seal-head",
            proof_id="proof-late", size=2, root=transparency.merkle_root(late), entries=late)
        self.assertEqual(applied["decision"], "applied")
        sealed = provenance.seal_record(self.db, "seal-d")
        self.assertEqual(sealed["status"], "contained")
        self.assertEqual({row["replica"] for row in provenance.containment_report(self.db)},
                         {"a", "b"})
        self.assertEqual(provenance.affected(self.db, "seal-d")["replicas"], ["a", "b"])
        self.assertEqual({row["digest"] for row in rows(self.db, "SELECT * FROM receipt")},
                         {d_digest})
        # A second, newly built plan over D can no longer be released.
        self.assertEqual(self.admitted(d_digest, plan_id="p2", start=20, end=30),
                         "seal_not_open")

    # 7. Signature rescan.

    def test_signature_rescan_flags_a_tampered_page_and_keeps_evidence(self):
        self.release_d()
        d_digest = one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"]
        self.admitted(d_digest, plan_id="p1")
        self.stage("s1", "p1", replicas=("a",))
        stage.receipt(self.db, "r1", "s1", "a", 1, d_digest, seal_id="seal-d")
        self.db.execute("UPDATE signature_page SET signature=? WHERE id='sig:seal-d:K1'",
                        ("00" * 64,))
        report = signature.rescan(self.db)
        self.assertEqual(report["scanned"], 1)
        self.assertEqual(report["problems"][0]["reason"], "signature_no_longer_verifies")
        self.assertEqual(provenance.seal_record(self.db, "seal-d")["status"], "contested")
        self.assertEqual(provenance.affected(self.db, "seal-d")["replicas"], ["a"])
        self.assertEqual(one(self.db, "SELECT digest FROM receipt WHERE id='r1'")["digest"],
                         d_digest)

    # 8. Option A: keep D, independent build witness, K2 cross-signature.

    def test_option_a_keeps_d_and_uses_independent_witness_and_cross_signature(self):
        self.build_d()
        d_digest = one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"]
        authorized = [entry({"kind": "key.authorization", "key_id": "K1", "at": 0}),
                      entry({"kind": "release", "digest": d_digest})]
        revoked = [entry({"kind": "key.revocation", "key_id": "K1", "at": 5}),
                   entry({"kind": "release", "digest": d_digest})]
        self.head("page-a", "L", "W1", authorized, 10)
        self.head("page-b", "L", "W2", revoked, 10)
        result = self.seal("seal-d", "build-d", "K1", 10)
        self.assertEqual(result["decision"], "untrusted")
        self.assertFalse(result["trusted"])
        # K2 alone cannot rescue before the bytes are independently checked.
        second = provenance.seal_statement(provenance.build_record(self.db, "build-d"), 10)
        self.sign("sig-k2-d", "K2", "artifact.seal", "seal-d", second, 10)
        self.assertEqual(provenance.cross_sign(self.db, "seal-d", "sig-k2-d")["decision"],
                         "independent_build_attestation_required")
        # The build witness is independent of both log witnesses.
        attestation = provenance.attestation_statement(
            provenance.build_record(self.db, "build-d"), "BW", 10)
        self.sign("sig-bw-d", "BW", "build.attestation", "build-d", attestation, 10)
        self.assertEqual(provenance.attest(self.db, "att-d", "build-d", "BW", "sig-bw-d",
                                           10, log_id="L")["decision"], "attested")
        self.assertEqual(provenance.cross_sign(self.db, "seal-d", "sig-k2-d")["decision"],
                         "sealed")
        sealed = provenance.seal_record(self.db, "seal-d")
        self.assertEqual(sealed["digest"], d_digest)
        self.assertTrue(sealed["trusted"])
        # The original plan may now deliver the original bytes.
        self.assertEqual(self.admitted(d_digest, plan_id="p-a"), "locked")
        self.assertEqual(self.stage("s-a", "p-a"), "started")
        self.assertEqual(stage.receipt(self.db, "r-a", "s-a", "a", 1, d_digest,
                                       seal_id="seal-d"), "recorded")
        self.assertEqual({row["digest"] for row in rows(self.db, "SELECT * FROM receipt")},
                         {d_digest})

    # 9. Option B: rebuild E, clean replicas that tried D, then deploy E.

    def test_option_b_rebuilds_e_cleans_d_replicas_and_deploys_e(self):
        self.release_d()
        d_digest = one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"]
        self.admitted(d_digest, plan_id="p-d")
        self.stage("s-d", "p-d", replicas=("a",))
        stage.receipt(self.db, "r-d", "s-d", "a", 1, d_digest, seal_id="seal-d")
        # A rebuild needs the same recipe, an isolated machine and an
        # independent snapshot.
        self.assertEqual(self.build_d("bad-e", "release.bin", E_CONTENT,
                                      builder="isolated-builder", at=12,
                                      snapshot=SNAPSHOT_D, isolated=True,
                                      rebuilt_from="build-d")["decision"],
                         "snapshot_not_independent")
        self.assertEqual(self.build_d("bad-e2", "release.bin", E_CONTENT,
                                      builder="isolated-builder", at=12,
                                      snapshot=SNAPSHOT_E, isolated=False,
                                      rebuilt_from="build-d")["decision"],
                         "rebuild_not_isolated")
        e = self.build_d("build-e", "release.bin", E_CONTENT, builder="isolated-builder",
                         at=12, snapshot=SNAPSHOT_E, isolated=True, rebuilt_from="build-d")
        self.assertEqual(e["decision"], "registered")
        e_digest = e["digest"]
        # K2 signs E and a fresh log history is anchored, then advanced by a
        # consistency proof that contains E's release entry.
        release_e = dict(kind="release", digest=e_digest)
        self.head("e1", "L2", "W2", [entry(release_e)], 14, anchor=True)
        later = [entry(release_e), entry({"kind": "key.authorization", "key_id": "K2", "at": 0})]
        self.head("e2", "L2", "W2", later, 15)
        self.assertEqual(transparency.consistency(self.db, "proof-e", "L2", "e1", "e2",
                                                  transparency.consistency_path(1, later), 15),
                         "consistent")
        statement = provenance.seal_statement(provenance.build_record(self.db, "build-e"), 14)
        self.sign("sig-k2-e", "K2", "artifact.seal", "seal-e", statement, 14)
        sealed = provenance.seal(self.db, "seal-e", "build-e", ["sig-k2-e"], 14,
                                 log_id="L2", log_entry=entry(release_e), log_known=True)
        self.assertEqual(sealed["decision"], "sealed")
        self.assertEqual(self.admitted(e_digest, plan_id="p-e", start=20, end=30), "locked")
        self.assertEqual(one(self.db, "SELECT status FROM plan WHERE id='p-d'")["status"],
                         "superseded_rebuild")
        # The replica that tried D must be cleaned first; a replica that never
        # reported D is not invented into the cleanup list.
        blocked = self.stage("s-e", "p-e", start=21, end=26)
        self.assertEqual(blocked, "replica_cleanup_required:a")
        self.assertEqual(provenance.pending_cleanup(self.db, d_digest, ["a", "b"]), ["a"])
        self.assertEqual(provenance.clean(self.db, "a", d_digest, 29, "removed D")["decision"],
                         "cleaned")
        self.assertEqual(self.stage("s-e", "p-e", start=21, end=26), "started")
        self.assertEqual(stage.receipt(self.db, "r-e", "s-e", "a", 1, e_digest,
                                       seal_id="seal-e"), "recorded")
        self.assertEqual(stage.receipt(self.db, "r-e2", "s-e", "b", 1, d_digest,
                                       seal_id="seal-d"), "wrong_identity_or_digest")
        self.assertEqual({row["digest"] for row in rows(self.db, "SELECT * FROM receipt")},
                         {d_digest, e_digest})
        # The D receipt is still intact; nothing was relabelled.
        self.assertEqual(one(self.db, "SELECT seal_id FROM receipt WHERE id='r-d'")["seal_id"],
                         "seal-d")

    # 10. Contamination of D's builder only touches option A.

    def test_contaminated_d_build_withdraws_d_seal_without_implicating_e(self):
        self.release_d()
        d_digest = one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"]
        self.assertEqual(self.admitted(d_digest, plan_id="p-d"), "locked")
        self.assertEqual(self.stage("s-d", "p-d", replicas=("a",)), "started")
        stage.receipt(self.db, "r-d", "s-d", "a", 1, d_digest, seal_id="seal-d")
        e = self.build_d("build-e", "release.bin", E_CONTENT, builder="isolated-builder",
                         at=12, snapshot=SNAPSHOT_E, isolated=True, rebuilt_from="build-d")
        self.seal("seal-e", "build-e", "K2", 14)
        self.assertEqual(self.admitted(e["digest"], plan_id="p-e", start=20, end=30), "locked")
        result = provenance.quarantine_build(self.db, "build-d", 40, "machine compromised",
                                             machine=True)
        self.assertEqual(result["decision"], "quarantined")
        self.assertIn("seal-d", result["seals"])
        self.assertIn("a", result["replicas"])
        self.assertEqual(provenance.seal_record(self.db, "seal-d")["status"], "withdrawn")
        # Option B is not wrongly implicated by D's contamination.
        self.assertEqual(provenance.seal_record(self.db, "seal-e")["status"], "published")
        self.assertTrue(provenance.seal_record(self.db, "seal-e")["trusted"])
        self.assertEqual(one(self.db, "SELECT status FROM plan WHERE id='p-e'")["status"],
                         "locked")

    # 10b. A conflicting witness page after deployment names exact replicas.

    def test_conflicting_witness_page_after_deployment_names_exact_replicas(self):
        self.build_d()
        d_digest = one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"]
        release = entry({"kind": "release", "digest": d_digest})
        self.head("genesis", "L", "W1", [release], 9, anchor=True)
        statement = provenance.seal_statement(provenance.build_record(self.db, "build-d"), 10)
        self.sign("sig-seal-d", "K1", "artifact.seal", "seal-d", statement, 10)
        sealed = provenance.seal(self.db, "seal-d", "build-d", ["sig-seal-d"], 10,
                                 log_id="L", log_entry=release, log_known=True)
        self.assertEqual(sealed["decision"], "sealed")
        self.assertEqual(self.admitted(d_digest, plan_id="p1"), "locked")
        self.assertEqual(self.stage("s1", "p1"), "started")
        for replica in ("a", "b"):
            self.assertEqual(stage.receipt(self.db, "r-" + replica, "s1", replica, 1, d_digest,
                                           seal_id="seal-d"), "recorded")
        # A witness page for the same size but a different root arrives and
        # denies the release entry.  It is kept verbatim; the affected
        # replicas are computed exactly.
        conflicting = [entry({"kind": "other", "digest": d_digest})]
        status = transparency.submit_head(
            self.db, "conflict-page", "L", "W2", 1,
            transparency.merkle_root(conflicting), 11, entries=conflicting,
            private_key=self.private("W2"))
        self.assertEqual(status, "forked")
        stored = one(self.db, "SELECT * FROM tree_head WHERE id='conflict-page'")
        self.assertIsNotNone(stored)
        affected = provenance.affected(self.db, "seal-d")
        self.assertEqual(affected["replicas"], ["a", "b"])
        self.assertEqual(provenance.seal_record(self.db, "seal-d")["status"], "contested")
        self.assertEqual({row["digest"] for row in rows(self.db, "SELECT * FROM receipt")},
                         {d_digest})
        # A plan for a different byte stream is untouched.
        e = self.build_d("build-e", "release.bin", E_CONTENT, builder="isolated-builder",
                         at=12, snapshot=SNAPSHOT_E, isolated=True, rebuilt_from="build-d")
        self.seal("seal-e", "build-e", "K2", 14)
        self.assertEqual(provenance.seal_record(self.db, "seal-e")["status"], "issued")

    # 12. Idempotent replay and identity conflicts.

    def test_replaying_the_same_command_is_idempotent_but_changed_input_conflicts(self):
        self.build_d()
        args = {"build_id": "build-d", "name": "release.bin", "builder": "old-builder",
                "at": 1, "content": D_CONTENT, "recipe": RECIPE,
                "snapshot": SNAPSHOT_D, "output_files": ["release.bin"],
                "min_api": 2, "max_api": 4}
        first = apply_command(self.db, "provenance.build", args, "same-request")
        again = apply_command(self.db, "provenance.build", args, "same-request")
        self.assertEqual(first, again)
        self.assertEqual(one(self.db, "SELECT COUNT(*) n FROM build")["n"], 1)
        changed = dict(args, content={"artifact": "D", "bytes": "other"})
        with self.assertRaises(ValueError):
            apply_command(self.db, "provenance.build", changed, "same-request")
        # A second, genuinely different registration under the same id is a
        # conflict, not a silent overwrite.
        conflicting = dict(args, snapshot=SNAPSHOT_E)
        self.assertEqual(apply_command(self.db, "provenance.build", conflicting,
                                       "other-request")["decision"],
                         "build_identity_conflict")

    def test_duplicate_or_mismatched_signature_pages_are_refused(self):
        self.build_d()
        statement = provenance.seal_statement(provenance.build_record(self.db, "build-d"), 10)
        self.sign("sig-k1", "K1", "artifact.seal", "seal-d", statement, 10)
        # Same key signing twice cannot count as two independent signers.
        self.assertEqual(provenance.seal(self.db, "seal-d", "build-d",
                                         ["sig-k1", "sig-k1"], 10)["decision"],
                         "duplicate_signer")
        # A second page under the same id with different content is refused.
        altered = dict(statement, release_at=11)
        result = signature.put_signature(self.db, "sig-k1", "K1", altered,
                                         signature.sign_statement(
                                             self.private("K1"), altered),
                                         "artifact.seal", "seal-d", 10)
        self.assertEqual(result, "signature_identity_conflict")

    def test_attestation_cannot_be_signed_by_a_transparency_witness(self):
        self.release_d()
        attestation = provenance.attestation_statement(
            provenance.build_record(self.db, "build-d"), "W1", 11)
        self.sign("sig-w1-attest", "W1", "build.attestation", "build-d", attestation, 11)
        self.assertEqual(provenance.attest(self.db, "att-w1", "build-d", "W1",
                                           "sig-w1-attest", 11, log_id="L")["decision"],
                         "witness_is_part_of_fork")

    # 11. Offline restart and replay.

    def test_offline_restart_keeps_provenance_and_audit_replays(self):
        # Use a database that was built *only* through logged commands so the
        # audit replay compares like with like.
        self.db.close()
        self.path = str(pathlib.Path(self.temp.name) / "restart.sqlite")
        self.db = open_db(self.path)
        counter = {"n": 0}

        def do(op, **args):
            counter["n"] += 1
            return apply_command(self.db, op, args, "%s:%d" % (op, counter["n"]))

        for key_id in ("K1", "K2", "BW", "W1", "W2"):
            self.assertIn(do("signature.register_key", key_id=key_id,
                             public_key=self.keys[key_id]["public_key"],
                             authority="release-authority"),
                          ("registered", "already_registered"))
        for key_id in ("K1", "K2"):
            do("signature.authorize", key_id=key_id, authority="release-authority",
               not_after=100)
        do("signature.authorize", key_id="BW", authority="build-witness",
           scope="build.attest", not_after=100)
        for witness_id in ("W1", "W2"):
            do("transparency.register_witness", witness_id=witness_id,
               public_key=self.keys[witness_id]["public_key"])
        built = do("provenance.build", build_id="build-d", name="release.bin",
                   builder="old-builder", at=1, content=D_CONTENT, recipe=RECIPE,
                   snapshot=SNAPSHOT_D, output_files=["release.bin"],
                   min_api=2, max_api=4)
        self.assertEqual(built["decision"], "registered")
        d_digest = built["digest"]
        item = provenance.build_record(self.db, "build-d")
        statement = provenance.seal_statement(item, 10)
        do("signature.make_signature", signature_id="sig-seal-d", key_id="K1",
           kind="artifact.seal", subject="seal-d", at=10, statement=statement,
           private_key=self.private("K1"))
        do("provenance.seal", seal_id="seal-d", build_id="build-d",
           signatures=["sig-seal-d"], release_at=10)
        entries = [entry({"kind": "release", "digest": d_digest})]
        do("transparency.submit_head", head_id="head-d", log_id="L", witness="W1",
           size=1, root=transparency.merkle_root(entries), at=10, entries=entries,
           private_key=self.private("W1"))
        do("transparency.anchor", head_id="head-d")
        do("artifact.baseline", service="svc", api=3, generation=1)
        do("artifact.contract", artifact_id=d_digest, min_protocol=1, max_protocol=3)
        do("artifact.population", service="svc", protocol=1, count=5)
        self.assertEqual(do("artifact.plan", event_id="ev-p1", plan_id="p1",
                            service="svc", artifact_id=d_digest,
                            start_ts=1, end_ts=10), "locked")
        self.assertTrue(audit(self.db)["verified"])

        self.db.close()
        self.db = open_db(self.path)
        sealed = provenance.seal_record(self.db, "seal-d")
        self.assertEqual(sealed["digest"], d_digest)
        self.assertTrue(sealed["trusted"])
        self.assertEqual(one(self.db, "SELECT digest FROM build WHERE id='build-d'")["digest"],
                         d_digest)
        self.assertEqual(one(self.db, "SELECT status FROM plan WHERE id='p1'")["status"],
                         "locked")
        self.assertEqual(one(self.db, "SELECT status FROM tree_head WHERE id='head-d'")["status"],
                         "anchored")
        self.assertTrue(audit(self.db)["verified"])


class ProvenanceFixtures(ProvenanceHarness):
    def test_new_fixture_scenarios_replay_cleanly(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        for name in ("provenance_option_a.json", "provenance_option_b.json"):
            with self.subTest(fixture=name):
                output = run(str(pathlib.Path(self.temp.name) / (name + ".sqlite")),
                             root / "fixtures" / name)
                self.assertTrue(output["audit"]["verified"], output["audit"]["mismatches"])
                decisions = [item["result"].get("decision") if isinstance(item["result"], dict)
                             else item["result"] for item in output["results"]]
                self.assertIn("sealed", decisions)
                self.assertIn("locked", decisions)

    def test_original_release_fixtures_still_pass(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        expected = {"artifact_normal": "locked",
                    "artifact_failure": "unsupported_active_clients",
                    "stage_normal": "passed",
                    "stage_failure": "failed:a:health,b",
                    "recovery_normal": "closed",
                    "recovery_failure": "incomplete_compensation"}
        for name, want in expected.items():
            with self.subTest(fixture=name):
                output = run(str(pathlib.Path(self.temp.name) / (name + ".sqlite")),
                             root / "fixtures" / (name + ".json"))
                self.assertEqual(output["results"][-1]["result"], want)
                self.assertTrue(output["audit"]["verified"], output["audit"]["mismatches"])


if __name__ == "__main__":
    unittest.main()

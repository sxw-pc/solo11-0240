"""Regenerate the provenance scenario fixtures.

Run from the repository root::

    python3 fixtures/make_provenance.py

The keys are deterministic on purpose so the checked-in fixtures replay
offline without any secrets.  They are test material only.
"""

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from cloudroll import signature, transparency  # noqa: E402

SEEDS = {"K1": "11", "K2": "22", "BW": "33", "W1": "44", "W2": "55"}
RECIPE = {"toolchain": "gcc-12", "flags": ["-O2"], "command": "make release"}
SNAPSHOT_D = {"sources": ["S@sha256:aaa", "compiler@sha256:bbb"]}
SNAPSHOT_E = {"sources": ["S@sha256:aaa", "compiler@sha256:ccc"]}
D_CONTENT = {"artifact": "D", "bytes": "original"}
E_CONTENT = {"artifact": "E", "bytes": "rebuilt"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def entry(value):
    return canonical(value)


D_DIGEST = digest_of(D_CONTENT)
E_DIGEST = digest_of(E_CONTENT)

KEYS = {name: signature.generate_keypair(seed * 32) for name, seed in SEEDS.items()}


def seal_statement(build_id, name, builder, digest, release_at):
    return {"artifact_digest": digest, "artifact_name": name, "build_id": build_id,
            "builder": builder, "builder_authority": builder,
            "kind": "artifact.seal", "release_at": release_at}


def attestation_statement(build_id, builder, digest, witness, at):
    return {"build_id": build_id, "builder": builder, "builder_authority": builder,
            "digest": digest, "kind": "build.attestation",
            "log_independent": True, "witness": witness, "at": at}


def key_actions():
    actions = []
    for key_id in ("K1", "K2", "BW"):
        actions.append({"op": "signature.register_key",
                        "args": {"key_id": key_id,
                                 "public_key": KEYS[key_id]["public_key"],
                                 "authority": "release-authority"}})
    for key_id in ("K1", "K2"):
        actions.append({"op": "signature.authorize",
                        "args": {"key_id": key_id, "authority": "release-authority",
                                 "not_after": 100}})
    actions.append({"op": "signature.authorize",
                    "args": {"key_id": "BW", "authority": "build-witness",
                             "scope": "build.attest", "not_after": 100}})
    for witness_id in ("W1", "W2"):
        actions.append({"op": "transparency.register_witness",
                        "args": {"witness_id": witness_id,
                                 "public_key": KEYS[witness_id]["public_key"]}})
    return actions


def admission_actions(digest):
    return [
        {"op": "artifact.baseline",
         "args": {"service": "svc", "api": 3, "generation": 1}},
        {"op": "artifact.contract",
         "args": {"artifact_id": digest, "min_protocol": 1, "max_protocol": 3}},
        {"op": "artifact.population",
         "args": {"service": "svc", "protocol": 1, "count": 5}},
    ]


def build_d_actions():
    return [
        {"op": "provenance.build",
         "args": {"build_id": "build-d", "name": "release.bin",
                  "builder": "old-builder", "at": 1, "content": D_CONTENT,
                  "recipe": RECIPE, "snapshot": SNAPSHOT_D,
                  "output_files": ["release.bin"], "min_api": 2, "max_api": 4}},
    ]


def option_a():
    actions = key_actions() + build_d_actions()
    statement = seal_statement("build-d", "release.bin", "old-builder", D_DIGEST, 10)
    actions += [
        {"op": "signature.make_signature",
         "args": {"signature_id": "sig-k1-d", "key_id": "K1", "kind": "artifact.seal",
                  "subject": "seal-d", "at": 10, "statement": statement,
                  "private_key": KEYS["K1"]["private_key"]}},
        {"op": "provenance.seal",
         "args": {"seal_id": "seal-d", "build_id": "build-d",
                  "signatures": ["sig-k1-d"], "release_at": 10}},
        # Two real witnesses hold two real histories at the same size.
        {"op": "transparency.submit_head",
         "args": {"head_id": "page-a", "log_id": "release-log", "witness": "W1",
                  "size": 2,
                  "root": transparency.merkle_root([
                      entry({"kind": "key.authorization", "key_id": "K1", "at": 0}),
                      entry({"kind": "release", "digest": D_DIGEST})]),
                  "at": 10,
                  "entries": [entry({"kind": "key.authorization", "key_id": "K1", "at": 0}),
                              entry({"kind": "release", "digest": D_DIGEST})],
                  "private_key": KEYS["W1"]["private_key"]}},
        {"op": "transparency.submit_head",
         "args": {"head_id": "page-b", "log_id": "release-log", "witness": "W2",
                  "size": 2,
                  "root": transparency.merkle_root([
                      entry({"kind": "key.revocation", "key_id": "K1", "at": 5}),
                      entry({"kind": "release", "digest": D_DIGEST})]),
                  "at": 10,
                  "entries": [entry({"kind": "key.revocation", "key_id": "K1", "at": 5}),
                              entry({"kind": "release", "digest": D_DIGEST})],
                  "private_key": KEYS["W2"]["private_key"]}},
        # The independent offline build witness checks the actual bytes.
        {"op": "signature.make_signature",
         "args": {"signature_id": "sig-bw-d", "key_id": "BW",
                  "kind": "build.attestation", "subject": "build-d", "at": 11,
                  "statement": attestation_statement("build-d", "old-builder", D_DIGEST,
                                                     "BW", 11),
                  "private_key": KEYS["BW"]["private_key"]}},
        {"op": "provenance.attest",
         "args": {"attestation_id": "att-d", "build_id": "build-d", "witness_key": "BW",
                  "signature_id": "sig-bw-d", "at": 11, "log_id": "release-log"}},
        {"op": "signature.make_signature",
         "args": {"signature_id": "sig-k2-d", "key_id": "K2", "kind": "artifact.seal",
                  "subject": "seal-d", "at": 10, "statement": statement,
                  "private_key": KEYS["K2"]["private_key"]}},
        {"op": "provenance.cross_sign",
         "args": {"seal_id": "seal-d", "signature_id": "sig-k2-d"}},
    ]
    actions += admission_actions(D_DIGEST)
    actions += [
        {"op": "artifact.plan",
         "args": {"event_id": "ev-p1", "plan_id": "p1", "service": "svc",
                  "artifact_id": D_DIGEST, "start_ts": 1, "end_ts": 10}},
        {"op": "stage.start",
         "args": {"stage_id": "s1", "plan_id": "p1",
                  "members": [{"replica": "a", "generation": 1},
                              {"replica": "b", "generation": 1}],
                  "start_ts": 2, "end_ts": 6}},
        {"op": "stage.receipt",
         "args": {"receipt_id": "r1", "stage_id": "s1", "replica": "a",
                  "generation": 1, "digest": D_DIGEST, "seal_id": "seal-d"}},
        {"op": "stage.receipt",
         "args": {"receipt_id": "r2", "stage_id": "s1", "replica": "b",
                  "generation": 1, "digest": D_DIGEST, "seal_id": "seal-d"}},
        {"op": "stage.sample",
         "args": {"sample_id": "h1", "stage_id": "s1", "replica": "a", "at": 3,
                  "digest": D_DIGEST, "healthy": True}},
        {"op": "stage.sample",
         "args": {"sample_id": "h2", "stage_id": "s1", "replica": "b", "at": 4,
                  "digest": D_DIGEST, "healthy": True}},
        {"op": "stage.decide", "args": {"stage_id": "s1", "at": 6}},
    ]
    return actions


def option_b():
    actions = key_actions() + build_d_actions()
    statement_d = seal_statement("build-d", "release.bin", "old-builder", D_DIGEST, 10)
    actions += [
        {"op": "signature.make_signature",
         "args": {"signature_id": "sig-k1-d", "key_id": "K1", "kind": "artifact.seal",
                  "subject": "seal-d", "at": 10, "statement": statement_d,
                  "private_key": KEYS["K1"]["private_key"]}},
        {"op": "provenance.seal",
         "args": {"seal_id": "seal-d", "build_id": "build-d",
                  "signatures": ["sig-k1-d"], "release_at": 10}},
    ]
    entries = [entry({"kind": "release", "digest": D_DIGEST})]
    actions += [
        {"op": "transparency.submit_head",
         "args": {"head_id": "head-d", "log_id": "release-log", "witness": "W1",
                  "size": 1, "root": transparency.merkle_root(entries), "at": 10,
                  "entries": entries, "private_key": KEYS["W1"]["private_key"]}},
        {"op": "transparency.anchor", "args": {"head_id": "head-d"}},
    ]
    actions += admission_actions(D_DIGEST)
    actions += [
        {"op": "artifact.plan",
         "args": {"event_id": "ev-p1", "plan_id": "p1", "service": "svc",
                  "artifact_id": D_DIGEST, "start_ts": 1, "end_ts": 10}},
        {"op": "stage.start",
         "args": {"stage_id": "s1", "plan_id": "p1",
                  "members": [{"replica": "a", "generation": 1}],
                  "start_ts": 2, "end_ts": 6}},
        # Replica a tried D before the rebuild decision.
        {"op": "stage.receipt",
         "args": {"receipt_id": "r-d", "stage_id": "s1", "replica": "a",
                  "generation": 1, "digest": D_DIGEST, "seal_id": "seal-d"}},
        {"op": "stage.sample",
         "args": {"sample_id": "h-d", "stage_id": "s1", "replica": "a", "at": 3,
                  "digest": D_DIGEST, "healthy": True}},
        # Isolated rebuild with the same recipe and an independent snapshot.
        {"op": "provenance.build",
         "args": {"build_id": "build-e", "name": "release.bin",
                  "builder": "isolated-builder", "at": 12, "content": E_CONTENT,
                  "recipe": RECIPE, "snapshot": SNAPSHOT_E,
                  "output_files": ["release.bin"], "isolated": True,
                  "rebuilt_from": "build-d", "min_api": 2, "max_api": 4}},
    ]
    statement_e = seal_statement("build-e", "release.bin", "isolated-builder", E_DIGEST, 14)
    actions += [
        {"op": "signature.make_signature",
         "args": {"signature_id": "sig-k2-e", "key_id": "K2", "kind": "artifact.seal",
                  "subject": "seal-e", "at": 14, "statement": statement_e,
                  "private_key": KEYS["K2"]["private_key"]}},
        # K2 signs E only after the new log is anchored and consistent.
        {"op": "provenance.seal",
         "args": {"seal_id": "seal-e", "build_id": "build-e",
                  "signatures": ["sig-k2-e"], "release_at": 14,
                  "log_id": "rebuild-log", "log_entry": entry({"kind": "release",
                                                               "digest": E_DIGEST}),
                  "log_known": True}},
    ]
    entries_e = [entry({"kind": "release", "digest": E_DIGEST})]
    actions.insert(len(actions) - 1, {
        "op": "transparency.submit_head",
        "args": {"head_id": "head-e", "log_id": "rebuild-log", "witness": "W2",
                 "size": 1, "root": transparency.merkle_root(entries_e), "at": 14,
                 "entries": entries_e, "private_key": KEYS["W2"]["private_key"]}})
    actions.insert(len(actions) - 1, {
        "op": "transparency.anchor", "args": {"head_id": "head-e"}})
    actions += admission_actions(E_DIGEST)
    actions += [
        {"op": "artifact.plan",
         "args": {"event_id": "ev-p2", "plan_id": "p2", "service": "svc",
                  "artifact_id": E_DIGEST, "start_ts": 20, "end_ts": 30}},
        # Replica a must be cleaned of D before E can be installed.
        {"op": "provenance.pending_cleanup",
         "args": {"source_digest": D_DIGEST, "replicas": ["a"]}},
        {"op": "stage.start",
         "args": {"stage_id": "s2", "plan_id": "p2",
                  "members": [{"replica": "a", "generation": 1}],
                  "start_ts": 21, "end_ts": 26}},
        {"op": "provenance.clean",
         "args": {"replica": "a", "digest": D_DIGEST, "at": 29,
                  "note": "removed D before E"}},
        {"op": "stage.start",
         "args": {"stage_id": "s2", "plan_id": "p2",
                  "members": [{"replica": "a", "generation": 1}],
                  "start_ts": 21, "end_ts": 26}},
        {"op": "stage.receipt",
         "args": {"receipt_id": "r-e", "stage_id": "s2", "replica": "a",
                  "generation": 1, "digest": E_DIGEST, "seal_id": "seal-e"}},
        {"op": "stage.sample",
         "args": {"sample_id": "h-e", "stage_id": "s2", "replica": "a", "at": 23,
                  "digest": E_DIGEST, "healthy": True}},
        {"op": "stage.decide", "args": {"stage_id": "s2", "at": 26}},
        # Even if D's build machine is later found contaminated, E is separate.
        {"op": "provenance.quarantine_build",
         "args": {"build_id": "build-d", "at": 40, "reason": "build machine compromised",
                  "machine": True}},
    ]
    return actions


def write(name, actions):
    (HERE / name).write_text(
        json.dumps({"actions": actions}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf8")


if __name__ == "__main__":
    write("provenance_option_a.json", option_a())
    write("provenance_option_b.json", option_b())
    print("wrote provenance_option_a.json and provenance_option_b.json")

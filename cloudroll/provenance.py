"""Offline artifact provenance seals.

An artifact is identified by the SHA-256 of its canonical bytes, never by its
file name.  Registering a build recomputes that digest from the bytes; it also
records the build recipe, the input snapshot digest and the names of the
output files.  Two files that share a name but differ in bytes are therefore
two artifacts, while the same bytes under two names collapse into one.

A seal is a signature page over an explicit statement:

    artifact digest, build id, builder authority and release time

and a seal is only trusted when a currently authorized signer signed the
recomputed digest (and, when the seal names a log entry, that entry sits in
the log's reconciled history).  Receipts must name both the seal and the true
digest, so an old replica reporting D can never be relabelled as E by
registering a later E signature.

Nothing here deletes evidence.  Containment records exactly which replicas
must stop receiving a contested seal; cleanup is recorded separately and
leaves historical receipts intact.
"""

from __future__ import annotations

import base64
import json

from . import signature, transparency
from .store import one, rows, tx
from .signature import canonical_json, digest_statement, sha256_hex

SEAL_SCOPE = "artifact.seal"
ATTEST_SCOPE = "build.attest"
MAX_API = 2 ** 31 - 1


# ---------------------------------------------------------------------------
# Canonical artifact bytes and blobs
# ---------------------------------------------------------------------------

def artifact_bytes(content=None, content_b64=None, output=None):
    """Return the canonical byte representation of an artifact.

    Structured content is canonicalised as JSON, so key order does not change
    identity.  Raw strings are encoded as UTF-8; base64 carries binary.
    """
    provided = [item for item in (content, content_b64, output) if item is not None]
    if len(provided) != 1:
        raise ValueError("exactly one of content, content_b64 or output is required")
    value = provided[0]
    if content_b64 is not None:
        if not isinstance(value, str):
            raise ValueError("content_b64 must be a string")
        try:
            return base64.b64decode(value, validate=True)
        except Exception as error:  # noqa: BLE001 - normalised into a ValueError
            raise ValueError("content_b64 is not valid base64") from error
    if isinstance(value, (dict, list)):
        return canonical_json(value)
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ValueError("artifact content must be JSON, text or base64")


def _canonical_field(value, name):
    if value is None:
        return "{}", digest_statement({})
    if isinstance(value, (dict, list)):
        encoded = canonical_json(value).decode("utf-8")
        return encoded, sha256_hex(canonical_json(value))
    if isinstance(value, str):
        return value, sha256_hex(value.encode("utf-8"))
    raise ValueError(name + " must be a JSON object or string")


def store_blob(db, data):
    digest = sha256_hex(data)
    old = one(db, "SELECT * FROM blob WHERE digest=?", (digest,))
    if old:
        if base64.b64decode(old["content"]) != data:
            raise ValueError("blob digest collision")
        return digest
    db.execute("INSERT INTO blob VALUES(?,?,?)",
               (digest, len(data), base64.b64encode(data).decode("ascii")))
    return digest


def blob_bytes(db, digest):
    stored = one(db, "SELECT * FROM blob WHERE digest=?", (digest,))
    return None if not stored else base64.b64decode(stored["content"])


# ---------------------------------------------------------------------------
# Build registration
# ---------------------------------------------------------------------------

def build(db, build_id, name, builder, at, content=None, content_b64=None,
          output=None, digest=None, recipe=None, snapshot=None, output_files=None,
          isolated=False, rebuilt_from=None, min_api=0, max_api=MAX_API,
          builder_authority=None):
    """Register a build and the artifact made from its canonical bytes."""
    with tx(db):
        try:
            data = artifact_bytes(content=content, content_b64=content_b64, output=output)
        except ValueError:
            return {"decision": "invalid_content"}
        computed = sha256_hex(data)
        if digest is not None and digest != computed:
            return {"decision": "digest_mismatch", "computed": computed}
        if isinstance(output_files, str):
            output_files = [output_files]
        if output_files is None:
            output_files = [name]
        if not isinstance(output_files, list) or not all(isinstance(x, str) for x in output_files):
            return {"decision": "invalid_output_files"}
        try:
            recipe_text, recipe_digest = _canonical_field(recipe, "recipe")
            snapshot_text, snapshot_digest = _canonical_field(snapshot, "snapshot")
        except ValueError:
            return {"decision": "invalid_recipe_or_snapshot"}
        if min_api > max_api:
            return {"decision": "invalid_range"}
        authority = builder_authority if builder_authority is not None else builder
        previous = one(db, "SELECT * FROM build WHERE id=?", (build_id,))
        record = (build_id, computed, name, builder, authority, at, recipe_text,
                  recipe_digest, snapshot_text, snapshot_digest, int(bool(isolated)),
                  rebuilt_from, canonical_json(output_files).decode("utf-8"))
        if previous:
            same = (previous["digest"], previous["name"], previous["builder"],
                    previous["builder_authority"], previous["at"], previous["recipe"],
                    previous["recipe_digest"], previous["snapshot"],
                    previous["snapshot_digest"], previous["isolated"],
                    previous["rebuilt_from"], previous["output_files"]) == record[1:]
            if not same:
                return {"decision": "build_identity_conflict"}
            return {"decision": "already_registered", "build": build_id, "digest": computed,
                    "artifact": computed}
        if rebuilt_from is not None:
            source = one(db, "SELECT * FROM build WHERE id=?", (rebuilt_from,))
            if not source:
                return {"decision": "unknown_source_build"}
            if recipe_digest != source["recipe_digest"]:
                return {"decision": "recipe_mismatch"}
            if not isolated:
                return {"decision": "rebuild_not_isolated"}
            if snapshot_digest == source["snapshot_digest"]:
                return {"decision": "snapshot_not_independent"}
        store_blob(db, data)
        existing = one(db, "SELECT * FROM artifact WHERE digest=? AND id<>?", (computed, computed))
        if existing:
            return {"decision": "artifact_digest_conflict", "artifact": existing["id"]}
        artifact_row = one(db, "SELECT * FROM artifact WHERE id=?", (computed,))
        if artifact_row and artifact_row["digest"] != computed:
            return {"decision": "artifact_identity_conflict"}
        if not artifact_row:
            db.execute("INSERT INTO artifact(id,digest,min_api,max_api,provenance_required) "
                       "VALUES(?,?,?,?,1)", (computed, computed, min_api, max_api))
        else:
            db.execute("UPDATE artifact SET provenance_required=1 WHERE id=?", (computed,))
        db.execute("INSERT INTO build(id,digest,name,builder,builder_authority,at,recipe,"
                   "recipe_digest,snapshot,snapshot_digest,isolated,rebuilt_from,output_files) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", record)
        return {"decision": "registered", "build": build_id, "digest": computed,
                "artifact": computed, "recipe_digest": recipe_digest,
                "snapshot_digest": snapshot_digest,
                "output_files": output_files,
                "builder_authority": authority}


def build_record(db, build_id):
    return one(db, "SELECT * FROM build WHERE id=?", (build_id,))


def artifact_for_build(db, build_id):
    return one(db, "SELECT * FROM artifact WHERE id=(SELECT digest FROM build WHERE id=?)",
               (build_id,))


# ---------------------------------------------------------------------------
# Seal statements and signatures
# ---------------------------------------------------------------------------

def seal_statement(build_record, release_at):
    """The exact statement every seal signer must sign.

    It names the recomputed byte digest, the builder identity and authority,
    and the release time; nothing else about the artifact (for example its
    file name) can stand in for those facts.
    """
    return {"artifact_digest": build_record["digest"],
            "artifact_name": build_record["name"],
            "build_id": build_record["id"],
            "builder": build_record["builder"],
            "builder_authority": build_record["builder_authority"] or build_record["builder"],
            "kind": "artifact.seal",
            "release_at": release_at}


def attestation_statement(build_record, witness, at, log_independent=True):
    return {"build_id": build_record["id"],
            "builder": build_record["builder"],
            "builder_authority": build_record["builder_authority"] or build_record["builder"],
            "digest": build_record["digest"],
            "kind": "build.attestation",
            "log_independent": bool(log_independent),
            "witness": witness,
            "at": at}


def _statement_matches(page, expected):
    try:
        stored = json.loads(page["statement"])
    except (TypeError, ValueError):
        return False
    return stored == expected


def _page_ok(db, page_id, kind, expected, scope, at, check_contest=False):
    """Crypto and policy checks for one signature page.

    ``check_contest=False`` lets a signature be *recorded* while its signer is
    disputed by the transparency pages; trust is decided in ``_refresh``.  That
    is what allows K1's original page to be kept verbatim and later rescued by
    a K2 cross-signature.
    """
    page = signature.signature_page(db, page_id)
    if not page or page["kind"] != kind:
        return None, "unknown_signature"
    if not _statement_matches(page, expected):
        return None, "statement_mismatch"
    key = signature.get_key(db, page["key_id"])
    if not key:
        return None, "unknown_key"
    if not signature.verify_statement(key["public_key"], expected, page["signature"]):
        return None, "invalid_signature"
    status = signature.key_status(db, page["key_id"], at)
    if status != "active":
        return None, "signer_" + status
    if scope and not signature.scope_authorized(db, page["key_id"], scope, at):
        return None, "scope_not_authorized"
    if check_contest and transparency.key_contested(db, page["key_id"], at):
        return None, "signer_contested"
    return key, None


# ---------------------------------------------------------------------------
# Seals
# ---------------------------------------------------------------------------

def seal(db, seal_id, build_id, signatures, release_at, log_id=None, log_entry=None,
         at=None, log_known=False):
    """Create a seal from existing, pre-verified signature pages.

    ``log_known=False`` means the caller has no log evidence to offer, so log
    consistency is not part of the provenance test.  Set ``log_known=True``
    (and name ``log_id``/``log_entry``) to require the seal's release entry to
    sit in the reconciled history.
    """
    with tx(db):
        build_record = one(db, "SELECT * FROM build WHERE id=?", (build_id,))
        if not build_record:
            return {"decision": "unknown_build"}
        artifact_row = one(db, "SELECT * FROM artifact WHERE id=?", (build_record["digest"],))
        if not artifact_row:
            return {"decision": "artifact_missing"}
        data = blob_bytes(db, build_record["digest"])
        if data is None or sha256_hex(data) != build_record["digest"]:
            return {"decision": "artifact_bytes_unavailable"}
        if not signatures:
            return {"decision": "signature_required"}
        expected = seal_statement(build_record, release_at)
        previous = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
        if previous:
            same = (previous["digest"], previous["build_id"], previous["release_at"]) == (
                build_record["digest"], build_id, release_at)
            if not same:
                return {"decision": "seal_identity_conflict"}
            return _seal_view(db, seal_id)
        accepted = []
        for page_id in signatures:
            key, problem = _page_ok(db, page_id, "artifact.seal", expected, SEAL_SCOPE,
                                    release_at)
            if problem:
                return {"decision": problem, "signature": page_id}
            if key["id"] in {item["key_id"] for item in accepted}:
                return {"decision": "duplicate_signer"}
            accepted.append({"signature_id": page_id, "key_id": key["id"]})
        db.execute("INSERT INTO seal(id,digest,build_id,artifact_id,name,builder,key_id,"
                   "signature_id,release_at,status,trusted,basis,log_id,log_entry,reason,"
                   "created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (seal_id, build_record["digest"], build_id, build_record["digest"],
                    build_record["name"], build_record["builder"], accepted[0]["key_id"],
                    accepted[0]["signature_id"], release_at, "untrusted", 0, None,
                    log_id if log_known else None, log_entry if log_known else None, None,
                    at if at is not None else release_at))
        for item in accepted:
            db.execute("INSERT INTO seal_signature VALUES(?,?,?,?)",
                       (seal_id, item["signature_id"], item["key_id"], "primary"))
        return _refresh(db, seal_id)


def attach_log(db, seal_id, log_id, log_entry):
    """Attach a log release entry to an existing seal and re-evaluate it."""
    with tx(db):
        record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
        if not record:
            return {"decision": "unknown_seal"}
        if record["log_id"] and (record["log_id"], record["log_entry"]) != (log_id, log_entry):
            return {"decision": "seal_log_conflict"}
        db.execute("UPDATE seal SET log_id=?,log_entry=? WHERE id=?",
                   (log_id, log_entry, seal_id))
        return _refresh(db, seal_id)


def cross_sign(db, seal_id, signature_id):
    """Add a cross-signature (for example K2 over D) to an existing seal.

    A seal held untrusted or contested because its original signer fell under
    a disputed revocation is exactly the case a second, authorized key may
    rescue: that is how option A (keep D, cross-sign with K2) works.  A seal
    that was withdrawn or over a quarantined build stays closed.
    """
    with tx(db):
        record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
        if not record:
            return {"decision": "unknown_seal"}
        if record["status"] in ("withdrawn", "quarantined", "contained"):
            return {"decision": "seal_not_open", "status": record["status"]}
        build_record = one(db, "SELECT * FROM build WHERE id=?", (record["build_id"],))
        if not build_record:
            return {"decision": "unknown_build"}
        expected = seal_statement(build_record, record["release_at"])
        key, problem = _page_ok(db, signature_id, "artifact.seal", expected, SEAL_SCOPE,
                                record["release_at"])
        if problem:
            return {"decision": problem}
        if one(db, "SELECT * FROM witness WHERE id=?", (key["id"],)):
            return {"decision": "witness_cannot_sign_seal"}
        if one(db, "SELECT 1 FROM seal_signature WHERE seal_id=? AND signature_id=?",
               (seal_id, signature_id)):
            return _seal_view(db, seal_id)
        signers = {row["key_id"] for row in rows(
            db, "SELECT key_id FROM seal_signature WHERE seal_id=?", (seal_id,))}
        if key["id"] in signers:
            return {"decision": "duplicate_signer"}
        if not build_record["isolated"] and not independent_attestation(db, record["build_id"]):
            return {"decision": "independent_build_attestation_required"}
        db.execute("INSERT INTO seal_signature VALUES(?,?,?,?)",
                   (seal_id, signature_id, key["id"], "cross"))
        return _refresh(db, seal_id)


def independent_attestation(db, build_id):
    return one(db, "SELECT * FROM build_attestation WHERE build_id=? AND independent=1 "
                   "AND digest=(SELECT digest FROM build WHERE id=?)",
               (build_id, build_id))


def attest(db, attestation_id, build_id, witness_key, signature_id, at,
           log_id=None, log_independent=True):
    """Record an offline build witness checking the artifact bytes.

    The witness must not be one of the transparency witnesses: an attestation
    from a party to the fork cannot break the tie.
    """
    with tx(db):
        build_record = one(db, "SELECT * FROM build WHERE id=?", (build_id,))
        if not build_record:
            return {"decision": "unknown_build"}
        if one(db, "SELECT 1 FROM witness WHERE id=?", (witness_key,)):
            return {"decision": "witness_is_part_of_fork"}
        if log_id is not None:
            for head in rows(db, "SELECT * FROM tree_head WHERE log_id=?", (log_id,)):
                if head["witness"] == witness_key:
                    return {"decision": "witness_is_part_of_fork"}
        key = signature.get_key(db, witness_key)
        if not key:
            return {"decision": "unknown_witness_key"}
        data = blob_bytes(db, build_record["digest"])
        if data is None or sha256_hex(data) != build_record["digest"]:
            return {"decision": "artifact_bytes_unavailable"}
        expected = attestation_statement(build_record, witness_key, at,
                                         log_independent=log_independent)
        page, problem = _page_ok(db, signature_id, "build.attestation", expected,
                                 ATTEST_SCOPE, at)
        if problem:
            return {"decision": problem}
        previous = one(db, "SELECT * FROM build_attestation WHERE id=?", (attestation_id,))
        if previous:
            if previous["signature_id"] != signature_id or previous["build_id"] != build_id:
                return {"decision": "attestation_identity_conflict"}
            return {"decision": "already_recorded", "build": build_id,
                    "digest": build_record["digest"]}
        db.execute("INSERT INTO build_attestation VALUES(?,?,?,?,?,?,?,?)",
                   (attestation_id, build_id, build_record["digest"], witness_key,
                    signature_id, canonical_json(expected).decode("utf-8"), at,
                    int(bool(log_independent))))
        for record in rows(db, "SELECT id FROM seal WHERE build_id=?", (build_id,)):
            _refresh(db, record["id"])
        return {"decision": "attested", "build": build_id, "digest": build_record["digest"],
                "witness": witness_key}


# ---------------------------------------------------------------------------
# Seal evaluation
# ---------------------------------------------------------------------------

def _refresh(db, seal_id):
    record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if not record:
        return {"decision": "unknown_seal"}
    if record["status"] in ("withdrawn", "quarantined", "contained"):
        return _seal_view(db, seal_id)
    build_record = one(db, "SELECT * FROM build WHERE id=?", (record["build_id"],))
    trusted_signers = []
    reasons = []
    for item in rows(db, "SELECT * FROM seal_signature WHERE seal_id=? ORDER BY signature_id",
                     (seal_id,)):
        page = signature.signature_page(db, item["signature_id"])
        key = signature.get_key(db, item["key_id"])
        if not page or not key:
            reasons.append("signer_unknown")
            continue
        if not signature.verify_statement(key["public_key"],
                                          seal_statement(build_record, record["release_at"]),
                                          page["signature"]):
            reasons.append("signer_signature_invalid")
        else:
            ok, reason = signature.authority_at(db, item["key_id"], record["release_at"],
                                                SEAL_SCOPE)
            if ok:
                trusted_signers.append(item["key_id"])
            else:
                reasons.append(reason)
    log_ok = True
    if record["log_id"]:
        log_ok = bool(record["log_entry"]) and transparency.entry_in_trusted_head(
            db, record["log_id"], record["log_entry"])
        if not log_ok:
            reasons.append("log_entry_not_consistent")
    trusted = bool(trusted_signers) and log_ok
    basis = ",".join(sorted(trusted_signers)) if trusted else ",".join(sorted(set(reasons)))
    if trusted:
        # A prior "contested" state can be healed by new evidence (for example
        # a K2 cross-signature over the same bytes); a "contained" or
        # "withdrawn" seal can not.
        referenced = one(db, "SELECT 1 FROM plan WHERE seal_id=? LIMIT 1", (seal_id,))
        next_status = "published" if referenced else "issued"
        db.execute("UPDATE seal SET trusted=1,status=?,basis=?,reason=NULL WHERE id=?",
                   (next_status, basis, seal_id))
        if record["status"] == "contested":
            db.execute("UPDATE containment SET resolved=1 WHERE seal_id=?", (seal_id,))
    else:
        next_status = record["status"] if record["status"] == "contested" else "untrusted"
        db.execute("UPDATE seal SET trusted=0,status=?,basis=? WHERE id=?",
                   (next_status, basis, seal_id))
    return _seal_view(db, seal_id)


def _seal_view(db, seal_id):
    record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if not record:
        return {"decision": "unknown_seal"}
    signers = rows(db, "SELECT key_id,signature_id,role FROM seal_signature WHERE seal_id=? "
                       "ORDER BY signature_id", (seal_id,))
    problems = []
    if not record["trusted"] and record["basis"]:
        problems = record["basis"].split(",")
    return {"decision": "sealed" if record["trusted"] else "untrusted",
            "seal": seal_id, "digest": record["digest"], "build": record["build_id"],
            "status": record["status"], "trusted": bool(record["trusted"]),
            "signers": [item["key_id"] for item in signers],
            "reasons": problems}


def seal_record(db, seal_id):
    return one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))


def refresh_seal(db, seal_id):
    with tx(db):
        return _refresh(db, seal_id)


def mark_seal_contested(db, seal_id, reason="contested"):
    """Keep the seal and its receipts; record which replicas must stop."""
    record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if not record:
        return []
    db.execute("UPDATE seal SET status='contested',trusted=0,reason=? WHERE id=?",
               (reason, seal_id))
    replicas = seal_replicas(db, seal_id)
    for replica in replicas:
        db.execute("INSERT INTO containment VALUES(?,?,?,?,0) ON CONFLICT(seal_id,replica) "
                   "DO UPDATE SET reason=excluded.reason,at=excluded.at,resolved=0",
                   (seal_id, replica, reason, 0))
    return replicas


def unmark_contested(db, seal_id, reason="resolved"):
    """Clear a ``contested`` flag once new evidence restores provenance.

    Only ``contested`` is reversible.  A ``withdrawn``/``contained`` seal is a
    delivery stop and stays that way.  The containment rows are marked
    resolved rather than deleted, so the record of which replicas were halted
    survives.
    """
    record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if not record or record["status"] != "contested":
        return False
    db.execute("UPDATE seal SET status='issued',reason=? WHERE id=?", (reason, seal_id))
    db.execute("UPDATE containment SET resolved=1 WHERE seal_id=?", (seal_id,))
    return True


def seal_replicas(db, seal_id):
    """Exact list of replicas that reported running this seal's bytes."""
    record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if not record:
        return []
    replicas = {row["replica"] for row in rows(
        db, "SELECT replica FROM receipt WHERE seal_id=? AND digest=?", (seal_id, record["digest"]))}
    plans = {row["id"] for row in rows(db, "SELECT id FROM plan WHERE seal_id=?", (seal_id,))}
    for plan_id in plans:
        for row in rows(db, "SELECT r.replica FROM receipt r JOIN stage s ON s.id=r.stage_id "
                            "WHERE s.plan_id=? AND r.digest=?", (plan_id, record["digest"])):
            replicas.add(row["replica"])
    return sorted(replicas)


def containment(db, seal_id, reason="contested", at=0):
    record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if not record:
        return []
    replicas = seal_replicas(db, seal_id)
    for replica in replicas:
        db.execute("INSERT INTO containment VALUES(?,?,?,?,0) ON CONFLICT(seal_id,replica) "
                   "DO UPDATE SET reason=excluded.reason,at=excluded.at,resolved=0",
                   (seal_id, replica, reason, at))
    return replicas


def withdraw(db, seal_id, reason, at=0):
    """Withdraw a seal while keeping it and every receipt on record."""
    with tx(db):
        record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
        if not record:
            return {"decision": "unknown_seal"}
        if record["status"] == "withdrawn" and record["reason"] == reason:
            return {"decision": "already_withdrawn", "seal": seal_id,
                    "replicas": seal_replicas(db, seal_id)}
        db.execute("UPDATE seal SET status='withdrawn',trusted=0,reason=? WHERE id=?",
                   (reason, seal_id))
        replicas = containment(db, seal_id, reason, at)
        return {"decision": "withdrawn", "seal": seal_id, "digest": record["digest"],
                "replicas": replicas}


# ---------------------------------------------------------------------------
# Publication
# ---------------------------------------------------------------------------

def bind_plan(db, seal_id, plan_id):
    """Record that a plan references a seal; the seal stays open for the stage."""
    record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if not record:
        return False
    if record["status"] == "untrusted":
        _refresh(db, seal_id)
        record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if record["status"] == "issued":
        db.execute("UPDATE seal SET status='published' WHERE id=?", (seal_id,))
    return True


def supersede_source_plans(db, build_id):
    """Abandon still-undelivered plans for the build a verified rebuild replaces."""
    build_record = one(db, "SELECT * FROM build WHERE id=?", (build_id,))
    if not build_record:
        return []
    with tx(db):
        return _supersede_source_plans(db, build_record)


def publish(db, seal_id, plan_id=None, at=None):
    """Release a trusted seal, optionally binding it to a locked plan."""
    with tx(db):
        record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
        if not record:
            return {"decision": "unknown_seal"}
        if record["status"] in ("withdrawn", "quarantined", "contained"):
            return {"decision": "seal_not_open", "status": record["status"]}
        refreshed = _refresh(db, seal_id)
        record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
        if record["status"] in ("withdrawn", "quarantined", "contained"):
            return {"decision": "seal_not_open", "status": record["status"]}
        if not refreshed.get("trusted"):
            return {"decision": "seal_not_trusted", "reasons": refreshed.get("reasons", [])}
        build_record = one(db, "SELECT * FROM build WHERE id=?", (record["build_id"],))
        if build_record and build_record["rebuilt_from"]:
            source = one(db, "SELECT * FROM build WHERE id=?", (build_record["rebuilt_from"],))
            if source:
                for plan in rows(db, "SELECT * FROM plan WHERE artifact_id=? AND status='locked'",
                                 (source["digest"],)):
                    db.execute("UPDATE plan SET status='superseded_rebuild' WHERE id=?",
                               (plan["id"],))
                    superseded.append(plan["id"])
        if plan_id is not None:
            plan = one(db, "SELECT * FROM plan WHERE id=?", (plan_id,))
            if not plan:
                return {"decision": "unknown_plan"}
            if plan["status"] != "locked":
                return {"decision": "plan_not_lockable", "status": plan["status"]}
            if plan["artifact_id"] != record["digest"]:
                return {"decision": "plan_artifact_mismatch"}
            if plan["seal_id"] and plan["seal_id"] != seal_id:
                return {"decision": "plan_already_sealed", "seal": plan["seal_id"]}
            if plan["sealed_digest"] and plan["sealed_digest"] != record["digest"]:
                return {"decision": "plan_digest_conflict"}
            db.execute("UPDATE plan SET seal_id=?,sealed_digest=? WHERE id=?",
                       (seal_id, record["digest"], plan_id))
        db.execute("UPDATE seal SET status='published',trusted=1 WHERE id=?", (seal_id,))
        return {"decision": "published", "seal": seal_id, "digest": record["digest"],
                "plan": plan_id, "superseded": superseded}


def _supersede_source_plans(db, build_record):
    superseded = []
    if build_record and build_record["rebuilt_from"]:
        source = one(db, "SELECT * FROM build WHERE id=?", (build_record["rebuilt_from"],))
        if source:
            for plan in rows(db, "SELECT * FROM plan WHERE artifact_id=? AND status='locked'",
                             (source["digest"],)):
                db.execute("UPDATE plan SET status='superseded_rebuild' WHERE id=?",
                           (plan["id"],))
                superseded.append(plan["id"])
    return superseded


# ---------------------------------------------------------------------------
# Build contamination and replica cleanup
# ---------------------------------------------------------------------------

def quarantine_build(db, build_id, at, reason, machine=False):
    """Withdraw seals over a contaminated build.

    With ``machine=True`` every other non-isolated build from the same builder
    is quarantined too.  An isolated rebuild with an independent snapshot has a
    different build id and builder, so it is deliberately left alone: option B
    must not be punished for option A's machine.
    """
    with tx(db):
        record = one(db, "SELECT * FROM build WHERE id=?", (build_id,))
        if not record:
            return {"decision": "unknown_build"}
        affected = [record]
        if machine:
            affected = rows(db, "SELECT * FROM build WHERE builder=? AND isolated=0",
                            (record["builder"],))
        build_ids = []
        for item in affected:
            if not one(db, "SELECT 1 FROM build_quarantine WHERE build_id=?", (item["id"],)):
                db.execute("INSERT INTO build_quarantine VALUES(?,?,?)",
                           (item["id"], at, reason))
            build_ids.append(item["id"])
        seals = []
        replicas = set()
        for item in affected:
            for seal_row in rows(db, "SELECT * FROM seal WHERE build_id=? AND status NOT IN "
                                     "('withdrawn','quarantined')", (item["id"],)):
                before = set(seal_replicas(db, seal_row["id"]))
                db.execute("UPDATE seal SET status='withdrawn',trusted=0,reason=? WHERE id=?",
                           ("build_quarantined:" + item["id"], seal_row["id"]))
                containing = containment(db, seal_row["id"],
                                         "build_quarantined:" + item["id"], at)
                seals.append(seal_row["id"])
                replicas.update(before)
                replicas.update(containing)
        return {"decision": "quarantined", "builds": build_ids, "seals": sorted(set(seals)),
                "replicas": sorted(replicas)}


def clean(db, replica, digest, at, note="", build_id=None):
    """Record that a replica has been cleaned of a previously attempted build."""
    with tx(db):
        evidence = one(db, "SELECT 1 FROM receipt WHERE replica=? AND digest=? LIMIT 1",
                       (replica, digest)) or one(
            db, "SELECT 1 FROM sample WHERE replica=? AND digest=? LIMIT 1", (replica, digest))
        if not evidence:
            return {"decision": "replica_never_reported", "replica": replica,
                    "digest": digest}
        old = one(db, "SELECT * FROM cleanup WHERE replica=? AND digest=?", (replica, digest))
        if old:
            return {"decision": "already_cleaned", "replica": replica, "digest": digest}
        db.execute("INSERT INTO cleanup VALUES(?,?,?,?)", (replica, digest, at, note))
        return {"decision": "cleaned", "replica": replica, "digest": digest}


def cleanup_record(db, replica, digest):
    return one(db, "SELECT * FROM cleanup WHERE replica=? AND digest=?", (replica, digest))


def pending_cleanup(db, source_digest, replicas):
    """Replicas that previously ran ``source_digest`` but have not been cleaned."""
    pending = []
    for replica in replicas:
        before = one(db, "SELECT 1 FROM receipt WHERE replica=? AND digest=? LIMIT 1",
                     (replica, source_digest)) or one(
            db, "SELECT 1 FROM sample WHERE replica=? AND digest=? LIMIT 1",
            (replica, source_digest))
        if before and not cleanup_record(db, replica, source_digest):
            pending.append(replica)
    return sorted(set(pending))


def source_digest_for_plan(db, plan):
    if not plan or not plan.get("seal_id"):
        return None
    record = one(db, "SELECT * FROM seal WHERE id=?", (plan["seal_id"],))
    if not record:
        return None
    build_record = one(db, "SELECT * FROM build WHERE id=?", (record["build_id"],))
    if not build_record or not build_record["rebuilt_from"]:
        return None
    source = one(db, "SELECT * FROM build WHERE id=?", (build_record["rebuilt_from"],))
    return source["digest"] if source else None


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def containment_report(db, seal_id=None, active_only=True):
    clause = " AND resolved=0" if active_only else ""
    if seal_id is None:
        return rows(db, "SELECT * FROM containment" + (" WHERE resolved=0" if active_only else "")
                    + " ORDER BY seal_id,replica")
    return rows(db, "SELECT * FROM containment WHERE seal_id=?" + clause + " ORDER BY replica",
                (seal_id,))


def affected(db, seal_id):
    record = one(db, "SELECT * FROM seal WHERE id=?", (seal_id,))
    if not record:
        return {"decision": "unknown_seal", "replicas": []}
    listed = {row["replica"] for row in containment_report(db, seal_id)}
    if record["status"] in ("contested", "contained", "withdrawn", "quarantined"):
        listed.update(seal_replicas(db, seal_id))
    return {"decision": "affected", "seal": seal_id, "digest": record["digest"],
            "status": record["status"], "replicas": sorted(listed)}

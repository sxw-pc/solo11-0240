"""Offline signature primitives and signature evidence.

The module has no third-party dependencies.  It contains a small, strict
Ed25519 implementation (checked against the RFC 8032 test vectors) plus the
canonical encoding helpers used by the rest of the release control plane.

A signature is always over *bytes*.  Statement pages are canonical JSON
objects and must name the artifact byte digest, the builder authority and the
release time explicitly.  That is what makes a later verification independent
of the human-readable artifact name.
"""

from __future__ import annotations

import hashlib
import json
import secrets

from .store import one, rows, tx

MAX_TIME = 2 ** 63 - 1
DOMAIN = b"cloudroll.statement.v1\n"


# ---------------------------------------------------------------------------
# Canonical encoding
# ---------------------------------------------------------------------------

def canonical_json(value):
    """Return canonical UTF-8 JSON bytes.

    Sorted keys and compact separators make two logically equal statements
    produce exactly the same signed bytes.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_bytes(value):
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    return canonical_json(value)


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(bytes(data)).hexdigest()


def digest_statement(statement):
    """Digest of the canonical statement bytes (no domain separator)."""
    return sha256_hex(canonical_json(statement))


def statement_message(statement):
    """Bytes actually handed to the signature algorithm."""
    return DOMAIN + canonical_json(statement)


def _hex(value, name="value", length=None):
    if not isinstance(value, str):
        raise ValueError(name + " must be hex")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(name + " must be hex") from error
    if length is not None and len(raw) != length:
        raise ValueError(name + " must be " + str(length) + " bytes")
    return raw


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032), pure Python
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x):
    return pow(x, _P - 2, _P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = 4 * _inv(5) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, _BX * _BY % _P)


def _add(first, second):
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * _D * t1 * t2 % _P
    d = 2 * z1 * z2 % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _double(point):
    x1, y1, z1, _ = point
    a = x1 * x1 % _P
    b = y1 * y1 % _P
    c = 2 * z1 * z1 % _P
    d = (-a) % _P
    e = ((x1 + y1) ** 2 - a - b) % _P
    g = (d + b) % _P
    f = (g - c) % _P
    h = (d - b) % _P
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(point, scalar):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _double(point)
        scalar >>= 1
    return result


def _encode(point):
    x, y, z, _ = point
    zi = _inv(z)
    x = x * zi % _P
    y = y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(encoded):
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    sign = encoded[31] >> 7
    if y >= _P:
        return None
    x = _xrecover(y)
    if x & 1 != sign:
        x = _P - x
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _P != 0:
        return None
    return (x, y, 1, x * y % _P)


def public_key_from_private(private_key):
    seed = _hex(private_key, "private_key", 32)
    h = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(h[:32], "little")
    scalar &= (1 << 254) - 1
    scalar |= 1 << 254
    return _encode(_multiply(_B, scalar)).hex()


def generate_keypair(private_key=None):
    seed = secrets.token_bytes(32) if private_key is None else _hex(private_key, "private_key", 32)
    return {"private_key": seed.hex(), "public_key": public_key_from_private(seed.hex())}


def sign(private_key, message):
    """Sign raw bytes and return a hex signature."""
    seed = _hex(private_key, "private_key", 32)
    message = canonical_bytes(message)
    h = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(h[:32], "little")
    scalar &= (1 << 254) - 1
    scalar |= 1 << 254
    prefix = h[32:]
    public = public_key_from_private(seed.hex())
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    encoded_r = _encode(_multiply(_B, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + bytes.fromhex(public) + message).digest(), "little") % _L
    scalar_s = (nonce + challenge * scalar) % _L
    return (encoded_r + scalar_s.to_bytes(32, "little")).hex()


def verify(public_key, message, signature):
    if not isinstance(signature, str):
        return False
    try:
        public = _hex(public_key, "public_key", 32)
        sig = _hex(signature, "signature", 64)
    except ValueError:
        return False
    point = _decode(public)
    encoded_r = sig[:32]
    scalar_s = int.from_bytes(sig[32:], "little")
    if point is None or scalar_s >= _L:
        return False
    r_point = _decode(encoded_r)
    if r_point is None:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public + canonical_bytes(message)).digest(), "little") % _L
    return _encode(_multiply(_B, scalar_s)) == _encode(_add(r_point, _multiply(point, challenge)))


def sign_statement(private_key, statement):
    return sign(private_key, statement_message(statement))


def verify_statement(public_key, statement, signature):
    return verify(public_key, statement_message(statement), signature)


# ---------------------------------------------------------------------------
# Signing keys
# ---------------------------------------------------------------------------

def register_key(db, key_id, public_key, authority, not_before=0, not_after=MAX_TIME,
                 scopes="artifact.seal"):
    with tx(db):
        try:
            _hex(public_key, "public_key", 32)
        except ValueError:
            return "invalid_public_key"
        if not_before > not_after:
            return "invalid_window"
        old = one(db, "SELECT * FROM signing_key WHERE id=?", (key_id,))
        if old:
            if old["public_key"] != public_key:
                return "key_identity_conflict"
            return "already_registered"
        db.execute("INSERT INTO signing_key VALUES(?,?,?,?,?,?,?,?,?)",
                   (key_id, public_key, authority, "active", not_before, not_after,
                    None, None, scopes))
        return "registered"


def authorize(db, key_id, authority, scope="artifact.seal", not_before=0, not_after=MAX_TIME):
    """Record a trusted authorization for a key.

    A key may be registered but not authorized; only an authorization makes it
    usable for a seal.  The authorization is time bounded.
    """
    with tx(db):
        key = one(db, "SELECT * FROM signing_key WHERE id=?", (key_id,))
        if not key:
            return "unknown_key"
        if not_before > not_after:
            return "invalid_window"
        old = one(db, "SELECT * FROM key_authorization WHERE key_id=? AND scope=?",
                  (key_id, scope))
        if old:
            if (old["authority"], old["not_before"], old["not_after"]) == (
                    authority, not_before, not_after):
                return "already_authorized"
            return "authorization_conflict"
        db.execute("INSERT INTO key_authorization VALUES(?,?,?,?,?)",
                   (key_id, authority, scope, not_before, not_after))
        return "authorized"


def get_key(db, key_id):
    return one(db, "SELECT * FROM signing_key WHERE id=?", (key_id,))


def key_status(db, key_id, at):
    """Status of a key for a signature made at ``at``."""
    key = get_key(db, key_id)
    if not key:
        return "unknown_key"
    if at < key["not_before"]:
        return "not_yet_valid"
    if at >= key["not_after"]:
        return "expired"
    if key["status"] == "revoked" and key["revoked_at"] is not None and at >= key["revoked_at"]:
        return "revoked"
    return "active"


def authority_at(db, key_id, at, scope=None):
    """Combined authority check used before any seal or attestation counts.

    Returns ``(ok, reason)``.  A key must be in its validity window, have the
    required scope authorized at ``at``, and must not be contradicted by the
    stored transparency pages.  This is the single place where "authorized at
    release time" is decided.
    """
    key = get_key(db, key_id)
    if not key:
        return False, "unknown_key"
    status = key_status(db, key_id, at)
    if status != "active":
        return False, "signer_" + status
    if scope and not scope_authorized(db, key_id, scope, at):
        return False, "scope_not_authorized"
    from . import transparency
    if transparency.key_contested(db, key_id, at):
        return False, "signer_contested"
    return True, "ok"




def scope_authorized(db, key_id, scope, at):
    auth = one(db, "SELECT * FROM key_authorization WHERE key_id=? AND scope=?", (key_id, scope))
    if not auth:
        return False
    return auth["not_before"] <= at <= auth["not_after"]


def revoke_key(db, key_id, at, reason="", head_id=None):
    """Revoke a key.

    ``head_id`` optionally ties the revocation evidence to a transparency head.
    If that head has not been accepted, the revocation is refused: a page that
    merely arrived first must not revoke a key in the other real history.

    Existing seals are never deleted.  Seals released before ``at`` stay
    readable and their receipts stay intact; they are marked for a delivery
    stop instead.  Seals released at or after ``at`` were signed by a key that
    was no longer authorized and are withdrawn.
    """
    from . import provenance

    with tx(db):
        key = get_key(db, key_id)
        if not key:
            return "unknown_key"
        if head_id is not None:
            head = one(db, "SELECT * FROM tree_head WHERE id=?", (head_id,))
            if not head:
                return "unknown_head"
            if not head["trusted"]:
                return "head_not_accepted"
        old = one(db, "SELECT * FROM key_revocation WHERE key_id=?", (key_id,))
        if old:
            if old["at"] == at and (old["head_id"] or "") == (head_id or ""):
                return "already_revoked"
            if at >= old["at"]:
                return "stale_revocation"
            return "revocation_conflict"
        if at < key["not_before"]:
            return "revocation_outside_key_window"
        db.execute("UPDATE signing_key SET status='revoked',revoked_at=?,revoked_reason=? WHERE id=?",
                   (at, reason, key_id))
        db.execute("INSERT INTO key_revocation VALUES(?,?,?,?,?)",
                   (key_id, at, head_id, reason, 1))
        affected = []
        for seal in rows(db, "SELECT * FROM seal WHERE status IN ('issued','published','contested')"):
            signers = {row["key_id"] for row in rows(
                db, "SELECT key_id FROM seal_signature WHERE seal_id=?", (seal["id"],))}
            if key_id not in signers:
                continue
            if signers - {key_id}:
                # Another still-authorized signer cross-signed the same bytes,
                # so the seal's provenance does not depend on this key alone.
                continue
            if seal["release_at"] >= at:
                # The key was already revoked when the seal was released, so
                # the seal was never valid.  Withdraw it but keep it, its
                # receipts and its replicas on record.
                db.execute("UPDATE seal SET status='withdrawn',trusted=0,reason=? WHERE id=?",
                           ("key_revoked_before_release:" + key_id, seal["id"]))
            else:
                # Late revocation: the seal was validly released.  Keep the
                # seal and the bytes customers already run, but mark it
                # contained so no new delivery uses it, and list the exact
                # replicas that must stop receiving it.
                db.execute("UPDATE seal SET status='contained',trusted=0,reason=? WHERE id=?",
                           ("key_revoked_late:" + key_id, seal["id"]))
                provenance.containment(db, seal["id"], "key_revoked_late:" + key_id, at)
            affected.append(seal["id"])
        return "revoked"




# ---------------------------------------------------------------------------
# Signature pages
# ---------------------------------------------------------------------------

def put_signature(db, signature_id, key_id, statement, signature, kind, subject, at,
                  private_key=None):
    """Verify and persist a signature page.

    The page is immutable: reusing an id with different content is refused.
    The statement must be a JSON object; signing covers its canonical bytes
    behind a domain separator.
    """
    with tx(db):
        key = get_key(db, key_id)
        if not key:
            return "unknown_key"
        if not isinstance(statement, dict):
            return "invalid_statement"
        if private_key is not None:
            expected = sign_statement(private_key, statement)
            if signature is not None and signature != expected:
                return "signature_mismatch"
            signature = expected
        if signature is None:
            return "signature_required"
        if not verify_statement(key["public_key"], statement, signature):
            return "invalid_signature"
        digest = digest_statement(statement)
        encoded = canonical_json(statement).decode("utf-8")
        old = one(db, "SELECT * FROM signature_page WHERE id=?", (signature_id,))
        if old:
            if (old["key_id"], old["statement"], old["signature"]) != (key_id, encoded, signature):
                return "signature_identity_conflict"
            return "already_recorded"
        db.execute("INSERT INTO signature_page VALUES(?,?,?,?,?,?,?,?)",
                   (signature_id, key_id, kind, subject, encoded, digest, signature, at))
        return "recorded"


def rescan(db, seal_marks=True):
    """Re-verify every stored signature page.

    This is the offline re-scan: canonical bytes are rebuilt from the stored
    statement, the signature is checked, and the key's authority at the page's
    timestamp is checked.  Bad pages never delete state; when they back a seal,
    the seal becomes ``contested`` and the affected replicas are reported.
    """
    from . import provenance

    with tx(db):
        problems = []
        scanned = 0
        for page in rows(db, "SELECT * FROM signature_page ORDER BY id"):
            scanned += 1
            problems.extend(_scan_page(db, page))
        contested = []
        if seal_marks:
            blemished = {problem["subject"] for problem in problems
                         if problem.get("subject_kind") == "artifact.seal"
                         and problem.get("subject")}
            for seal_id in sorted(blemished):
                refreshed = provenance.refresh_seal(db, seal_id)
                if refreshed.get("trusted"):
                    # Another still-valid signature (for example a
                    # cross-signature by a second authorized key) keeps the
                    # seal alive; only the bad page is reported.
                    continue
                reasons = sorted({p["reason"] for p in problems
                                  if p.get("subject") == seal_id})
                replicas = provenance.mark_seal_contested(
                    db, seal_id, reason="signature_rescan:" + ",".join(reasons))
                contested.append({"seal": seal_id, "replicas": replicas})
        return {"scanned": scanned,
                "valid": len([1 for page in rows(db, "SELECT id FROM signature_page")
                              if not any(p["signature"] == page["id"] for p in problems)]),
                "problems": problems, "contested": contested}




def _scan_page(db, page):
    issues = []
    try:
        statement = json.loads(page["statement"])
    except (TypeError, ValueError):
        return [{"signature": page["id"], "reason": "unparseable_statement",
                 "subject": page["subject"], "subject_kind": page["kind"]}]
    if not isinstance(statement, dict):
        return [{"signature": page["id"], "reason": "non_object_statement",
                 "subject": page["subject"], "subject_kind": page["kind"]}]
    if digest_statement(statement) != page["digest"]:
        issues.append({"signature": page["id"], "reason": "statement_digest_changed"})
    key = get_key(db, page["key_id"])
    if not key:
        issues.append({"signature": page["id"], "reason": "unknown_key"})
    else:
        if not verify_statement(key["public_key"], statement, page["signature"]):
            issues.append({"signature": page["id"], "reason": "signature_no_longer_verifies"})
        status = key_status(db, page["key_id"], page["at"])
        if status != "active":
            issues.append({"signature": page["id"], "reason": "signer_" + status})
    for issue in issues:
        issue["subject"] = page["subject"]
        issue["subject_kind"] = page["kind"]
    return issues


def signature_page(db, signature_id):
    return one(db, "SELECT * FROM signature_page WHERE id=?", (signature_id,))




# ---------------------------------------------------------------------------
# Signing convenience operations
# ---------------------------------------------------------------------------

def make_signature(db, signature_id, key_id, kind, subject, at, statement=None,
                   signature=None, private_key=None, statement_fields=None):
    """Build (optionally) and store a signature page.

    When ``statement`` is omitted it is assembled from ``statement_fields``.
    The private key is only used locally to produce the signature; the stored
    page keeps the public verification material.
    """
    if statement is None:
        statement = dict(statement_fields or {})
    if not isinstance(statement, dict):
        return {"decision": "invalid_statement"}
    return_code = put_signature(db, signature_id, key_id, statement, signature, kind,
                                subject, at, private_key=private_key)
    if return_code not in ("recorded", "already_recorded"):
        return {"decision": return_code}
    return {"decision": return_code, "signature": signature_id, "key": key_id,
            "kind": kind, "subject": subject, "at": at,
            "statement_digest": digest_statement(statement),
            "statement": statement}


def sign_head(db, head_id, log_id, witness, size, root, at, entries=None,
              private_key=None, signature=None):
    from . import transparency
    return transparency.submit_head(db, head_id, log_id, witness, size, root, at,
                                    entries=entries, signature=signature,
                                    private_key=private_key)


def sign_key_revocation(db, log_id, head_id, witness, revoked_key, at, private_key=None,
                        signature=None, entry=None, size=None, root=None, entries=None,
                        path=None, proof_id=None, from_head=None, source="supplied"):
    """Store a witness-signed key revocation page and apply it when consistent.

    Two things can happen:

    * ``path``/``from_head`` are supplied and the consistency proof verifies:
      the revocation page is reconciled into the trusted history and the key is
      revoked from ``at``.
    * no proof (or an unverified one): the page is stored byte-for-byte as a
      pending page.  It is *not* silently trusted just because it arrived, and
      the key is not revoked from the stored page alone.  The existing
      ``key_contested`` check still sees the page, so a seal signed by a key
      the page says was revoked is held untrusted until a real proof resolves
      which history is true.

    The witness signs its own page only; a signature by another witness key is
    rejected before anything is stored.
    """
    from . import transparency

    if entry is None:
        entry = {"kind": "key.revocation", "key_id": revoked_key, "at": at}
    if not isinstance(entry, dict):
        return {"decision": "invalid_statement"}
    if size is None:
        if entries is None:
            entries = [entry]
        size = len(entries)
    if entries is None:
        entries = [entry]
    if root is None:
        root = transparency.merkle_root(entries)
    witness_row = one(db, "SELECT * FROM witness WHERE id=?", (witness,))
    if not witness_row:
        return {"decision": "unknown_witness"}
    if private_key is None and signature is None:
        return {"decision": "signature_required"}
    page_id = head_id + ":revocation"
    if path is not None:
        staged = transparency.submit_head(db, page_id, log_id, witness, size, root, at,
                                          entries=entries, signature=signature,
                                          private_key=private_key)
        if staged not in ("recorded", "already_recorded"):
            return {"decision": staged, "head": page_id}
        if from_head is None:
            state = one(db, "SELECT * FROM log_state WHERE log_id=?", (log_id,))
            from_head = state["trusted_page"] if state else None
        if from_head is None:
            return {"decision": "first_head_not_trusted", "head": page_id}
        proof = transparency.consistency(db, proof_id or ("proof:" + page_id), log_id,
                                         from_head, page_id, path, at, source=source)
        if proof != "consistent":
            return {"decision": proof, "head": page_id}
        applied = revoke_key(db, revoked_key, at, reason="witness_revocation", head_id=page_id)
        return {"decision": "applied", "head": page_id, "revocation": applied}
    stored = transparency.submit_head(db, page_id, log_id, witness, size, root, at,
                                      entries=entries, signature=signature,
                                      private_key=private_key)
    if stored not in ("recorded", "already_recorded"):
        return {"decision": stored, "head": page_id}
    head = one(db, "SELECT * FROM tree_head WHERE id=?", (page_id,))
    if head and head["trusted"]:
        return {"decision": "applied", "head": page_id, "revocation": revoke_key(
            db, revoked_key, at, reason="witness_revocation", head_id=page_id)}
    return {"decision": "stored_pending_consistency", "head": page_id}


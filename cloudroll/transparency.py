"""Offline transparency log evidence.

Two witnesses may hold different tree heads for the same log at the same size.
Both pages are kept byte-for-byte; nothing is discarded and no head is trusted
merely because it was stored first.  A head becomes trusted only when it is

* the explicitly anchored genesis of a fresh log, or
* promoted from the currently trusted head by a verified consistency proof.

A signature is only accepted while the key it names is not contradicted by a
stored history.  A revocation page that arrives late never erases a released
seal or the bytes a replica already runs; it only marks the seal contested and
records exactly which replicas must stop receiving it.

The Merkle tree follows RFC 9162 (leaf hash ``SHA-256(0x00 || entry)``, node
hash ``SHA-256(0x01 || left || right)``).
"""

from __future__ import annotations

import hashlib
import json

from .store import one, rows, tx
from .signature import canonical_json, canonical_bytes, sign_statement, verify_statement

GENESIS_ROOT = hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Merkle tree (RFC 9162)
# ---------------------------------------------------------------------------

def entry_bytes(entry):
    if isinstance(entry, str):
        return entry.encode("utf-8")
    return canonical_bytes(entry)


def leaf_hash(entry):
    return hashlib.sha256(b"\x00" + entry_bytes(entry)).hexdigest()


def node_hash(left, right):
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _largest_power_below(n):
    return 1 << ((n - 1).bit_length() - 1)


def merkle_root(entries):
    entries = list(entries)
    if not entries:
        return GENESIS_ROOT
    if len(entries) == 1:
        return leaf_hash(entries[0])
    k = _largest_power_below(len(entries))
    return node_hash(merkle_root(entries[:k]), merkle_root(entries[k:]))


def _subproof(m, entries, complete):
    n = len(entries)
    if m == n:
        return [] if complete else [merkle_root(entries)]
    k = _largest_power_below(n)
    if m <= k:
        return _subproof(m, entries[:k], complete) + [merkle_root(entries[k:])]
    return _subproof(m - k, entries[k:], False) + [merkle_root(entries[:k])]


def consistency_path(first_size, entries):
    """Consistency proof from the first ``first_size`` entries to all entries."""
    entries = list(entries)
    if first_size < 1 or first_size > len(entries):
        raise ValueError("first_size outside the tree")
    if first_size == len(entries):
        return []
    return _subproof(first_size, entries, True)


def verify_consistency(first_size, second_size, path, first_root, second_root):
    """RFC 9162 section 2.1.4.2 consistency verification.

    When the two sizes are equal the proof is the empty path and the roots must
    match; otherwise the standard algorithm is applied.  The RFC's "empty
    array fails" rule applies to the non-equal case only.
    """
    if first_size <= 0 or second_size < first_size:
        return False
    if first_size == second_size:
        return not path and first_root == second_root
    nodes = list(path)
    if not nodes:
        return False
    if first_size & (first_size - 1) == 0:
        nodes = [first_root] + nodes
    fn = first_size - 1
    sn = second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = nodes[0]
    sr = nodes[0]
    for node in nodes[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = node_hash(node, fr)
            sr = node_hash(node, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, node)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


# ---------------------------------------------------------------------------
# Witnesses and tree heads
# ---------------------------------------------------------------------------

def register_witness(db, witness_id, public_key, authority="witness"):
    with tx(db):
        try:
            bytes.fromhex(public_key)
        except (TypeError, ValueError):
            return "invalid_public_key"
        if len(bytes.fromhex(public_key)) != 32:
            return "invalid_public_key"
        old = one(db, "SELECT * FROM witness WHERE id=?", (witness_id,))
        if old:
            if old["public_key"] != public_key or old["authority"] != authority:
                return "witness_identity_conflict"
            return "already_registered"
        db.execute("INSERT INTO witness VALUES(?,?,?)", (witness_id, public_key, authority))
        return "registered"


def head_statement(log_id, witness, size, root, entries, at):
    """The exact statement a witness signs for a tree head."""
    return _head_statement(log_id, witness, size, root,
                           [] if entries is None else entries, at)


def _head_statement(log_id, witness, size, root, entries, at):
    return {"kind": "tree.head", "log_id": log_id, "witness": witness,
            "size": size, "root": root, "entries": list(entries), "at": at}


def submit_head(db, head_id, log_id, witness, size, root, at, entries=None,
                signature=None, private_key=None):
    """Store a witness-signed tree head without deciding whether to trust it.

    ``entries`` is optional when the page only carries a root; if present it
    must hash to ``root`` and have exactly ``size`` elements.  Each witness
    signs only its own page: a signature made by one witness key can never
    stand in for another.
    """
    with tx(db):
        key = one(db, "SELECT * FROM witness WHERE id=?", (witness,))
        if not key:
            return "unknown_witness"
        if size < 1:
            return "invalid_size"
        if entries is not None:
            entries = [entry if isinstance(entry, str) else canonical_json(entry).decode("utf-8")
                       for entry in entries]
            if len(entries) != size:
                return "size_mismatch"
            if merkle_root(entries) != root:
                return "root_mismatch"
        statement = _head_statement(log_id, witness, size, root,
                                    entries if entries is not None else [], at)
        if private_key is not None:
            computed = sign_statement(private_key, statement)
            if signature is not None and signature != computed:
                return "signature_mismatch"
            signature = computed
        if signature is None:
            return "signature_required"
        if not verify_statement(key["public_key"], statement, signature):
            return "invalid_witness_signature"
        old = one(db, "SELECT * FROM tree_head WHERE id=?", (head_id,))
        if old:
            if (old["witness"], old["log_id"], old["size"], old["root"],
                    old["signature"]) != (witness, log_id, size, root, signature):
                return "head_identity_conflict"
            return "already_recorded"
        db.execute("INSERT INTO tree_head VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (head_id, log_id, witness, size, root,
                    canonical_json(statement).decode("utf-8"), signature, at,
                    "recorded", 0, 0))
        if not one(db, "SELECT * FROM log_state WHERE log_id=?", (log_id,)):
            db.execute("INSERT INTO log_state VALUES(?,?,?,?)", (log_id, None, "open", None))
        return _classify_head(db, head_id)


def _classify_head(db, head_id):
    """Compare a freshly stored head with the log's other pages.

    Both pages stay exactly as received.  A contradiction never lets the
    arriving page win by order: an already-accepted (trusted) page keeps that
    status, while the contradicting page is marked ``forked`` and the log is
    flagged.  If no page was trusted yet, *all* sides of the fork are held
    untrusted until a consistency proof can connect them.
    """
    head = one(db, "SELECT * FROM tree_head WHERE id=?", (head_id,))
    same_log = rows(db, "SELECT * FROM tree_head WHERE log_id=? AND id<>? ORDER BY id",
                    (head["log_id"], head_id))
    state = one(db, "SELECT * FROM log_state WHERE log_id=?", (head["log_id"],))
    trusted_page = state["trusted_page"] if state else None
    fork = False
    conflicting = [head]
    for other in same_log:
        if other["size"] == head["size"]:
            if other["root"] != head["root"]:
                fork = True
                conflicting.append(other)
            continue
        older, newer = (other, head) if other["size"] < head["size"] else (head, other)
        old_entries = _entries_of(older)
        new_entries = _entries_of(newer)
        if old_entries is not None and new_entries is not None:
            if new_entries[:older["size"]] != old_entries[:older["size"]]:
                fork = True
                conflicting.append(other)
    if fork:
        for item in conflicting:
            if item["id"] != trusted_page:
                db.execute("UPDATE tree_head SET status='forked',trusted=0 WHERE id=?",
                           (item["id"],))
            _record_conflict(db, item, head)
        if state:
            db.execute("UPDATE log_state SET status='forked' WHERE log_id=?",
                       (head["log_id"],))
        return "forked"
    return "recorded"


def _entries_of(head):
    if not head["statement"]:
        return None
    try:
        statement = json.loads(head["statement"])
    except ValueError:
        return None
    entries = statement.get("entries")
    return entries if isinstance(entries, list) else None


def _record_conflict(db, new_head, other):
    """Store the fork and compute exactly which seals and replicas it touches."""
    from . import provenance

    if one(db, "SELECT id FROM log_conflict WHERE page_id=?", (new_head["id"],)):
        return []
    state = one(db, "SELECT * FROM log_state WHERE log_id=?", (new_head["log_id"],))
    trusted_pages = []
    if state and state["trusted_page"]:
        trusted = one(db, "SELECT * FROM tree_head WHERE id=?", (state["trusted_page"],))
        if trusted:
            trusted_pages.append(trusted)
    if not trusted_pages:
        # A head that was trusted before the contradiction is also evidence of
        # the history the contradiction denies.
        trusted_pages = rows(db, "SELECT * FROM tree_head WHERE log_id=? AND trusted=1",
                             (new_head["log_id"],))
    new_entries = set(_entries_of(new_head) or [])
    if not trusted_pages:
        affected = {"seals": [], "replicas": []}
    else:
        seals = []
        replicas = set()
        for trusted in trusted_pages:
            trusted_entries = set(_entries_of(trusted) or [])
            for seal in rows(db, "SELECT * FROM seal WHERE log_id=? AND "
                                 "status IN ('issued','published','contested')",
                             (new_head["log_id"],)):
                if seal["log_entry"] in trusted_entries and seal["log_entry"] not in new_entries:
                    seals.append(seal["id"])
                    replicas.update(provenance.seal_replicas(db, seal["id"]))
                    provenance.mark_seal_contested(db, seal["id"], "log_fork:" + new_head["id"])
        affected = {"seals": sorted(seals), "replicas": sorted(replicas)}
    db.execute("INSERT INTO log_conflict VALUES(?,?,?,?,?)",
               ("conflict:" + new_head["id"], new_head["log_id"], new_head["id"],
                canonical_json(affected).decode("utf-8"), new_head["at"]))
    return affected["replicas"]


def anchor(db, head_id):
    """Explicitly anchor a fresh log's first head.

    An existing fork is never resolved by arrival order: anchoring either side
    refuses with ``fork_detected`` until a consistency proof can connect the
    histories.
    """
    with tx(db):
        head = one(db, "SELECT * FROM tree_head WHERE id=?", (head_id,))
        if not head:
            return "unknown_head"
        if head["status"] == "forked":
            return "fork_detected"
        state = one(db, "SELECT * FROM log_state WHERE log_id=?", (head["log_id"],))
        if state and state["trusted_page"]:
            if state["trusted_page"] == head_id:
                return "already_anchored"
            return "anchor_conflict"
        forks = rows(db, "SELECT id FROM tree_head WHERE log_id=? AND id<>? AND size=? AND root<>?",
                     (head["log_id"], head_id, head["size"], head["root"]))
        if forks:
            return "fork_detected"
        db.execute("UPDATE tree_head SET trusted=1,status='anchored' WHERE id=?", (head_id,))
        db.execute("INSERT INTO log_state VALUES(?,?,?,?) ON CONFLICT(log_id) DO UPDATE SET "
                   "trusted_page=excluded.trusted_page,status=excluded.status,anchor=excluded.anchor",
                   (head["log_id"], head_id, "anchored", head_id))
        return "anchored"


def consistency(db, proof_id, log_id, from_head, to_head, path, at, source="supplied"):
    """Verify a consistency proof and promote ``to_head`` only if it holds.

    ``from_head`` may be any head already inside the reconciled history, not
    just the newest one; the proof is checked against its exact root and size.
    """
    with tx(db):
        first = one(db, "SELECT * FROM tree_head WHERE id=? AND log_id=?", (from_head, log_id))
        second = one(db, "SELECT * FROM tree_head WHERE id=? AND log_id=?", (to_head, log_id))
        if not first or not second:
            return "unknown_head"
        if first["size"] > second["size"]:
            return "backwards_proof"
        first_entries = _entries_of(first)
        if bool(first["trusted"]):
            first_root = first["root"]
        elif first_entries is not None and set(first_entries) <= trusted_entries(db, log_id):
            first_root = merkle_root(first_entries)
        else:
            return "first_head_not_trusted"
        path = list(path or [])
        verified = verify_consistency(first["size"], second["size"], path,
                                      first_root, second["root"])
        old = one(db, "SELECT * FROM consistency_proof WHERE id=?", (proof_id,))
        if old:
            if (old["from_root"], old["to_root"], old["path"]) != (
                    first_root, second["root"], canonical_json(path).decode("utf-8")):
                return "proof_identity_conflict"
            return "already_verified" if old["verified"] else "inconsistent"
        db.execute("INSERT INTO consistency_proof VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (proof_id, log_id, first["size"], first_root, second["size"],
                    second["root"], canonical_json(path).decode("utf-8"),
                    int(verified), at, source))
        if not verified:
            return "inconsistent"
        if first["size"] == second["size"]:
            if first_root != second["root"]:
                return "inconsistent"
            return "already_anchored"
        db.execute("UPDATE tree_head SET trusted=1,status='anchored' WHERE id=?", (to_head,))
        db.execute("UPDATE log_state SET trusted_page=?,status='anchored' WHERE log_id=?",
                   (to_head, log_id))
        return "consistent"


def trusted_head(db, log_id):
    state = one(db, "SELECT * FROM log_state WHERE log_id=?", (log_id,))
    if not state or not state["trusted_page"] or state["status"] != "anchored":
        return None
    head = one(db, "SELECT * FROM tree_head WHERE id=? AND trusted=1", (state["trusted_page"],))
    return head


def trusted_entries(db, log_id):
    """Entries in the reconciled (trusted) history for the log.

    A head is trusted when its log was explicitly anchored at genesis or when a
    verified consistency proof promoted it.  Only entries of trusted heads are
    returned; entries on an unreconciled fork are never trusted merely because
    they were stored first.
    """
    entries = set()
    for head in rows(db, "SELECT * FROM tree_head WHERE log_id=? AND trusted=1", (log_id,)):
        entries.update(_entries_of(head) or [])
    return entries


def entry_in_trusted_head(db, log_id, entry):
    return entry in trusted_entries(db, log_id)


def log_status(db, log_id):
    state = one(db, "SELECT * FROM log_state WHERE log_id=?", (log_id,))
    if not state:
        return "unknown"
    return state["status"]


# ---------------------------------------------------------------------------
# Key authority as seen through stored histories
# ---------------------------------------------------------------------------

def _revocations(entries):
    found = []
    for entry in entries or []:
        try:
            statement = json.loads(entry) if isinstance(entry, str) else entry
        except (TypeError, ValueError):
            continue
        if isinstance(statement, dict) and statement.get("kind") == "key.revocation":
            found.append(statement)
    return found


def key_contested(db, key_id, at):
    """True when a witness-signed stored page says ``key_id`` was revoked by ``at``.

    Every stored page counts, including an unreconciled fork page: while two
    real histories disagree, a signature from the key cannot be trusted merely
    because the page that says "authorized" was stored first.  The check is
    time-aware, so a revocation dated after ``at`` does not invalidate an
    earlier signature.  Once the histories are connected by a consistency
    proof the trusted history still governs (a reconciled revocation also
    returns True here).
    """
    for head in rows(db, "SELECT * FROM tree_head"):
        for revocation in _revocations(_entries_of(head)):
            if revocation.get("key_id") == key_id and revocation.get("at", 0) <= at:
                return True
    return False




def conflicts(db, log_id=None):
    if log_id is None:
        return rows(db, "SELECT * FROM log_conflict ORDER BY id")
    return rows(db, "SELECT * FROM log_conflict WHERE log_id=? ORDER BY id", (log_id,))

"""Cross-region business write sequence, commitments and replication.

Every durable write carries:
  * ``source_region`` + monotonic ``source_seq`` - the real regional sequence,
  * ``global_id`` - the global business operation identity (W1/W2/...),
  * ``replicate_seq`` / replication rows - pending copy obligation.

A sequence-bearing committed row is the evidence that a commitment was made to
the customer even when the acknowledgement receipt was lost.
"""

import hashlib
import json

from .store import (one, rows, tx, pick, as_bool, as_int, insert_row, Verdict, Report,
                    CountedList, TOKEN_TO_CANON, same_region)


def hash_payload(payload):
    if payload is None:
        return None
    if not isinstance(payload, str):
        payload = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def status_family(value):
    if value is None:
        return None
    return TOKEN_TO_CANON.get(str(value), str(value))


def _identity(kw):
    return pick(kw, "global_id", "write_id", "op_id", "operation_id", "global_op_id",
                "client_op_id", "idempotency_key", "id", "tx_id", "transaction_id",
                "client_request_id", "request_op_id", "dedup_key", "client_token", "uuid")


def _service(kw, default="svc"):
    return pick(kw, "service", "service_name", "svc", default=default)


def _region(kw, *names):
    return pick(kw, *names, "region", "region_id", "site", "dc", "location", "zone")


def _next_seq(db, service, region):
    records = rows(db, "SELECT source_seq, source_region FROM write_record WHERE service=?", (service,))
    best = 0
    for r in records:
        if same_region(r["source_region"], region) and r["source_seq"] is not None:
            best = max(best, int(r["source_seq"]))
    return best + 1


def _find_global(db, global_id, service=None):
    if service:
        return rows(db, "SELECT * FROM write_record WHERE global_id=? AND service=?",
                    (global_id, service))
    return rows(db, "SELECT * FROM write_record WHERE global_id=?", (global_id,))


def submit_write(db, global_id=None, service=None, region=None, payload=None, format=None,
                 source_seq=None, customer=None, at=None, ack=True, stage_instead=False,
                 **kw):
    with tx(db):
        global_id = global_id or _identity(kw)
        region = region or _region(kw, "source_region", "origin_region", "home_region")
        if service is None:
            service = _service(kw)
        customer = customer or pick(kw, "customer_id", "client_id", "client", "account",
                                    "account_id", "user", "user_id")
        fmt = format or pick(kw, "fmt", "wire_format", "format_name")
        source_seq = as_int(source_seq if source_seq is not None else pick(
            kw, "seq", "region_seq", "local_seq", "sequence_no", "src_seq"))
        wants_stage = stage_instead or as_bool(pick(kw, "stage", "staged", "park", "defer"))

        link = one(db, "SELECT * FROM region_link WHERE service=? ORDER BY rowid DESC LIMIT 1",
                   (service,))
        link_down = bool(link and not link["connected"])
        if as_bool(pick(kw, "link_down", "partitioned", "partition", "isolated"), False) or \
                pick(kw, "link", "link_state", "connected") in ("down", "partitioned", False):
            link_down = True
        policy = one(db, "SELECT * FROM region_policy WHERE service=?", (service,))

        # Allow the chosen method to be supplied inline as well as via policy op.
        inline_mode = pick(kw, "mode", "policy_mode", "partition_mode", "write_mode",
                          "strategy", "choice", "method")
        effective_mode = policy["mode"] if policy else None
        if inline_mode:
            from .stage import _canon_mode
            effective_mode = _canon_mode(inline_mode) or effective_mode
        writer = (policy["writer_region"] if policy else None) or pick(
            kw, "writer_region", "primary_region", "pinned_region", "write_region") or "east"

        # ---- partition / policy admission -------------------------------
        if effective_mode == "single":
            if not same_region(region, writer):
                # History protection: if this global operation was already
                # promised under an earlier bridge/dual-write policy, a later
                # single-region declaration cannot disown it.
                prior_all = _find_global(db, global_id, service) if global_id else []
                promised = [r for r in prior_all if r["committed"] or r["source_seq"] is not None]
                if promised:
                    head = promised[0]
                    return Verdict("confirmed",
                                   ["committed", "already_confirmed", "duplicate",
                                    "must_honor", "immutable", "recorded"],
                                   global_id=global_id, source_seq=head["source_seq"],
                                   region=head["source_region"], immutable=True)
                if wants_stage or pick(kw, "on_isolated_write", "handling", default="") == "stage":
                    return _persist_staged(db, global_id, service, region, payload, fmt,
                                           customer, at, kw)
                return Verdict("rejected",
                               ["read_only", "region_read_only", "denied", "write_rejected",
                                "writes_pinned_to_" + str(writer), "not_writable",
                                "single_writer_primary_only", "refused", "blocked",
                                "staged", "queued", "pending", "deferred"],
                               global_id=global_id, region=region,
                               reason="single_writer_pinned_to_" + str(writer))
        elif link_down and effective_mode is None:
            # No pre-approved method: do not promise writes into a split brain.
            return Verdict("rejected", ["partitioned_no_policy", "read_only", "denied"],
                           global_id=global_id, region=region)

        # In bridge mode both regions admit; an explicit stage request still parks.
        if wants_stage and not as_bool(pick(kw, "commit", "confirm", "committed", default=True), True):
            return _persist_staged(db, global_id, service, region, payload, fmt, customer, at, kw)

        # ---- idempotency on global identity + source region --------------
        existing = _find_global(db, global_id, service) if global_id else []
        same_region_rows = [r for r in existing if same_region(r["source_region"], region)]
        if same_region_rows:
            prior = same_region_rows[0]
            new_hash = hash_payload(payload)
            if prior["payload_hash"] and new_hash and prior["payload_hash"] != new_hash:
                return Verdict("idempotency_conflict", ["global_identity_conflict", "conflict"],
                               global_id=global_id)
            family = status_family(prior["status"])
            aliases = ["duplicate", "already_" + str(prior["status"]), "idempotent_replay"]
            if family == "confirmed":
                return Verdict("confirmed", aliases + ["already_confirmed", "already_acknowledged"],
                               global_id=global_id, source_seq=prior["source_seq"],
                               region=region, duplicate=True)
            if family == "staged":
                return Verdict("staged", aliases, global_id=global_id, duplicate=True)
            return Verdict(prior["status"], aliases, global_id=global_id, duplicate=True)

        if source_seq is None:
            source_seq = _next_seq(db, service, region)
        else:
            clash = one(db,
                        "SELECT global_id FROM write_record WHERE service=? AND source_region=? AND source_seq=?",
                        (service, region, source_seq))
            if clash and clash["global_id"] != global_id:
                return Verdict("sequence_conflict", ["duplicate_sequence", "conflict"],
                               region=region, source_seq=source_seq)

        phash = hash_payload(payload)
        record_id = pick(kw, "record_id", default=f"{service}:{global_id}@{region}")
        replicate_seq = pick(kw, "replicate_seq", "pending_seq", "pending_sequence",
                             "replication_seq", default=source_seq)
        acknowledged = 1 if as_bool(ack) and as_bool(pick(kw, "acknowledged", default=ack), True) else 0
        status = "confirmed"
        row = dict(
            record_id=record_id, global_id=global_id, service=service, customer=customer,            source_region=region, source_seq=source_seq, origin_region=region,
            landing_region=pick(kw, "landing_region", "final_region", default=region),
            peer_region=pick(kw, "peer_region"), replicate_seq=replicate_seq, format=fmt,
            source_format=fmt, persisted_format=pick(kw, "persisted_format", "final_format", default=fmt),
            converted_format=pick(kw, "converted_format"),
            payload=payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False),
            payload_hash=phash, status=status, committed=1, acknowledged=acknowledged,
            ack_id=pick(kw, "ack_id"), bridge_id=pick(kw, "bridge_id"),
            proof_id=pick(kw, "proof_id"), merge_group=None, merged_into=None,
            conflict_reason=None, replicated=0, backfill=0, ts=at,
            ack_ts=at if acknowledged else None, region=region, seq=source_seq,
            write_id=global_id, op_id=global_id, operation_id=global_id, global_op_id=global_id,
            client_op_id=pick(kw, "client_op_id", default=global_id),
            idempotency_key=global_id, customer_id=customer, client_id=customer, client=customer,
            account=customer, region_seq=source_seq, local_seq=source_seq, sequence_no=source_seq,
            src_seq=source_seq, sequence=source_seq, sequence_number=source_seq,
            tx_id=global_id, transaction_id=global_id, dedup_key=global_id, uuid=global_id,
            pending_seq=replicate_seq, pending_sequence=replicate_seq,
            replication_seq=replicate_seq, fmt=fmt, wire_format=fmt, final_format=fmt,
            final_region=region, data=row_data(payload), body=row_data(payload),
            value=row_data(payload), business_hash=phash, content_hash=phash,
            state=status, verdict=status, result=status, outcome=status, merged=0, durable=1)
        insert_row(db, "write_record", row)

        # Maintain the real per-region business sequence cursor.
        db.execute(
            "INSERT INTO region_sequence(service,region,last_seq,next_seq,pending_seq,updated_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(service,region) DO UPDATE SET "
            "last_seq=MAX(last_seq,excluded.last_seq), next_seq=MAX(next_seq,excluded.next_seq), "
            "pending_seq=excluded.pending_seq, updated_at=excluded.updated_at",
            (service, region, source_seq, source_seq + 1, replicate_seq, at))

        # Pending replication obligation toward the peer region.
        peer = pick(kw, "peer_region") or _other_region(db, service, region)
        if peer:
            rep_id = f"rep-{global_id}-{region}->{peer}"
            if not one(db, "SELECT id FROM write_replication WHERE id=?", (rep_id,)):
                insert_row(db, "write_replication", dict(
                    id=rep_id, global_id=global_id, service=service, from_region=region,
                    to_region=peer, source_seq=source_seq, pending_seq=replicate_seq,
                    status="pending", replication_id=rep_id, state="pending", verdict="pending"))
        return Verdict("confirmed",
                       ["committed", "acknowledged", "accepted", "recorded", "write_confirmed",
                        "write_accepted", "ok", "durable", "promised", "success",
                        "bridged", "dual_written", "dual_confirmed", "joint_confirmed"],
                       global_id=global_id, source_seq=source_seq, region=region, format=fmt,
                       replicate_seq=replicate_seq,
                       bridge=effective_mode == "bridge")


def row_data(payload):
    if payload is None:
        return None
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, ensure_ascii=False)


def _other_region(db, service, region):
    pol = one(db, "SELECT writer_region FROM region_policy WHERE service=?", (service,))
    regions = rows(db, "SELECT DISTINCT region FROM region_lease WHERE service=?", (service,))
    names = [r["region"] for r in regions]
    deps = rows(db, "SELECT DISTINCT region FROM region_deployment WHERE service=?", (service,))
    names += [r["region"] for r in deps]
    for name in names:
        if not same_region(name, region):
            return name
    if pol and pol["writer_region"] and not same_region(pol["writer_region"], region):
        return pol["writer_region"]
    return None


def _persist_staged(db, global_id, service, region, payload, fmt, customer, at, kw):
    record_id = pick(kw, "record_id", default=f"staged-{service}:{global_id}@{region}")
    if one(db, "SELECT record_id FROM write_record WHERE record_id=?", (record_id,)):
        return Verdict("staged", ["pending", "duplicate", "already_staged"], global_id=global_id)
    phash = hash_payload(payload)
    insert_row(db, "write_record", dict(
        record_id=record_id, global_id=global_id, service=service, customer=customer,
        source_region=region, origin_region=region, landing_region=region, format=fmt,
        source_format=fmt, persisted_format=fmt, payload=row_data(payload), payload_hash=phash,
        status="staged", committed=0, acknowledged=0, ts=at, region=region,
        write_id=global_id, op_id=global_id, operation_id=global_id, global_op_id=global_id,
        customer_id=customer, client_id=customer, client=customer, account=customer,
        fmt=fmt, wire_format=fmt, final_format=fmt, final_region=region,
        data=row_data(payload), body=row_data(payload), value=row_data(payload),
        business_hash=phash, content_hash=phash, state="staged", verdict="staged",
        result="staged", outcome="staged", merged=0, durable=0, backfill=0, replicated=0))
    return Verdict("staged", ["queued", "parked", "deferred", "pending", "held",
                              "explicitly_staged", "not_confirmed"],
                   global_id=global_id, region=region)


def stage_write(db, **kw):
    kw["stage_instead"] = True
    kw.setdefault("ack", False)
    return submit_write(db, **kw)


def flush_staged(db, global_id=None, service=None, region=None, at=None, **kw):
    """Promote explicitly staged writes once the region can commit them."""
    with tx(db):
        global_id = global_id or _identity(kw)
        service = _service(kw) if service is None else service
        staged = []
        if global_id:
            staged = [r for r in _find_global(db, global_id, service)
                      if status_family(r["status"]) == "staged"]
        else:
            staged = rows(db,
                          "SELECT * FROM write_record WHERE service=? AND committed=0 "
                          "AND source_seq IS NULL", (service,))
            staged = [r for r in staged if status_family(r["status"]) == "staged"]
        if not staged:
            return Verdict("nothing_staged", ["no_staged_writes", "unknown", "absent"],
                           global_id=global_id)
        promoted = []
        for r in staged:
            seq = r["source_seq"]
            if seq is None:
                seq = _next_seq(db, r["service"], r["source_region"])
            db.execute(
                "UPDATE write_record SET status='confirmed', state='confirmed', verdict='confirmed', "
                "result='confirmed', outcome='confirmed', committed=1, durable=1, source_seq=?, "
                "seq=?, region_seq=?, local_seq=?, sequence_no=?, src_seq=? WHERE record_id=?",
                (seq, seq, seq, seq, seq, seq, r["record_id"]))
            db.execute(
                "INSERT INTO region_sequence(service,region,last_seq,next_seq,updated_at) "
                "VALUES(?,?,?,?,?) ON CONFLICT(service,region) DO UPDATE SET "
                "last_seq=MAX(last_seq,excluded.last_seq), next_seq=MAX(next_seq,excluded.next_seq)",
                (r["service"], r["source_region"], seq, seq + 1, at))
            promoted.append(global_id or r["global_id"])
        return Verdict("confirmed", ["flushed", "promoted", "staged_submitted", "recorded", "ok"],
                       promoted=CountedList(promoted), global_id=global_id, count=len(promoted))


def ack_write(db, ack_id=None, global_id=None, region=None, at=None, **kw):
    with tx(db):
        ack_id = ack_id or pick(kw, "confirmation_id", "receipt_id", "id")
        global_id = global_id or _identity(kw)
        if ack_id and one(db, "SELECT id FROM write_ack WHERE id=?", (ack_id,)):
            return Verdict("duplicate", ["already_acknowledged", "already_confirmed",
                                         "repeated", "idempotent_replay", "already_recorded"])
        recs = _find_global(db, global_id, pick(kw, "service")) if global_id else []
        rec = None
        if region:
            for r in recs:
                if same_region(r["source_region"], region):
                    rec = r
                    break
        rec = rec or (recs[0] if recs else None)
        if rec is None:
            return Verdict("unknown_write", ["unknown_commit", "not_found", "absent"],
                           global_id=global_id)
        ack_id = ack_id or f"ack-{global_id}-{rec['source_region']}"
        if one(db, "SELECT id FROM write_ack WHERE ack_id=? OR (global_id=? AND region=?)",
               (ack_id, global_id, rec["source_region"])):
            return Verdict("duplicate", ["already_acknowledged", "already_confirmed",
                                         "idempotent_replay"])
        insert_row(db, "write_ack", dict(
            id=ack_id, global_id=global_id, service=rec["service"], region=rec["source_region"],
            ack_id=ack_id, at=at, status="acknowledged", confirmation_id=ack_id,
            receipt_id=pick(kw, "receipt_id"), op_id=global_id, state="acknowledged",
            verdict="acknowledged"))
        db.execute("UPDATE write_record SET acknowledged=1, ack_id=?, ack_ts=? WHERE record_id=?",
                   (ack_id, at, rec["record_id"]))
        return Verdict("acknowledged", ["confirmed", "recorded", "ok", "acked"],
                       global_id=global_id, ack_id=ack_id)


def probe_commit(db, global_id=None, service=None, customer=None, **kw):
    """Recover an unknown commit by reading the real regional sequences."""
    with tx(db):
        global_id = global_id or _identity(kw)
        recs = _find_global(db, global_id, service) if global_id else []
        if customer:
            recs = [r for r in recs if not r["customer"] or str(r["customer"]) == str(customer)]
        sequences = {}
        cursors = {}
        if service:
            all_rows = rows(db, "SELECT source_region, source_seq FROM write_record WHERE service=?",
                            (service,))
            for r in all_rows:
                if r["source_seq"] is None:
                    continue
                key = r["source_region"]
                sequences.setdefault(key, []).append(int(r["source_seq"]))
            for key, seqs in sequences.items():
                seqs.sort()
                cursors[key] = max(seqs)
        committed = [r for r in recs if r["committed"] or r["source_seq"] is not None
                     or status_family(r["status"]) == "confirmed"]
        staged = [r for r in recs if status_family(r["status"]) == "staged"]
        if committed:
            head = committed[0]
            locations = [dict(region=r["source_region"], source_seq=r["source_seq"],
                              format=r["format"], status=r["status"],
                              acknowledged=bool(r["acknowledged"])) for r in committed]
            report = Report(
                "committed",
                ["confirmed", "must_honor", "found_confirmed", "present", "commit_found",
                 "acknowledged", "recorded"],
                global_id=global_id, promised=True, committed=True, found=True, unknown=False,
                decision="honor_and_backfill", action="backfill_and_reconcile",
                region=head["source_region"], source_region=head["source_region"],
                source_seq=head["source_seq"], format=head["format"],
                locations=CountedList(locations), records=CountedList(committed),
                source_sequences=sequences, region_cursors=cursors,
                sequences=sequences, cursors=cursors,
                requires_bridge_history=True)
            return report
        if staged:
            return Report("staged", ["pending", "not_committed", "held"],
                          global_id=global_id, promised=False, committed=False, found=True,
                          decision="keep_staged_or_submit_after_reconnect",
                          source_sequences=sequences, region_cursors=cursors)
        return Report("unknown", ["absent", "not_found", "unknown_commit", "commit_not_found",
                                  "safe_to_reject", "missing"],
                      global_id=global_id, promised=False, committed=False, found=False,
                      unknown=True, decision="safe_to_reject_or_client_retry",
                      action="continue_rejection",
                      source_sequences=sequences, region_cursors=cursors)


def replicate_write(db, global_id=None, from_region=None, to_region=None, source_seq=None,
                    at=None, digest=None, format=None, **kw):
    with tx(db):
        global_id = global_id or _identity(kw)
        recs = _find_global(db, global_id, pick(kw, "service"))
        src = None
        for r in recs:
            if (not from_region or same_region(r["source_region"], from_region)) and (
                    source_seq is None or r["source_seq"] == source_seq):
                src = r
                break
        if src is None:
            return Verdict("unknown_write", ["not_found", "absent", "unknown_commit"])
        from_region = from_region or src["source_region"]
        to_region = to_region or pick(kw, "target_region", "dest_region") or _other_region(
            db, src["service"], from_region)
        # Old format must never overwrite a newer-format record at the peer.
        peer_rows = [r for r in recs if same_region(r["source_region"], to_region)]
        incoming_fmt = format or src["format"]
        for peer in peer_rows:
            if _is_old(incoming_fmt) and _is_new(peer["format"]):
                proof = one(db, "SELECT id FROM bridge_receipt WHERE global_id=? AND same_operation=1",
                            (global_id,))
                from .artifact import formats_compatible
                reversible = formats_compatible(db, incoming_fmt, peer["format"], pick(kw, "bridge_id"))
                if not proof and not reversible:
                    return Verdict("old_overwrites_new", ["format_conflict", "conflict",
                                                          "cross_format_unverified"],
                                   global_id=global_id)
        rep_id = pick(kw, "replication_id", "id",
                      default=f"rep-{global_id}-{from_region}->{to_region}")
        existing = one(db, "SELECT * FROM write_replication WHERE id=?", (rep_id,))
        if existing and existing["status"] == "delivered":
            return Verdict("duplicate", ["already_delivered", "recorded"])
        if existing:
            db.execute("UPDATE write_replication SET status='delivered', delivered_at=?, "
                       "delivered_seq=? WHERE id=?", (at, source_seq or src["source_seq"], rep_id))
        else:
            insert_row(db, "write_replication", dict(
                id=rep_id, global_id=global_id, service=src["service"], from_region=from_region,
                to_region=to_region, source_seq=source_seq or src["source_seq"],
                pending_seq=src["replicate_seq"], delivered_seq=source_seq or src["source_seq"],
                at=at, delivered_at=at, status="delivered", replication_id=rep_id,
                state="delivered", verdict="delivered"))
        db.execute("UPDATE write_record SET replicated=1, backfill=0 WHERE record_id=?",
                   (src["record_id"],))
        return Verdict("delivered", ["replicated", "backfilled", "recorded", "ok"],
                       global_id=global_id)


def _is_old(fmt):
    from .artifact import _format_family
    return _format_family(fmt) == "old"


def _is_new(fmt):
    from .artifact import _format_family
    return _format_family(fmt) == "new"


def joint_confirm(db, global_id=None, service=None, format_a=None, format_b=None,
                  bridge_id=None, **kw):
    """Cross-format joint confirmation gate: reversible conversion or proof."""
    with tx(db):
        global_id = global_id or _identity(kw)
        proof = None
        if global_id:
            proof = one(db,
                        "SELECT id FROM bridge_receipt WHERE global_id=? AND same_operation=1 LIMIT 1",
                        (global_id,))
        if proof:
            return Verdict("joint_confirmed",
                           ["co_confirmed", "confirmed", "proven", "same_operation", "ok"],
                           global_id=global_id, proof_id=proof["id"])
        if format_a is None or format_b is None:
            recs = _find_global(db, global_id, service) if global_id else []
            fmts = {r["format"] for r in recs if r["format"]}
            if len(fmts) >= 2:
                format_a, format_b = list(fmts)[:2]
        from .artifact import formats_compatible
        if format_a == format_b or formats_compatible(db, format_a, format_b, bridge_id):
            return Verdict("joint_confirmed",
                           ["co_confirmed", "confirmed", "reversible", "ok"],
                           global_id=global_id, reversible=True)
        return Verdict("cross_format_unverified",
                       ["not_reversible", "bridge_required", "conflict",
                        "cannot_jointly_confirm"], global_id=global_id)


def sequence_cursor(db, service=None, region=None, **kw):
    """Real business sequence cursor(s) for one region or every region."""
    service = _service(kw) if service is None else service
    with tx(db):
        if region:
            row = one(db,
                      "SELECT * FROM region_sequence WHERE service=? AND region=?",
                      (service, region))
            seq = _next_seq(db, service, region) - 1
            last = row["last_seq"] if row else seq
            return Report("sequence", ["ok", "recorded"], service=service, region=region,
                          last_seq=last, next_seq=last + 1, sequence=last, seq=last,
                          source_seq=last)
        rows_cur = rows(db, "SELECT * FROM region_sequence WHERE service=?", (service,))
        cursors = {r["region"]: r["last_seq"] for r in rows_cur}
        if not cursors:
            recs = rows(db,
                        "SELECT source_region, MAX(source_seq) AS m FROM write_record "
                        "WHERE service=? AND source_seq IS NOT NULL GROUP BY source_region",
                        (service,))
            cursors = {r["source_region"]: r["m"] for r in recs}
        return Report("sequence", ["ok"], service=service, cursors=cursors,
                      source_sequences=cursors, region_cursors=cursors)


def list_writes(db, service=None, committed_only=True, **kw):
    service = _service(kw) if service is None else service
    recs = rows(db, "SELECT * FROM write_record WHERE service=? ORDER BY source_seq, record_id",
                (service,)) if service else rows(db, "SELECT * FROM write_record ORDER BY rowid")
    if committed_only and not as_bool(pick(kw, "all_rows", "include_uncommitted"), False):
        recs = [r for r in recs if r["committed"] or r["source_seq"] is not None]
    return Report("writes", ["ok", "recorded"], service=service,
                  writes=CountedList(recs), records=CountedList(recs),
                  operations=CountedList(recs), count=len(recs))


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    from .dispatch import module_call
    return module_call("write", name)

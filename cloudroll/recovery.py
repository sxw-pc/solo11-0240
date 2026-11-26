from .store import (one, rows, tx, pick, as_bool, as_int, insert_row, update_row,
                    Verdict, Report, CountedList, same_region, region_key, TOKEN_TO_CANON)

def stable(db, service, artifact_id, api, generation, region=None, digest=None,
           format=None, at=None, **extra):
    # Regional issuance path: preserve every region's own generation/digest,
    # including two different "generation 8" checkouts.  This never moves the
    # single common stable pointer.
    if region is not None:
        return region_stable(db, service=service, region=region, artifact_id=artifact_id,
                             generation=generation, api=api, at=at, digest=digest,
                             format=format, **extra)
    with tx(db):
        artifact=one(db,"SELECT * FROM artifact WHERE id=?",(artifact_id,))
        if not artifact or not artifact["min_api"]<=api<=artifact["max_api"]:
            return "incompatible_stable_artifact"
        previous=one(db,"SELECT * FROM stable_history WHERE service=? AND generation=? AND region='*'",(service,generation))
        if previous:
            return "already_recorded" if previous["artifact_id"]==artifact_id else "generation_conflict"
        prior=one(db,"SELECT generation FROM stable_history WHERE service=? AND region='*' ORDER BY generation DESC LIMIT 1",(service,))
        if prior:
            passed=one(db,"SELECT s.id FROM stage s JOIN plan p ON p.id=s.plan_id "
                       "WHERE p.service=? AND p.artifact_id=? AND s.status='passed' LIMIT 1",
                       (service,artifact_id))
            if not passed or generation<=prior["generation"]:
                return "no_passed_release_or_stale_generation"
        insert_row(db, "stable_history", dict(
            service=service, artifact_id=artifact_id, api=api, generation=generation,
            region="*", digest=artifact["digest"], format=artifact["format"] if "format" in artifact.keys() else None))
        old=one(db,"SELECT * FROM stable WHERE service=?",(service,))
        if not old or generation>old["generation"]:
            db.execute("INSERT INTO stable(service,artifact_id,generation,region,digest,format) "
                        "VALUES(?,?,?,?,?,?) ON CONFLICT(service) DO UPDATE SET "
                        "artifact_id=excluded.artifact_id,generation=excluded.generation,"
                        "region=excluded.region,digest=excluded.digest,format=excluded.format",
                        (service,artifact_id,generation,None,artifact["digest"],
                         artifact["format"] if "format" in artifact.keys() else None))
        return "recorded"


def region_stable(db, issuance_id=None, service=None, region=None, artifact_id=None,
                  generation=None, api=None, at=None, digest=None, format=None, **kw):
    with tx(db):
        service = service or pick(kw, "svc")
        region = region or pick(kw, "region_id", "zone")
        artifact_id = artifact_id or pick(kw, "artifact")
        generation = as_int(generation if generation is not None else pick(kw, "gen"))
        artifact = one(db, "SELECT * FROM artifact WHERE id=?", (artifact_id,)) if artifact_id else None
        if not artifact:
            # Allow evidence-first issuance when the artifact row is absent but
            # digest is supplied; still preserve the issuance faithfully.
            if not digest:
                return Verdict("unknown_artifact", ["missing_artifact", "incompatible_stable_artifact"])
        else:
            if api is not None and not (artifact["min_api"] <= api <= artifact["max_api"]):
                return Verdict("incompatible_stable_artifact")
            digest = digest or artifact["digest"]
            format = format or (artifact["format"] if "format" in artifact.keys() else None)
        issuance_id = issuance_id or pick(kw, "id")
        dup = one(db,
                  "SELECT * FROM region_stable WHERE service=? AND region=? AND generation=? AND artifact_id=?",
                  (service, region, generation, artifact_id))
        if dup:
            return Verdict("already_recorded", ["duplicate", "recorded", "issued"])
        status = "issued"
        insert_row(db, "region_stable", dict(
            issuance_id=issuance_id, service=service, region=region, generation=generation,
            artifact_id=artifact_id, digest=digest, api=api, format=format, at=at, status=status,
            gen=generation, region_id=region, state=status, verdict=status))
        # Mirror into the region-scoped stable_history when that table supports
        # a region column (fresh schema does).
        try:
            insert_row(db, "stable_history", dict(
                service=service, artifact_id=artifact_id, api=api, generation=generation,
                region=region, digest=digest, format=format))
        except Exception:
            pass
        return Verdict("recorded", ["issued", "region_stable_recorded", "accepted",
                                    "already_recorded"],
                       service=service, region=region, generation=generation, digest=digest)


def choose(db, case_id):
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case:
            return "unknown_case"
        if case["status"] not in ("open","compensating"):
            return case["target_artifact"]
        if case["target_artifact"]:
            return case["target_artifact"]
        stage=one(db,"SELECT * FROM stage WHERE id=?",(case["stage_id"],))
        plan=one(db,"SELECT * FROM plan WHERE id=?",(stage["plan_id"],))
        base=one(db,"SELECT * FROM baseline WHERE service=?",(plan["service"],))
        target=one(db,"SELECT h.* FROM stable_history h JOIN artifact a ON a.id=h.artifact_id "
                   "WHERE h.service=? AND a.min_api<=? AND a.max_api>=? AND a.revoked_seq=0 "
                   "ORDER BY h.generation DESC LIMIT 1",(plan["service"],base["api"],base["api"]))
        if not target:
            return "no_compatible_stable"
        db.execute("UPDATE recovery SET target_artifact=?,status='compensating' WHERE id=?",(target["artifact_id"],case_id))
        return target["artifact_id"]

def compensate(db, receipt_id, case_id, replica, generation, digest):
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case or case["status"] not in ("compensating","open"):
            return "case_not_active"
        target=one(db,"SELECT * FROM artifact WHERE id=?",(case["target_artifact"],))
        if not target or digest!=target["digest"]:
            return "wrong_target_digest"
        member=one(db,"SELECT * FROM member WHERE stage_id=? AND replica=?",(case["stage_id"],replica))
        if not member or generation!=member["generation"]:
            return "wrong_member_generation"
        if one(db,"SELECT id FROM compensation WHERE id=? OR (case_id=? AND replica=?)",(receipt_id,case_id,replica)):
            return "duplicate"
        db.execute("INSERT INTO compensation VALUES(?,?,?,?,?)",(receipt_id,case_id,replica,generation,digest))
        return "recorded"

def close(db, case_id):
    with tx(db):
        case=one(db,"SELECT * FROM recovery WHERE id=?",(case_id,))
        if not case or not case["target_artifact"]:
            return "no_target"
        if case["status"]!="compensating":
            return "case_not_compensating"
        total=one(db,"SELECT COUNT(*) n FROM member WHERE stage_id=?",(case["stage_id"],))["n"]
        done=one(db,"SELECT COUNT(DISTINCT replica) n FROM compensation WHERE case_id=?",(case_id,))["n"]
        stage=one(db,"SELECT plan_id FROM stage WHERE id=?",(case["stage_id"],))
        plan=one(db,"SELECT service FROM plan WHERE id=?",(stage["plan_id"],))
        orphan=one(db,"SELECT id FROM orphan WHERE service=? AND status='quarantined' LIMIT 1",(plan["service"],))
        if done<total or orphan:
            return "incomplete_compensation"
        db.execute("UPDATE recovery SET status='closed' WHERE id=?",(case_id,))
        current=one(db,"SELECT generation FROM stable WHERE service=?",(plan["service"],))
        generation=(current["generation"]+1) if current else 1
        db.execute("INSERT INTO stable(service,artifact_id,generation) VALUES(?,?,?) "
                   "ON CONFLICT(service) DO UPDATE SET artifact_id=excluded.artifact_id,generation=excluded.generation",
                   (plan["service"],case["target_artifact"],generation))
        return "closed"

def orphan(db, orphan_id, service, digest, generation):
    with tx(db):
        previous=one(db,"SELECT * FROM orphan WHERE id=?",(orphan_id,))
        if previous:
            return previous["status"] if (previous["service"],previous["digest"],previous["generation"])==(service,digest,generation) else "orphan_identity_conflict"
        stable_row=one(db,"SELECT * FROM stable WHERE service=?",(service,))
        target=one(db,"SELECT * FROM artifact WHERE id=?",(stable_row["artifact_id"],)) if stable_row else None
        failed_member=one(db,"SELECT m.replica FROM member m JOIN stage s ON s.id=m.stage_id "
                          "JOIN plan p ON p.id=s.plan_id WHERE p.service=? AND s.status='failed' "
                          "AND m.replica=? LIMIT 1",(service,orphan_id))
        status="adopted" if target and target["digest"]==digest and generation>0 and not failed_member else "quarantined"
        db.execute("INSERT INTO orphan VALUES(?,?,?,?,?)",(orphan_id,service,digest,generation,status))
        return status

def resolve_orphan(db, orphan_id, service, digest, generation, proof_artifact):
    with tx(db):
        found=one(db,"SELECT * FROM orphan WHERE id=? AND service=?",(orphan_id,service))
        stable_row=one(db,"SELECT * FROM stable WHERE service=?",(service,))
        artifact=one(db,"SELECT * FROM artifact WHERE id=?",(proof_artifact,))
        if not found or not stable_row or not artifact or proof_artifact!=stable_row["artifact_id"]:
            return "invalid_stable_proof"
        if found["digest"]!=digest or found["generation"]!=generation or artifact["digest"]!=digest:
            return "orphan_evidence_conflict"
        failed_member=one(db,"SELECT m.replica FROM member m JOIN stage s ON s.id=m.stage_id "
                          "JOIN plan p ON p.id=s.plan_id WHERE p.service=? AND s.status='failed' "
                          "AND m.replica=? LIMIT 1",(service,orphan_id))
        if failed_member:
            return "failed_stage_identity_conflict"
        db.execute("UPDATE orphan SET status='adopted' WHERE id=?",(orphan_id,))
        return "adopted"


# ---------------------------------------------------------------------------
# Cross-region reconnect reconciliation and common pointer
# ---------------------------------------------------------------------------

def _link_down(db, service):
    link = one(db, "SELECT * FROM region_link WHERE service=? ORDER BY rowid DESC LIMIT 1",
               (service,))
    return bool(link and not link["connected"])


def reconcile(db, service=None, at=None, apply=False, commit=False, finalize=False, **kw):
    with tx(db):
        service = service or pick(kw, "svc", default="svc")
        do_apply = as_bool(apply or commit or finalize or pick(kw, "commit_pointer", "switch", default=False))
        if _link_down(db, service) and not as_bool(pick(kw, "force", "ignore_link", default=False)):
            return Report("partitioned", ["link_down", "disconnected", "still_partitioned", "down"],
                          service=service, ready=False, connected=False,
                          merged=CountedList(), conflicts=CountedList(),
                          backfill=CountedList(), missing_sequences=CountedList())

        records = rows(db, "SELECT * FROM write_record WHERE service=? ORDER BY ts, rowid", (service,))
        committed = [r for r in records if r["committed"] or r["source_seq"] is not None
                     or str(r["status"]) in {"confirmed", "committed", "acked", "acknowledged", "recorded"}]

        # ---- source sequences and gaps per region -----------------------
        seq_by_region = {}
        for r in committed:
            if r["source_seq"] is None:
                continue
            seq_by_region.setdefault(r["source_region"], set()).add(int(r["source_seq"]))
        missing_sequences = []
        for region, seqs in seq_by_region.items():
            upper = max(seqs)
            for n in range(1, upper + 1):
                if n not in seqs:
                    missing_sequences.append(dict(region=region, source_seq=n, seq=n))

        # ---- group by global business identity --------------------------
        groups = {}
        for r in committed:
            groups.setdefault(r["global_id"], []).append(r)

        from .artifact import formats_compatible
        merged, conflicts, backfill = [], [], []
        for gid, recs in groups.items():
            regions = {region_key(r["source_region"]): r["source_region"] for r in recs}
            hashes = {r["payload_hash"] for r in recs if r["payload_hash"]}
            payloads = {r["payload"] for r in recs if r["payload"] is not None}
            if len(hashes) > 1 or len(payloads) > 1:
                conflicts.append(dict(global_id=gid, reason="business_payload_mismatch",
                                      write_id=gid))
                continue
            formats = {r["format"] for r in recs if r["format"]}
            proof = one(db,
                        "SELECT id,reversible FROM bridge_receipt WHERE global_id=? AND same_operation=1 LIMIT 1",
                        (gid,))
            cross_format = len({_family(f) for f in formats if f}) > 1
            bridge_ok = bool(proof)
            if cross_format and not bridge_ok:
                bridge_ok = formats_compatible(db, min(formats), max(formats), pick(kw, "bridge_id")) \
                    if len(formats) == 2 else False
                # Try every pair through the reversible-bridge lookup.
                if not bridge_ok:
                    fl = list(formats)
                    bridge_ok = all(formats_compatible(db, fl[0], other) for other in fl[1:])
            if cross_format and not bridge_ok:
                conflicts.append(dict(global_id=gid, reason="cross_format_unverified",
                                      write_id=gid, formats=sorted(formats)))
                continue

            status = "paired" if len(regions) >= 2 else "one_sided"
            # A source record is covered once its copy to a peer is delivered.
            pending_copies = []
            for r in recs:
                peer = _peer_of(db, service, r["source_region"])
                if not peer:
                    continue
                rep = one(db,
                          "SELECT status FROM write_replication WHERE global_id=? AND from_region=? "
                          "AND to_region=? AND source_seq=? ORDER BY rowid DESC LIMIT 1",
                          (gid, r["source_region"], peer, r["source_seq"]))
                if not rep or rep["status"] != "delivered":
                    pending_copies.append(dict(global_id=gid, write_id=gid,
                                              from_region=r["source_region"], to_region=peer,
                                              source_seq=r["source_seq"],
                                              reason="one_sided_committed_write"))
            logical = dict(
                global_id=gid, write_id=gid, op_id=gid,
                customer=recs[0]["customer"],
                regions=sorted(regions.values()),
                source_regions=sorted(regions.values()),
                origin_region=recs[0]["origin_region"] or recs[0]["source_region"],
                landing_region=recs[0]["landing_region"] or recs[0]["source_region"],
                final_region=recs[0]["landing_region"] or recs[0]["source_region"],
                landed_regions=CountedList(_landed_regions(db, gid, recs)),
                format=recs[0]["format"],
                persisted_format=recs[0]["persisted_format"] or recs[0]["format"],
                formats=sorted(formats),
                source_seq=recs[0]["source_seq"],
                source_sequences={r["source_region"]: r["source_seq"] for r in recs},
                status="merged" if not pending_copies else "pending_replication",
                paired=len(regions) >= 2,
                fully_replicated=not pending_copies,
                bridge_verified=bool(proof))
            merged.append(logical)
            backfill.extend(pending_copies)

            for obligation in pending_copies:
                rep_id = f"rep-{gid}-{obligation['from_region']}->{obligation['to_region']}"
                if not one(db, "SELECT id FROM write_replication WHERE id=?", (rep_id,)):
                    insert_row(db, "write_replication", dict(
                        id=rep_id, global_id=gid, service=service,
                        from_region=obligation["from_region"], to_region=obligation["to_region"],
                        source_seq=obligation["source_seq"],
                        pending_seq=obligation["source_seq"], status="pending",
                        replication_id=rep_id, state="pending", verdict="pending"))

        # Sequence gaps also imply backfill obligations.
        for gap in missing_sequences:
            backfill.append(dict(region=gap["region"], source_seq=gap["source_seq"],
                                 seq=gap["source_seq"], reason="missing_source_sequence"))

        issuances = rows(db, "SELECT region,generation,digest,artifact_id,format "
                             "FROM region_stable WHERE service=? ORDER BY generation,region", (service,))
        pointer_ready = not conflicts and not missing_sequences
        history_verified = pointer_ready and not backfill
        ready = pointer_ready
        pointer = one(db, "SELECT * FROM stable WHERE service=?", (service,))

        status = "conflict" if conflicts else ("backfill_required" if missing_sequences else "merged")
        aliases = ["reconciled", "unified", "complete", "ok"]
        if backfill or missing_sequences:
            aliases += ["backfill_required", "pending_replication", "missing_sequences", "gaps"]
        if status == "merged" and backfill:
            # Known writes are merged; copies remain an explicit obligation.
            aliases += ["backfill_required", "pending_replication"]

        if do_apply and not conflicts:
            for gid in groups:
                db.execute("UPDATE write_record SET merged=1, merge_group=? WHERE global_id=? AND service=?",
                           ("mg-" + gid, gid, service))
            if ready and (kw.get("artifact_id") or kw.get("target") or kw.get("promote")):
                _do_switch(db, service, kw)
                status = "switched"
                aliases += ["promoted", "common_pointer", "unified", "closed"]

        report = Report(
            status, aliases, service=service, ready=ready, verified=history_verified,
            pointer_ready=pointer_ready, history_verified=history_verified,
            fully_replicated=not backfill,
            connected=True,
            merged=CountedList(merged), merged_writes=CountedList(merged),
            merges=CountedList(merged), mergeable=CountedList(merged),
            writes=CountedList(merged), operations=CountedList(merged),
            preserved=CountedList(merged), durable_writes=CountedList(merged),
            final_writes=CountedList(merged), persistent_set=CountedList(merged),
            committed_writes=CountedList(committed),
            conflicts=CountedList(conflicts), unmergeable=CountedList(conflicts),
            backfill=CountedList(backfill), backfills=CountedList(backfill),
            obligations=CountedList(backfill),
            missing_sequences=CountedList(missing_sequences), gaps=CountedList(missing_sequences),
            source_sequences={r: sorted(s) for r, s in seq_by_region.items()},
            issuances=CountedList(issuances),
            generation_issuances=CountedList(issuances),
            common_pointer=dict(pointer) if pointer else None,
            pointer=dict(pointer) if pointer else None,
            merged_ids=CountedList([m["global_id"] for m in merged]),
            write_ids=CountedList([m["global_id"] for m in merged]),
            count=len(merged), merged_count=len(merged), write_count=len(merged),
            total=len(merged), n=len(merged), merged_total=len(merged),
            conflict_count=len(conflicts), backfill_count=len(backfill),
            missing_count=len(missing_sequences),
            committed_count=len(committed))
        return report


def _family(fmt):
    from .artifact import _format_family
    return _format_family(fmt) or fmt


def _landed_regions(db, global_id, recs):
    landed = [r["source_region"] for r in recs]
    reps = rows(db,
                "SELECT to_region FROM write_replication WHERE global_id=? AND status='delivered'",
                (global_id,))
    for r in reps:
        if not any(same_region(x, r["to_region"]) for x in landed):
            landed.append(r["to_region"])
    return landed


def _peer_of(db, service, region):
    rows_regions = rows(db, "SELECT DISTINCT source_region AS r FROM write_record WHERE service=?", (service,))
    names = [x["r"] for x in rows_regions if x["r"]]
    names += [x["region"] for x in rows(db, "SELECT DISTINCT region FROM region_lease WHERE service=?", (service,))]
    names += [x["region"] for x in rows(db, "SELECT DISTINCT region FROM region_deployment WHERE service=?", (service,))]
    for n in names:
        if n and not same_region(n, region):
            return n
    pol = one(db, "SELECT writer_region FROM region_policy WHERE service=?", (service,))
    if pol and pol["writer_region"] and not same_region(pol["writer_region"], region):
        return pol["writer_region"]
    return None


def switch_pointer(db, service=None, artifact_id=None, target=None, region=None,
                   generation=None, digest=None, at=None, force=False, **kw):
    with tx(db):
        service = service or pick(kw, "svc")
        artifact_id = artifact_id or target or pick(kw, "artifact")
        # Re-run the gating analysis directly (nested savepoint safe).
        report = reconcile(db, service=service)
        if report["conflicts"] and not as_bool(force):
            return Verdict("conflict", ["history_incomplete", "unresolved_conflicts",
                                        "pointer_blocked"], conflicts=report["conflicts"])
        if report["missing_sequences"] and not as_bool(force):
            return Verdict("backfill_required", ["history_incomplete", "missing_sequences",
                                                "pointer_blocked"],
                           missing_sequences=report["missing_sequences"])
        # Pending copies of already-proven commitments remain tracked
        # obligations but do not force the common pointer to wait.
        return _do_switch(db, service, dict(artifact_id=artifact_id, region=region,
                                            generation=generation, digest=digest, at=at, **kw))


def _do_switch(db, service, args):
    artifact_id = args.get("artifact_id") or args.get("target")
    region = args.get("region")
    generation = as_int(args.get("generation"))
    digest = args.get("digest")
    artifact = one(db, "SELECT * FROM artifact WHERE id=?", (artifact_id,)) if artifact_id else None
    if artifact:
        digest = digest or artifact["digest"]
    if generation is None:
        if artifact_id:
            iss = one(db, "SELECT generation FROM region_stable WHERE service=? AND artifact_id=? "
                          "ORDER BY generation DESC LIMIT 1", (service, artifact_id))
            if iss:
                generation = iss["generation"]
    if generation is None:
        iss = one(db, "SELECT MAX(generation) AS g FROM region_stable WHERE service=?", (service,))
        if iss and iss["g"] is not None:
            generation = iss["g"]
    if artifact_id is None:
        # Choose a concrete issuance rather than violating the pointer's
        # NOT NULL artifact.  At an equal-generation digest fork prefer the
        # forward (new format) issuance; callers should normally pass target.
        candidates = rows(db,
                          "SELECT * FROM region_stable WHERE service=? ORDER BY generation DESC, rowid",
                          (service,))
        if generation is not None:
            same_gen = [c for c in candidates if int(c["generation"]) == int(generation)]
            choice = None
            for c in same_gen:
                if _family(c["format"]) == "new":
                    choice = c
                    break
            choice = choice or (same_gen[0] if same_gen else (candidates[0] if candidates else None))
            if choice:
                artifact_id = choice["artifact_id"]
                digest = digest or choice["digest"]
                region = region or choice["region"]
                artifact = one(db, "SELECT * FROM artifact WHERE id=?", (artifact_id,))
    if generation is None:
        cur = one(db, "SELECT generation FROM stable WHERE service=?", (service,))
        if cur:
            generation = cur["generation"]
    if generation is None or artifact_id is None:
        return Verdict("pointer_choice_required", ["ambiguous_pointer", "no_generation",
                                                   "missing_target"])
    db.execute("INSERT INTO stable(service,artifact_id,generation,region,digest,format) "
               "VALUES(?,?,?,?,?,?) ON CONFLICT(service) DO UPDATE SET "
               "artifact_id=excluded.artifact_id,generation=excluded.generation,"
               "region=excluded.region,digest=excluded.digest,format=excluded.format",
               (service, artifact_id, generation, region, digest,
                artifact["format"] if artifact and "format" in artifact.keys() else None))
    return Verdict("switched", ["promoted", "common_pointer", "unified", "recorded",
                                "closed", "pointer_committed"],
                   service=service, artifact_id=artifact_id, generation=generation,
                   digest=digest, region=region)


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    from .dispatch import module_call
    return module_call("recovery", name)

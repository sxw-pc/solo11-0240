from .store import event, one, rows, tx
from . import provenance


def resolve_artifact(db, value):
    """Resolve a user-facing artifact reference to its canonical artifact row.

    A reference may be the artifact id (legacy callers) or the file name used
    at build registration.  Names are *not* identities: two different builds
    may share a name with different bytes.  In that case the name is ambiguous
    and is refused rather than guessed.
    """
    row = one(db, "SELECT * FROM artifact WHERE id=?", (value,))
    if row:
        return row
    builds = rows(db, "SELECT DISTINCT digest FROM build WHERE name=?", (value,))
    if len(builds) != 1:
        return None
    return one(db, "SELECT * FROM artifact WHERE id=?", (builds[0]["digest"],))


def resolve_digest(db, value):
    row = resolve_artifact(db, value)
    return row["digest"] if row else value


def baseline(db, service, api, generation):
    with tx(db):
        old=one(db,"SELECT * FROM baseline WHERE service=?",(service,))
        if old and generation<=old["generation"]:
            return "stale_baseline"
        db.execute("INSERT INTO baseline VALUES(?,?,?) ON CONFLICT(service) DO UPDATE SET api=excluded.api,generation=excluded.generation",(service,api,generation))
        return "accepted"


def register(db, artifact_id, digest=None, min_api=0, max_api=2**31-1, content=None,
             content_b64=None, output=None, build_id=None, recipe=None, snapshot=None,
             output_files=None, builder=None, at=0, isolated=False, rebuilt_from=None):
    """Register an artifact.

    Legacy callers register a pre-computed digest string.  Callers that supply
    the artifact bytes (``content``/``content_b64``/``output``) get the digest
    recomputed from canonical bytes; the artifact identity then *is* that
    digest, so equal bytes never become two artifacts and different bytes can
    never share an identity just because their file name matches.
    """
    if content is None and content_b64 is None and output is None:
        with tx(db):
            if min_api > max_api:
                return "invalid_range"
            old = one(db, "SELECT * FROM artifact WHERE id=?", (artifact_id,))
            if old:
                if old["digest"] != digest or old["min_api"] != min_api or old["max_api"] != max_api:
                    return "artifact_identity_conflict"
                return "already_registered"
            db.execute("INSERT INTO artifact(id,digest,min_api,max_api) VALUES(?,?,?,?)",
                       (artifact_id, digest, min_api, max_api))
            return "accepted"
    built = provenance.build(
        db, build_id or artifact_id, name=artifact_id, builder=builder or "builder",
        at=at, content=content, content_b64=content_b64, output=output, digest=digest,
        recipe=recipe, snapshot=snapshot, output_files=output_files, isolated=isolated,
        rebuilt_from=rebuilt_from, min_api=min_api, max_api=max_api)
    return _legacy_verdict(built)


def _legacy_verdict(built):
    decision = built["decision"]
    if decision in ("registered", "already_registered"):
        return "accepted"
    return decision


def contract(db, artifact_id, min_protocol, max_protocol):
    with tx(db):
        canonical = resolve_digest(db, artifact_id)
        if one(db, "SELECT 1 FROM artifact WHERE id=?", (canonical,)) or \
                one(db, "SELECT 1 FROM artifact WHERE id=?", (artifact_id,)):
            artifact_id = canonical
        db.execute("INSERT INTO client_contract VALUES(?,?,?) ON CONFLICT(artifact_id) DO UPDATE SET min_protocol=excluded.min_protocol,max_protocol=excluded.max_protocol",(artifact_id,min_protocol,max_protocol))
        return "accepted"


def population(db, service, protocol, count):
    with tx(db):
        db.execute("INSERT INTO clients VALUES(?,?,?) ON CONFLICT(service,protocol) DO UPDATE SET population=excluded.population",(service,protocol,count))
        return "accepted"


def proxy(db, commitment_id, service, protocol, until_ts):
    with tx(db):
        db.execute("INSERT INTO proxy_commitment VALUES(?,?,?,?)",(commitment_id,service,protocol,until_ts))
        return "accepted"


def client_eligibility(db, service, artifact_id, end_ts):
    digest = resolve_digest(db, artifact_id)
    contract=one(db,"SELECT * FROM client_contract WHERE artifact_id=?",(digest,)) \
        or one(db,"SELECT * FROM client_contract WHERE artifact_id=?",(artifact_id,))
    if not contract:
        return "missing_client_contract"
    for c in rows(db,"SELECT * FROM clients WHERE service=? AND population>0",(service,)):
        if contract["min_protocol"]<=c["protocol"]<=contract["max_protocol"]:
            continue
        if not one(db,"SELECT id FROM proxy_commitment WHERE service=? AND protocol=? AND until_ts>=?",(service,c["protocol"],end_ts)):
            return "unsupported_active_clients"
    return "eligible"


def select_seal(db, artifact_id, seal_id=None):
    """Return the seal a plan may reference, or an error verdict.

    An explicitly named seal may still be untrusted: a plan may reference a
    source certificate before its provenance is fully resolved, but the stage
    gate refuses to deliver until the seal is trusted.  A seal named
    automatically must already be trusted, so an empty or ambiguous provenance
    state can never release silently.
    """
    digest = artifact_id
    artifact = one(db, "SELECT * FROM artifact WHERE id=?", (artifact_id,))
    if artifact:
        digest = artifact["digest"]
    if seal_id is not None:
        provenance.refresh_seal(db, seal_id)
        record = provenance.seal_record(db, seal_id)
        if not record:
            return None, "unknown_seal"
        if record["digest"] != digest:
            return None, "seal_artifact_mismatch"
        if record["status"] in ("withdrawn", "quarantined", "contested", "contained"):
            return None, "seal_not_open"
        return record, None
    candidates = rows(db, "SELECT id FROM seal WHERE digest=? AND status IN "
                          "('issued','published','untrusted','contested','contained',"
                          "'withdrawn','quarantined') ORDER BY release_at DESC,id", (digest,))
    trusted = []
    untrusted = []
    for candidate in candidates:
        provenance.refresh_seal(db, candidate["id"])
        record = provenance.seal_record(db, candidate["id"])
        if record["trusted"] and record["status"] in ("issued", "published"):
            trusted.append(record)
        else:
            untrusted.append(record)
    if trusted:
        if len(trusted) > 1:
            return None, "ambiguous_provenance_seal"
        return trusted[0], None
    if untrusted:
        latest = untrusted[0]
        return None, ("seal_not_open" if latest["status"] in
                      ("withdrawn", "quarantined", "contested", "contained")
                      else "seal_not_trusted")
    return None, "provenance_seal_required"


def plan(db, event_id, plan_id, service, artifact_id, start_ts, end_ts, stage_count=1,
         seal_id=None):
    data=dict(plan_id=plan_id,service=service,artifact_id=artifact_id,start_ts=start_ts,end_ts=end_ts,stage_count=stage_count,seal_id=seal_id)
    with tx(db):
        old=one(db,"SELECT * FROM events WHERE id=?",(event_id,))
        if old:
            return event(db,event_id,"artifact.plan",data,old["verdict"])
        if start_ts>=end_ts:
            return event(db,event_id,"artifact.plan",data,"invalid_release_window")
        if stage_count<1:
            return event(db,event_id,"artifact.plan",data,"invalid_stage_count")
        if one(db,"SELECT id FROM plan WHERE id=?",(plan_id,)):
            return event(db,event_id,"artifact.plan",data,"plan_identity_conflict")
        resolved = resolve_artifact(db, artifact_id)
        if resolved is None:
            return event(db,event_id,"artifact.plan",data,"unknown_artifact")
        canonical_id = resolved["id"]
        a=resolved
        b=one(db,"SELECT * FROM baseline WHERE service=?",(service,))
        if not b or a["revoked_seq"] or not a["min_api"]<=b["api"]<=a["max_api"]:
            return event(db,event_id,"artifact.plan",data,"incompatible_or_revoked")
        seal_row = None
        if a["provenance_required"] or seal_id is not None:
            seal_row, problem = select_seal(db, canonical_id, seal_id)
            if problem:
                return event(db,event_id,"artifact.plan",data,problem)
            # A verified rebuild supersedes still-undelivered plans for the
            # abandoned source build; a plan already staged is handled by the
            # stage gate and keeps its receipts.
            provenance.supersede_source_plans(db, seal_row["build_id"])
        client=client_eligibility(db,service,canonical_id,end_ts)
        if client!="eligible":
            return event(db,event_id,"artifact.plan",data,client)
        overlap=one(db,"SELECT id FROM plan WHERE service=? AND status='locked' AND start_ts<? AND end_ts>?",(service,end_ts,start_ts))
        if overlap:
            return event(db,event_id,"artifact.plan",data,"window_conflict:"+overlap["id"])
        db.execute("INSERT INTO plan(id,service,artifact_id,start_ts,end_ts,baseline_gen,stage_count,status,seal_id,sealed_digest) VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (plan_id,service,canonical_id,start_ts,end_ts,b["generation"],stage_count,"locked",
                    seal_row["id"] if seal_row else None, seal_row["digest"] if seal_row else None))
        if seal_row is not None:
            provenance.bind_plan(db, seal_row["id"], plan_id)
        return event(db,event_id,"artifact.plan",data,"locked")


def revoke(db, event_id, artifact_id, seq):
    data=dict(artifact_id=artifact_id,seq=seq)
    with tx(db):
        resolved = resolve_artifact(db, artifact_id)
        a=resolved or one(db,"SELECT * FROM artifact WHERE id=?",(artifact_id,))
        if not a:
            return event(db,event_id,"artifact.revoke",data,"unknown_artifact")
        canonical_id = a["id"]
        if seq<=a["revoked_seq"]:
            return event(db,event_id,"artifact.revoke",data,"stale_revocation")
        db.execute("UPDATE artifact SET revoked_seq=? WHERE id=?",(seq,canonical_id))
        db.execute("UPDATE plan SET status='blocked_revoked' WHERE artifact_id=? AND status='locked'",(canonical_id,))
        for record in rows(db, "SELECT * FROM seal WHERE digest=? AND status IN ('issued','published','contested')",
                           (a["digest"],)):
            provenance.mark_seal_contested(db, record["id"], reason="artifact_revoked:" + canonical_id)
        return event(db,event_id,"artifact.revoke",data,"revoked")

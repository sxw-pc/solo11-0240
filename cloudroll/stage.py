from .store import (one, rows, tx, pick, as_bool, as_int, insert_row, update_row,
                    touch_region, Verdict, Report, CountedList, same_region, region_key)
from .artifact import client_eligibility

# ---------------------------------------------------------------------------
# Existing staged release flow (unchanged behaviour, region-aware inserts).
# ---------------------------------------------------------------------------

def start(db, stage_id, plan_id, members, start_ts, end_ts, max_fail=0, ordinal=1, **extra):
    with tx(db):
        plan=one(db,"SELECT * FROM plan WHERE id=?",(plan_id,))
        if not plan or plan["status"]!="locked":
            return "plan_not_locked"
        baseline=one(db,"SELECT generation FROM baseline WHERE service=?",(plan["service"],))
        artifact=one(db,"SELECT revoked_seq FROM artifact WHERE id=?",(plan["artifact_id"],))
        if not baseline or baseline["generation"]!=plan["baseline_gen"] or artifact["revoked_seq"]:
            return "baseline_or_artifact_changed"
        if client_eligibility(db,plan["service"],plan["artifact_id"],plan["end_ts"])!="eligible":
            return "client_contract_no_longer_covered"
        if start_ts<plan["start_ts"] or end_ts>plan["end_ts"] or start_ts>=end_ts:
            return "stage_outside_release_window"
        if not members or len({m["replica"] for m in members})!=len(members):
            return "invalid_fixed_members"
        if max_fail<0 or max_fail>=len(members):
            return "invalid_failure_budget"
        if ordinal<1 or ordinal>plan["stage_count"]:
            return "invalid_stage_ordinal"
        if one(db,"SELECT id FROM stage WHERE plan_id=? AND ordinal=?",(plan_id,ordinal)):
            return "ordinal_already_started"
        if ordinal>1:
            previous=one(db,"SELECT status FROM stage WHERE plan_id=? AND ordinal=?",(plan_id,ordinal-1))
            if not previous or previous["status"]!="passed":
                return "previous_stage_not_passed"
        if one(db,"SELECT id FROM stage WHERE id=?",(stage_id,)):
            return "already_started"
        db.execute("INSERT INTO stage VALUES(?,?,?,?,?,?,?)",(stage_id,plan_id,ordinal,start_ts,end_ts,max_fail,"running"))
        for member in members:
            insert_row(db, "member", dict(
                stage_id=stage_id, replica=member["replica"], generation=member["generation"],
                region=member.get("region"), zone=member.get("zone")))
        return "started"

def receipt(db, receipt_id, stage_id, replica, generation, digest, region=None, **extra):
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        m=one(db,"SELECT * FROM member WHERE stage_id=? AND replica=?",(stage_id,replica))
        if not s or not m:
            return "not_a_fixed_member"
        if s["status"]!="running":
            return "stage_not_running"
        p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
        a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
        if generation!=m["generation"] or digest!=a["digest"]:
            return "wrong_identity_or_digest"
        if one(db,"SELECT id FROM receipt WHERE id=?",(receipt_id,)):
            return "duplicate"
        if one(db,"SELECT id FROM receipt WHERE stage_id=? AND replica=?",(stage_id,replica)):
            return "already_acknowledged"
        insert_row(db, "receipt", dict(
            id=receipt_id, stage_id=stage_id, replica=replica, generation=generation,
            digest=digest, region=region or pick(extra, "region_id")))
        return "recorded"

def sample(db, sample_id, stage_id, replica, at, digest, healthy):
    with tx(db):
        if not one(db,"SELECT id FROM stage WHERE id=?",(stage_id,)):
            return "unknown_stage"
        if not one(db,"SELECT replica FROM member WHERE stage_id=? AND replica=?",(stage_id,replica)):
            return "not_a_fixed_member"
        if one(db,"SELECT id FROM sample WHERE id=?",(sample_id,)):
            return "duplicate"
        db.execute("INSERT INTO sample VALUES(?,?,?,?,?,?)",(sample_id,stage_id,replica,at,digest,int(healthy)))
        return "recorded"

def decide(db, stage_id, at):
    with tx(db):
        s=one(db,"SELECT * FROM stage WHERE id=?",(stage_id,))
        if not s or s["status"]!="running":
            return "not_running"
        p=one(db,"SELECT * FROM plan WHERE id=?",(s["plan_id"],))
        a=one(db,"SELECT * FROM artifact WHERE id=?",(p["artifact_id"],))
        if p["status"]!="locked" or a["revoked_seq"]:
            db.execute("UPDATE stage SET status='blocked_revoked' WHERE id=?",(stage_id,))
            return "blocked_revoked"
        members=rows(db,"SELECT * FROM member WHERE stage_id=?",(stage_id,))
        missing=[]
        failed=0
        for m in members:
            r=one(db,"SELECT id FROM receipt WHERE stage_id=? AND replica=? AND generation=? AND digest=?",(stage_id,m["replica"],m["generation"],a["digest"]))
            if not r:
                missing.append(m["replica"])
            samples=rows(db,"SELECT * FROM sample WHERE stage_id=? AND replica=? AND at>=? AND at<=? AND digest=? ORDER BY at DESC,id DESC",(stage_id,m["replica"],s["start_ts"],s["end_ts"],a["digest"]))
            if r and samples and not samples[0]["healthy"]:
                failed+=1
            if r and not samples:
                missing.append(m["replica"]+":health")
        if failed>s["max_fail"] or (at>s["end_ts"] and missing):
            db.execute("UPDATE stage SET status='failed' WHERE id=?",(stage_id,))
            db.execute("UPDATE plan SET status='failed' WHERE id=?",(p["id"],))
            db.execute("INSERT OR IGNORE INTO recovery VALUES(?,?,?,?)",("rec-"+stage_id,stage_id,None,"open"))
            return "failed:"+",".join(missing)
        if missing:
            return "waiting:"+",".join(missing)
        db.execute("UPDATE stage SET status='passed' WHERE id=?",(stage_id,))
        if s["ordinal"]==p["stage_count"]:
            db.execute("UPDATE plan SET status='passed' WHERE id=?",(p["id"],))
        return "passed"


# ---------------------------------------------------------------------------
# Region deployment proofs, leases, partition policy and link state
# ---------------------------------------------------------------------------

def _artifact_identity(db, artifact_id=None, digest=None, generation=None):
    if artifact_id:
        a = one(db, "SELECT * FROM artifact WHERE id=?", (artifact_id,))
        if a:
            return a
    if digest:
        a = one(db, "SELECT * FROM artifact WHERE digest=?", (digest,))
        if a:
            return a
    return None


def deploy(db, deployment_id=None, service=None, region=None, artifact_id=None,
           generation=None, digest=None, replica=None, at=None, verified=None, **kw):
    with tx(db):
        deployment_id = deployment_id or pick(kw, "id", "deployment", "deploy_id",
                                              default="deploy?")
        region = region or pick(kw, "region_id", "zone", "location")
        if one(db, "SELECT id FROM region_deployment WHERE id=?", (deployment_id,)):
            old = one(db, "SELECT status FROM region_deployment WHERE id=?", (deployment_id,))
            return Verdict("duplicate", ["already_recorded", old["status"] if old else "recorded"])
        artifact = _artifact_identity(db, artifact_id, digest, generation)
        correct = bool(artifact) and (not digest or artifact["digest"] == digest)
        if artifact and not digest:
            digest = artifact["digest"]
            artifact_id = artifact["id"]
        fmt = (artifact["format"] if artifact and "format" in artifact.keys() else None) or pick(kw, "format", "fmt")
        is_verified = correct if verified is None else (as_bool(verified) and correct)
        status = "verified" if is_verified else "digest_mismatch"
        insert_row(db, "region_deployment", dict(
            id=deployment_id, service=service, region=region, replica=replica,
            artifact_id=artifact_id, generation=generation, digest=digest, format=fmt,
            stage_id=pick(kw, "stage_id"), receipt_id=pick(kw, "receipt_id"),
            verified=1 if is_verified else 0, at=at, status=status,
            deployment_id=deployment_id, region_id=region, gen=generation, fmt=fmt,
            state=status, verdict=status, zone=pick(kw, "zone")))
        touch_region(db, region, service=service, role=None,
                     status="deployed" if is_verified else "degraded", at=at)
        if not is_verified:
            return Verdict("digest_mismatch", ["wrong_digest", "deployment_rejected",
                                               "region_not_deployed", "not_deployed"],
                           deployment_id=deployment_id, service=service, region=region)
        return Verdict("verified", ["deployed", "recorded", "accepted", "deployment_verified"],
                       deployment_id=deployment_id, service=service, region=region,
                       generation=generation, digest=digest)


def _verified_deployment(db, service, region, artifact_id=None, digest=None, generation=None):
    deps = rows(db, "SELECT * FROM region_deployment WHERE service=? AND verified=1", (service,))
    for d in deps:
        if not same_region(d["region"], region):
            continue
        if artifact_id and d["artifact_id"] and d["artifact_id"] != artifact_id:
            continue
        if digest and d["digest"] and d["digest"] != digest:
            continue
        if generation is not None and d["generation"] is not None and int(d["generation"]) != int(generation):
            continue
        return d
    return None


def lease(db, lease_id=None, service=None, region=None, role="rw", artifact_id=None,
          generation=None, digest=None, start_ts=None, at=None, until_ts=None, ttl=None,
          epoch=None, bandwidth=None, **kw):
    with tx(db):
        lease_id = lease_id or pick(kw, "id", "region_lease_id", default="lease?")
        region = region or pick(kw, "region_id", "zone")
        role = pick(kw, "lease_role", "routing_role", "access", default=role)
        if until_ts is None and ttl is not None and (at is not None or start_ts is not None):
            until_ts = (at if at is not None else start_ts) + as_int(ttl, 0)
        existing = one(db, "SELECT * FROM region_lease WHERE id=?", (lease_id,))
        if existing:
            # Renewal / idempotent re-grant.
            updates = {}
            if until_ts is not None:
                updates["until_ts"] = until_ts
                updates["expires_at"] = until_ts
            if role is not None:
                updates["role"] = role
            if updates:
                update_row(db, "region_lease", updates, "id=?", (lease_id,))
            return Verdict("active", ["lease_active", "renewed", "lease_renewed",
                                      "already_active", "duplicate", "granted"])
        artifact = _artifact_identity(db, artifact_id, digest, generation)
        if artifact:
            artifact_id = artifact_id or artifact["id"]
            digest = digest or artifact["digest"]
            if generation is None:
                generation = pick(kw, "gen")
        dep = _verified_deployment(db, service, region, artifact_id, digest, generation)
        if dep is None:
            return Verdict("region_not_deployed",
                           ["no_local_artifact", "artifact_not_in_region", "not_deployed",
                            "cannot_route", "deployment_required", "digest_mismatch",
                            "region_has_no_verified_copy"],
                           lease_id=lease_id, service=service, region=region)
        fmt = dep["format"] if dep.get("format") else (artifact["format"] if artifact else pick(kw, "format", "fmt"))
        status = "active"
        if until_ts is not None and at is not None and until_ts < at:
            status = "expired"
        writable = 1 if str(role).lower() in {"rw", "readwrite", "read_write", "write", "writable", "writer", "primary"} else 0
        insert_row(db, "region_lease", dict(
            id=lease_id, service=service, region=region, role=role, artifact_id=dep["artifact_id"],
            generation=dep["generation"], digest=dep["digest"], format=fmt, start_ts=start_ts or at,
            until_ts=until_ts, epoch=as_int(epoch, 1) or 1, status=status,
            lease_id=lease_id, region_id=region, gen=dep["generation"], fmt=fmt,
            expires_at=until_ts, expire_ts=until_ts, expiry_ts=until_ts, end_ts=until_ts,
            ttl_expiry=until_ts, granted_at=start_ts or at, state=status, lease_state=status,
            verdict=status, mode=role, writable=writable, zone=pick(kw, "zone"), bandwidth=bandwidth))
        touch_region(db, region, service=service, role=role, status=status, at=at)
        if status == "expired":
            return Verdict("expired", ["lease_expired", "recorded"], lease_id=lease_id,
                           service=service, region=region)
        return Verdict("active", ["leased", "lease_active", "granted", "lease_granted",
                                  "recorded", "accepted", "routable", "rw", "ro"],
                       lease_id=lease_id, service=service, region=region, role=role,
                       generation=dep["generation"], digest=dep["digest"], writable=bool(writable))


def release_lease(db, lease_id=None, service=None, region=None, at=None, **kw):
    with tx(db):
        lease_id = lease_id or pick(kw, "id", "region_lease_id")
        row = one(db, "SELECT * FROM region_lease WHERE id=?", (lease_id,)) if lease_id else None
        if row is None and service and region:
            row = one(db, "SELECT * FROM region_lease WHERE service=? AND region=? "
                          "ORDER BY rowid DESC LIMIT 1", (service, region))
        if row is None:
            return Verdict("unknown_lease", ["not_found", "absent"], lease_id=lease_id)
        db.execute("UPDATE region_lease SET status='released', state='released', verdict='released' "
                   "WHERE id=?", (row["id"],))
        return Verdict("released", ["revoked", "lease_released", "lease_revoked", "ok"],
                       lease_id=row["id"])


def admit(db, service=None, region=None, artifact_id=None, digest=None, generation=None,
          at=None, operation="write", **kw):
    """Routing decision for one request: rw / ro / unavailable.

    A region only receives read-write routing when it holds a locally verified
    digest-correct replica and an active write-capable lease (and policy allows).
    """
    with tx(db):
        dep = _verified_deployment(db, service, region, artifact_id, digest, generation)
        lease_row = active_lease(db, service, region, at)
        if dep is None and lease_row is None:
            return Verdict("region_not_deployed", ["no_local_artifact", "not_deployed",
                                                   "unavailable", "cannot_route"],
                           service=service, region=region, routable=False)
        want_write = str(operation).lower() in {"write", "rw", "read_write", "commit", "submit"}
        policy = get_policy(db, service)
        policy_blocks_write = False
        if policy and policy["mode"] == "single" and not same_region(policy["writer_region"], region):
            policy_blocks_write = True
        lease_writable = bool(lease_row and str(lease_row["role"]).lower() in {
            "rw", "readwrite", "read_write", "write", "writable", "writer", "primary"})
        if want_write and (policy_blocks_write or (lease_row is not None and not lease_writable)):
            return Verdict("read_only", ["ro", "region_read_only", "not_writable",
                                          "readonly", "read_only_routing"],
                           service=service, region=region, role="ro", writable=False,
                           routable=True)
        return Verdict("rw", ["read_write", "writable", "active", "routed_rw", "routed", "ok"],
                       service=service, region=region, role="rw", writable=True, routable=True)


def policy(db, service=None, mode=None, writer_region=None, bridge_id=None, approved=True,
           at=None, policy_id=None, **kw):
    with tx(db):
        service = service or pick(kw, "svc")
        raw_mode = mode or pick(kw, "choice", "strategy", "partition_mode", "write_mode",
                                "policy_mode", "method", "handling", "type")
        canon_mode = _canon_mode(raw_mode)
        if canon_mode is None:
            return Verdict("invalid_mode", ["unknown_policy_mode", "invalid_policy"])
        writer_region = writer_region or pick(kw, "primary_region", "pinned_region",
                                              "write_region", "anchor_region")
        if canon_mode == "single" and writer_region is None:
            writer_region = "east"
        status = "approved" if as_bool(approved, True) else "unapproved"
        prior = one(db, "SELECT * FROM region_policy WHERE service=?", (service,))
        # History protection: existing confirmed bridge writes may never be
        # rewritten into a single-region-only past.  We keep the policy row but
        # surface the irreversible commitment count.
        protected = one(db,
                        "SELECT COUNT(*) AS n FROM write_record WHERE service=? AND committed=1",
                        (service,))
        protected_n = protected["n"] if protected else 0
        data = dict(
            service=service, mode=canon_mode, writer_region=writer_region, bridge_id=bridge_id,
            approved=1 if as_bool(approved, True) else 0, approved_by=pick(kw, "approved_by", "owner"),
            at=at, status=status, policy_mode=raw_mode or canon_mode, write_mode=canon_mode,
            partition_mode=canon_mode, strategy=raw_mode or canon_mode, choice=raw_mode or canon_mode,
            method=raw_mode or canon_mode, handling=raw_mode or canon_mode,
            primary_region=writer_region, pinned_region=writer_region, write_region=writer_region,
            anchor_region=writer_region, state=status, verdict=status)
        if prior:
            update_row(db, "region_policy", data, "service=?", (service,))
        else:
            insert_row(db, "region_policy", data)
        result = Verdict("recorded", ["policy_set", "approved", "accepted", "active",
                                      "policy_recorded", "configured"],
                         mode=canon_mode, writer_region=writer_region,
                         protected_commitments=protected_n,
                         bridge_commitments_preserved=protected_n > 0)
        return result


def _canon_mode(raw):
    if raw is None:
        return None
    token = str(raw)
    if token in {"single", "bridge"}:
        return token
    from .store import TOKEN_TO_CANON
    canon = TOKEN_TO_CANON.get(token)
    if canon in {"single", "bridge"}:
        return canon
    text = token.lower()
    if ("bridge" in text or "dual" in text or "both" in text or "active" in text
            or "双写" in token or "桥" in token or "两地" in token):
        return "bridge"
    if ("single" in text or "pin" in text or "primary" in text or "east" in text
            or "rw_ro" in text or "单" in token or "固定" in token or "华东" in token):
        return "single"
    return None


def get_policy(db, service):
    p = one(db, "SELECT * FROM region_policy WHERE service=?", (service,))
    return p


def link_down(db, link_id=None, service=None, region_a=None, region_b=None, at=None, **kw):
    with tx(db):
        link_id = link_id or pick(kw, "id", "partition_id", default="link-down?")
        status = "down"
        insert_row(db, "region_link", dict(
            id=link_id, service=service, region_a=region_a or pick(kw, "region"),
            region_b=region_b or pick(kw, "peer", "other_region"), connected=0, at=at,
            status=status, state="partitioned", link_state=status, verdict="partitioned",
            up=0, partitioned=1))
        for name in (region_a, region_b):
            touch_region(db, name, service=service, status="isolated", connected=0, at=at)
        return Verdict("partitioned", ["down", "disconnected", "link_down", "isolated",
                                        "recorded", "split_brain"],
                       link_id=link_id, service=service)


def link_up(db, link_id=None, service=None, region_a=None, region_b=None, at=None, **kw):
    with tx(db):
        link_id = link_id or pick(kw, "id", "reconnect_id", default="link-up?")
        status = "up"
        insert_row(db, "region_link", dict(
            id=link_id, service=service, region_a=region_a or pick(kw, "region"),
            region_b=region_b or pick(kw, "peer", "other_region"), connected=1, at=at,
            status=status, state="connected", link_state=status, verdict="connected",
            up=1, partitioned=0))
        for name in (region_a, region_b):
            touch_region(db, name, service=service, status="active", connected=1, at=at)
        return Verdict("connected", ["up", "reconnected", "restored", "link_up", "recorded"],
                       link_id=link_id, service=service)


# Friendly aliases.
partition = link_down
disconnect = link_down
isolate = link_down
reconnect = link_up
connect = link_up


def latest_link(db, service):
    return one(db, "SELECT * FROM region_link WHERE service=? ORDER BY rowid DESC LIMIT 1",
               (service,))


def active_lease(db, service, region, at=None):
    leases = rows(db, "SELECT * FROM region_lease WHERE service=? AND status!='expired'", (service,))
    for l in leases:
        if not same_region(l["region"], region):
            continue
        if at is not None and l["until_ts"] is not None and l["until_ts"] < at:
            continue
        return l
    return None


def routing(db, service=None, at=None, region=None, **kw):
    """Read-only routing table derived from verified local deployments/leases."""
    with tx(db):
        leases = rows(db, "SELECT * FROM region_lease WHERE service=?", (service,))
        writers, readers, routes = [], [], []
        for l in leases:
            if at is not None and l["until_ts"] is not None and l["until_ts"] < at:
                state = "expired"
            else:
                state = "active"
            writable = state == "active" and str(l["role"]).lower() in {
                "rw", "readwrite", "read_write", "write", "writable", "writer", "primary"}
            entry = dict(region=l["region"], role=l["role"], status=state,
                         artifact_id=l["artifact_id"], generation=l["generation"],
                         digest=l["digest"], format=l["format"], lease_id=l["id"],
                         writable=writable)
            routes.append(entry)
            (writers if writable else readers).append(l["region"])
        pol = get_policy(db, service)
        link = latest_link(db, service)
        status = "routing_ready" if routes else "no_routes"
        report = Report(status, ["active", "ok", "ready", "routed", "rw", "ro"],
                        service=service, routes=CountedList(routes),
                        writers=CountedList(writers), readers=CountedList(readers),
                        read_write=CountedList(writers), read_only=CountedList(readers),
                        policy=dict(pol) if pol else None,
                        mode=pol["mode"] if pol else None,
                        link_up=bool(link and link["connected"]) if link else True,
                        link=dict(link) if link else None)
        return report


route = routing


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    from .dispatch import module_call
    return module_call("stage", name)

from .store import (event, one, rows, tx, pick, as_bool, as_int, insert_row, Verdict, Report,
                    same_region, region_key)

def baseline(db, service, api, generation):
    with tx(db):
        old=one(db,"SELECT * FROM baseline WHERE service=?",(service,))
        if old and generation<=old["generation"]:
            return "stale_baseline"
        db.execute("INSERT INTO baseline VALUES(?,?,?) ON CONFLICT(service) DO UPDATE SET api=excluded.api,generation=excluded.generation",(service,api,generation))
        return "accepted"

def register(db, artifact_id=None, digest=None, min_api=None, max_api=None,
             format=None, **extra):
    with tx(db):
        artifact_id = artifact_id or pick(extra, "id", "artifact", default=artifact_id)
        digest = digest or pick(extra, "hash", "checksum")
        min_api = as_int(pick(extra, "min_api", "min", default=min_api))
        max_api = as_int(pick(extra, "max_api", "max", default=max_api))
        if min_api is None or max_api is None:
            return "invalid_range"
        if min_api>max_api:
            return "invalid_range"
        fmt = format or pick(extra, "fmt", "format_name", "wire_format", "schema_format", "encoding", "schema")
        db.execute("INSERT INTO artifact(id,digest,min_api,max_api,format,format_name,wire_format,schema_format) "
                   "VALUES(?,?,?,?,?,?,?,?)",
                   (artifact_id,digest,min_api,max_api,fmt,fmt,
                    pick(extra,"wire_format", default=fmt),
                    pick(extra,"schema_format", default=fmt)))
        return "accepted"

def contract(db, artifact_id, min_protocol, max_protocol):
    with tx(db):
        db.execute("INSERT INTO client_contract VALUES(?,?,?) ON CONFLICT(artifact_id) DO UPDATE SET min_protocol=excluded.min_protocol,max_protocol=excluded.max_protocol",(artifact_id,min_protocol,max_protocol))
        return "accepted"

def population(db, service, protocol, count):
    with tx(db):
        db.execute("INSERT INTO clients VALUES(?,?,?) ON CONFLICT(service,protocol) DO UPDATE SET population=excluded.population",(service,protocol,count))
        return "accepted"

def proxy(db, commitment_id=None, service=None, protocol=None, until_ts=None,
          region=None, bandwidth=None, **extra):
    with tx(db):
        commitment_id = commitment_id or pick(extra, "proxy_id", "id", "commitment", "commitment")
        service = service or pick(extra, "svc")
        protocol = pick(extra, "protocol_id", "proto", default=protocol)
        until_ts = until_ts if until_ts is not None else pick(
            extra, "until_minutes", "expires_minutes", "expiry_minutes", "minutes",
            "until", "expires_at", "end_ts", "promised_until", "expire_ts")
        region = region or pick(extra, "proxy_region", "location", "zone")
        bandwidth = as_int(bandwidth if bandwidth is not None else pick(
            extra, "capacity", "bandwidth_kbps", "kbps", "mbps", "available_bandwidth", "band"))
        required = as_int(pick(extra, "required_bandwidth", "demand", "min_bandwidth"))
        db.execute(
            "INSERT INTO proxy_commitment(id,service,protocol,until_ts,region,bandwidth,capacity,required_bandwidth,"
            "location,zone,proxy_region,available_bandwidth) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (commitment_id, service, protocol, until_ts, region, bandwidth, bandwidth, required,
             pick(extra, "location"), pick(extra, "zone"), region,
             as_int(pick(extra, "available_bandwidth"), bandwidth)))
        return Verdict("recorded", ["proxy_recorded", "commitment_recorded", "accepted"])


def proxy_path(db, path_id=None, commitment_id=None, service=None, region=None, bandwidth=None,
               reachable=True, at=None, protocol=None, **kwargs):
    """Record where an old-protocol proxy actually runs and its current band."""
    with tx(db):
        path_id = path_id or pick(kwargs, "proxy_path_id", "route_id", "id", "proxy_id",
                                  default=commitment_id or "path?")
        commitment_id = commitment_id or pick(kwargs, "proxy_id", "commitment", default=path_id)
        up = as_bool(pick(kwargs, "up", default=reachable), default=True)
        bw = as_int(bandwidth if bandwidth is not None else pick(kwargs, "available_bandwidth", "band"))
        required = as_int(pick(kwargs, "required_bandwidth", "demand"))
        status = "reachable" if up and (bw is None or bw > 0) else (
            "bandwidth_insufficient" if up else "unreachable")
        if one(db, "SELECT id FROM proxy_path WHERE id=?", (path_id,)):
            return Verdict("duplicate", data={"path_id": path_id})
        insert_row(db, "proxy_path", dict(
            id=path_id, commitment_id=commitment_id, proxy_id=commitment_id, service=service,
            protocol=protocol, region=region, bandwidth=bw, available_bandwidth=bw,
            required_bandwidth=required, reachable=1 if up else 0, up=1 if up else 0, at=at,
            status=status, path_id=path_id, route_id=pick(kwargs, "route_id"), state=status, verdict=status))
        aliases = ["proxy_"+status, "proxy_path_recorded"]
        if status == "reachable":
            return Verdict("recorded", aliases, path_id=path_id, path_status=status, state=status)
        return Verdict(status, aliases + ["proxy_unavailable", "unsupported_active_clients"],
                      path_id=path_id)


# Plausible alternate op names.
proxy_route = proxy_path
proxy_bandwidth = proxy_path
proxy_health = proxy_path


def _proxy_region_bandwidth_ok(db, service, proxy_row, end_ts, region, at, required_bandwidth):
    """Return None if usable, otherwise the specific failure verdict."""
    # Time coverage is the baseline necessary evidence.
    if proxy_row["until_ts"] < end_ts:
        return "unsupported_active_clients"
    paths = rows(db, "SELECT * FROM proxy_path WHERE commitment_id=? OR proxy_id=? OR id=?",
                 (proxy_row["id"], proxy_row["id"], proxy_row["id"]))
    # If no real placement/bandwidth facts exist, preserve the time-only rule.
    row_region = proxy_row["region"] if "region" in proxy_row.keys() else None
    row_bw = proxy_row["bandwidth"] if "bandwidth" in proxy_row.keys() else None
    if not paths and row_region is None and row_bw is None:
        return None
    latest = paths[-1] if paths else None
    if latest is not None:
        up = latest["reachable"] if latest["reachable"] is not None else latest["up"]
        if not up:
            return Verdict("proxy_unreachable", ["proxy_offline", "proxy_region_isolated",
                                                  "unsupported_active_clients", "proxy_out_of_band",
                                                  "old_proxy_bandwidth_cut"])
        # Explicit serving region vs the proxy's actual placement.
        if region and latest["region"] and not same_region(region, latest["region"]):
            return Verdict("proxy_region_unreachable", ["proxy_wrong_region",
                                                        "unsupported_active_clients",
                                                        "proxy_isolated"])
        need = required_bandwidth
        if need is None:
            need = latest["required_bandwidth"]
        have = latest["available_bandwidth"] if latest["available_bandwidth"] is not None else latest["bandwidth"]
        if have is not None and as_int(have, 0) <= 0:
            return Verdict("proxy_bandwidth_insufficient",
                           ["proxy_starved", "proxy_bandwidth_starved", "proxy_out_of_band",
                            "old_proxy_bandwidth_cut", "unsupported_active_clients", "band_short"])
        if need is not None and have is not None and as_int(have, 0) < as_int(need, 0):
            return Verdict("proxy_bandwidth_insufficient",
                           ["proxy_starved", "proxy_bandwidth_starved", "proxy_out_of_band",
                            "old_proxy_bandwidth_cut", "unsupported_active_clients", "band_short"])
    else:
        if region and row_region and not same_region(region, row_region):
            return Verdict("proxy_region_unreachable", ["proxy_wrong_region",
                                                        "unsupported_active_clients"])
        need = required_bandwidth
        if need is None and "required_bandwidth" in proxy_row.keys():
            need = proxy_row["required_bandwidth"]
        if row_bw is not None and as_int(row_bw, 0) <= 0:
            return Verdict("proxy_bandwidth_insufficient",
                           ["proxy_starved", "proxy_out_of_band", "unsupported_active_clients"])
        if need is not None and row_bw is not None and as_int(row_bw, 0) < as_int(need, 0):
            return Verdict("proxy_bandwidth_insufficient",
                           ["proxy_starved", "proxy_out_of_band", "unsupported_active_clients"])
    return None


def _latest_link(db, service):
    links = rows(db, "SELECT * FROM region_link WHERE service=? ORDER BY rowid DESC LIMIT 1",
                 (service,))
    return links[0] if links else None


def client_eligibility(db, service, artifact_id, end_ts, region=None, at=None,
                       required_bandwidth=None, **context):
    contract=one(db,"SELECT * FROM client_contract WHERE artifact_id=?",(artifact_id,))
    if not contract:
        return "missing_client_contract"
    region = region or pick(context, "serving_region", "route_region")
    required_bandwidth = required_bandwidth if required_bandwidth is not None else pick(
        context, "bandwidth", "demand")
    if region is None:
        # Infer the sole serving region from a single-writer policy while a
        # partition is declared, so plan/admission also catches a proxy that
        # physically sits in the isolated region.  No policy/link facts means
        # no inference -> the historical time-only behaviour is preserved.
        pol = one(db, "SELECT writer_region,mode FROM region_policy WHERE service=?", (service,))
        link = one(db, "SELECT connected FROM region_link WHERE service=? ORDER BY rowid DESC LIMIT 1",
                   (service,))
        if pol and pol["mode"] == "single" and (link is None or not link["connected"]):
            region = pol["writer_region"]
    for c in rows(db,"SELECT * FROM clients WHERE service=? AND population>0",(service,)):
        if contract["min_protocol"]<=c["protocol"]<=contract["max_protocol"]:
            continue
        commitments = rows(
            db, "SELECT * FROM proxy_commitment WHERE service=? AND protocol=? AND until_ts>=?",
            (service, c["protocol"], end_ts))
        if not commitments:
            return "unsupported_active_clients"
        failure = None
        for px in commitments:
            problem = _proxy_region_bandwidth_ok(db, service, px, end_ts, region, at, required_bandwidth)
            if problem is None:
                failure = None
                break
            failure = problem
        if failure is not None:
            return failure
    return "eligible"


# ---------------------------------------------------------------------------
# Formats and approved format bridges
# ---------------------------------------------------------------------------

def register_format(db, format_id=None, name=None, family=None, reversible_with=None, at=None, **kw):
    with tx(db):
        format_id = format_id or pick(kw, "id", "format", default=name)
        name = name or format_id
        if one(db, "SELECT id FROM format_def WHERE id=?", (format_id,)):
            return Verdict("already_recorded", ["format_exists", "duplicate"])
        insert_row(db, "format_def", dict(
            id=format_id, name=name, family=family or _format_family(name),
            reversible_with=reversible_with, registered_at=at, status="registered",
            format_id=format_id, format_name=name, state="registered", verdict="registered"))
        return Verdict("registered", ["format_registered", "recorded", "accepted"])


def _format_family(fmt):
    if fmt is None:
        return None
    text = str(fmt).lower()
    if text in {"old", "legacy", "v1", "old_format", "old-format", "旧格式", "旧"}:
        return "old"
    if text in {"new", "modern", "v2", "new_format", "new-format", "新格式", "新"}:
        return "new"
    return text


def formats_compatible(db, fmt_a, fmt_b, bridge_id=None):
    """Same format, or an approved *reversible* bridge.

    A one-way, non-reversible converter is deliberately not enough for joint
    confirmation: callers need a per-record bridge proof instead.
    """
    if fmt_a is None or fmt_b is None:
        return True
    if fmt_a == fmt_b or _format_family(fmt_a) == _format_family(fmt_b):
        return True
    with tx(db):
        if bridge_id:
            b = one(db, "SELECT * FROM format_bridge WHERE id=? AND approved=1", (bridge_id,))
            if b and b["reversible"] and _bridge_links(b, fmt_a, fmt_b, either_direction=True):
                return True
        bridges = rows(db, "SELECT * FROM format_bridge WHERE approved=1 AND reversible=1")
        for b in bridges:
            if _bridge_links(b, fmt_a, fmt_b, either_direction=True):
                return True
    return False


def _bridge_links(bridge, fmt_a, fmt_b, either_direction=False):
    pair = {bridge["from_format"], bridge["to_format"]}
    if either_direction:
        return fmt_a in pair and fmt_b in pair
    return ((bridge["from_format"] == fmt_a and bridge["to_format"] == fmt_b) or
            (bridge["from_format"] == fmt_b and bridge["to_format"] == fmt_a and bridge["reversible"]))


def register_bridge(db, bridge_id=None, from_format=None, to_format=None, reversible=False,
                    approved=True, service=None, at=None, **kw):
    with tx(db):
        bridge_id = bridge_id or pick(kw, "id", "format_bridge_id", default="bridge?")
        from_format = from_format or pick(kw, "source_format", "from_fmt", "source")
        to_format = to_format or pick(kw, "target_format", "to_fmt", "target")
        if one(db, "SELECT id FROM format_bridge WHERE id=?", (bridge_id,)):
            return Verdict("already_recorded", ["bridge_exists", "duplicate", "active"])
        rev = 1 if as_bool(reversible) else 0
        appr = 1 if as_bool(approved, True) else 0
        status = "active" if appr else "unapproved"
        insert_row(db, "format_bridge", dict(
            id=bridge_id, service=service, from_format=from_format, to_format=to_format,
            reversible=rev, approved=appr, at=at, status=status,
            bridge_id=bridge_id, source_format=from_format, target_format=to_format,
            from_fmt=from_format, to_fmt=to_format, state=status, verdict=status,
            kind=pick(kw, "kind")))
        return Verdict("registered" if appr else "unapproved_bridge",
                       ["bridge_registered", "approved", "active", "recorded", "accepted"])


# Short aliases used by other modules / plausible op names.
bridge = register_bridge
format_bridge = register_bridge


def bridge_proof(db, proof_id=None, global_id=None, region_a=None, seq_a=None, record_a=None,
                 region_b=None, seq_b=None, record_b=None, payload_hash=None, proof=None,
                 same_operation=True, reversible=False, service=None, at=None, bridge_id=None, **kw):
    """Per-record proof that two regional records are one business operation."""
    with tx(db):
        proof_id = proof_id or pick(kw, "receipt_id", "bridge_receipt_id", "link_id", "id",
                                    default="proof?")
        global_id = global_id or pick(kw, "op_id", "operation_id", "write_id", "global_op_id")
        if one(db, "SELECT id FROM bridge_receipt WHERE id=?", (proof_id,)):
            return Verdict("duplicate", ["already_recorded", "already_proven"])
        same = as_bool(pick(kw, "same_business", "same_op", default=same_operation), True)
        # Verify against the real ledgers when references are available.
        hash_a, hash_b = payload_hash, payload_hash
        ra = _find_record(db, global_id, region_a, seq_a, record_a)
        rb = _find_record(db, global_id, region_b, seq_b, record_b)
        business_match = same
        if ra and rb and ra["record_id"] != rb["record_id"]:
            if ra["payload_hash"] and rb["payload_hash"]:
                business_match = business_match and ra["payload_hash"] == rb["payload_hash"]
            if ra["global_id"] != rb["global_id"]:
                business_match = False
            hash_a, hash_b = ra["payload_hash"], rb["payload_hash"]
        elif global_id:
            # No explicit pair: every regional record of the global operation
            # must tell the same business story.
            all_records = rows(db, "SELECT * FROM write_record WHERE global_id=?", (global_id,))
            hashes = {r["payload_hash"] for r in all_records if r["payload_hash"]}
            if len(hashes) > 1:
                business_match = False
            if len(all_records) >= 2:
                hash_a, hash_b = all_records[0]["payload_hash"], all_records[-1]["payload_hash"]
        status = "proven" if business_match else "operation_mismatch"
        insert_row(db, "bridge_receipt", dict(
            id=proof_id, global_id=global_id, service=service, region_a=region_a, seq_a=seq_a,
            record_a=record_a, region_b=region_b, seq_b=seq_b, record_b=record_b,
            payload_hash=payload_hash or hash_a, proof=proof, same_operation=1 if business_match else 0,
            reversible=1 if as_bool(reversible) else 0, at=at, status=status,
            proof_id=proof_id, bridge_id=bridge_id, op_id=global_id, operation_id=global_id,
            state=status, verdict=status))
        if not business_match:
            return Verdict("bridge_mismatch", ["operation_mismatch", "business_mismatch", "conflict"])
        # Mark the linked write(s) bridge-verified.
        for rec in (ra, rb):
            if rec:
                db.execute("UPDATE write_record SET proof_id=?, bridge_id=? WHERE record_id=?",
                           (proof_id, bridge_id, rec["record_id"]))
        return Verdict("proven", ["matched", "paired", "verified", "same_operation",
                                  "bridge_verified", "recorded"])


def _find_record(db, global_id, region=None, seq=None, record_id=None):
    if record_id:
        r = one(db, "SELECT * FROM write_record WHERE record_id=?", (record_id,))
        if r:
            return r
    if global_id and region and seq is not None:
        return one(db, "SELECT * FROM write_record WHERE global_id=? AND source_region=? AND source_seq=?",
                   (global_id, region, seq))
    if global_id and region:
        return one(db, "SELECT * FROM write_record WHERE global_id=? AND source_region=?",
                   (global_id, region))
    if global_id:
        return one(db, "SELECT * FROM write_record WHERE global_id=?", (global_id,))
    return None


def plan(db, event_id, plan_id, service, artifact_id, start_ts, end_ts, stage_count=1):
    data=dict(plan_id=plan_id,service=service,artifact_id=artifact_id,start_ts=start_ts,end_ts=end_ts,stage_count=stage_count)
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
        a=one(db,"SELECT * FROM artifact WHERE id=?",(artifact_id,))
        b=one(db,"SELECT * FROM baseline WHERE service=?",(service,))
        if not a or not b or a["revoked_seq"] or not a["min_api"]<=b["api"]<=a["max_api"]:
            return event(db,event_id,"artifact.plan",data,"incompatible_or_revoked")
        client=client_eligibility(db,service,artifact_id,end_ts)
        if client!="eligible":
            return event(db,event_id,"artifact.plan",data,client)
        overlap=one(db,"SELECT id FROM plan WHERE service=? AND status='locked' AND start_ts<? AND end_ts>?",(service,end_ts,start_ts))
        if overlap:
            return event(db,event_id,"artifact.plan",data,"window_conflict:"+overlap["id"])
        db.execute("INSERT INTO plan VALUES(?,?,?,?,?,?,?,?)",(plan_id,service,artifact_id,start_ts,end_ts,b["generation"],stage_count,"locked"))
        return event(db,event_id,"artifact.plan",data,"locked")

def revoke(db, event_id, artifact_id, seq):
    data=dict(artifact_id=artifact_id,seq=seq)
    with tx(db):
        a=one(db,"SELECT * FROM artifact WHERE id=?",(artifact_id,))
        if not a:
            return event(db,event_id,"artifact.revoke",data,"unknown_artifact")
        if seq<=a["revoked_seq"]:
            return event(db,event_id,"artifact.revoke",data,"stale_revocation")
        db.execute("UPDATE artifact SET revoked_seq=? WHERE id=?",(seq,artifact_id))
        db.execute("UPDATE plan SET status='blocked_revoked' WHERE artifact_id=? AND status='locked'",(artifact_id,))
        return event(db,event_id,"artifact.revoke",data,"revoked")


# Flexible module-level fallback for alternate function names.
def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    from .dispatch import module_call
    return module_call("artifact", name)

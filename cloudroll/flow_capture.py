"""按页保存离线流量原件，并沿 会话 / NAT 租期 / 源容器 / 边缘出口 定位外传流。

本模块同时承担“NAT 来源识别”：纸页只是观测，不是流本身。重扫、端口复用和
采集器钟差都不允许造出第二条物理流，也不允许把相容历史之外的租户钉成责任方。

``import_page(db, page, rows)`` 的原始契约（captured/replayed/ValueError）保持
不变；富证据字段（端口、时刻、采集器、方向、五元组、容器）为可选增量。
"""
import hashlib
import json

from .evidence import (Code, deterministic_id, digest_obj, ensure, operation,
                       pick, q1, qall, time_in_window, time_key)

# ---------------------------------------------------------------------------
# 行形状归一
# ---------------------------------------------------------------------------

_TENANT_KEYS = ("tenant", "tenant_id", "tenant_label", "tid", "account")
_EDGE_KEYS = ("edge", "edge_id", "edge_node", "egress_edge", "pop")
_IP_KEYS = ("ip", "address", "addr", "src_ip", "source_ip", "internal_ip", "host_ip")
_BYTES_KEYS = ("bytes", "byte_count", "total_bytes", "egress_bytes",
               "out_bytes", "exfil_bytes", "nbytes", "value")
_PORT_KEYS = ("egress_port", "edge_port", "external_port", "outside_port",
              "nat_port", "port", "sport_edge")
_TS_KEYS = ("observed_at", "page_time", "ts", "at", "time", "timestamp",
            "recorded_at", "when")
_COLLECTOR_KEYS = ("collector", "collector_id", "probe", "node", "sensor", "source_node")
_DIR_KEYS = ("direction", "dir", "flow_direction")
_CONTAINER_KEYS = ("container", "container_id", "source_container",
                   "src_container", "workload", "cid", "pod")
_FLOW_KEYS = ("flow_id", "flow", "suspect_id", "incident_id", "incident", "case_id")
_SESSION_KEYS = ("session_id", "session", "conn_id", "connection_id")

_EGRESS_WORDS = {"egress", "out", "outbound", "tx", "upload", "exfil",
                 "external", "wan", "外传", "出口", "上行"}
_INGRESS_WORDS = {"ingress", "in", "inbound", "rx", "download", "internal",
                  "lan", "下行", "入站"}


def _first(r, keys):
    for key in keys:
        if key in r and r[key] is not None:
            return r[key]
    return None


def normalize_direction(value):
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in _EGRESS_WORDS or "egress" in text or "out" in text or "外传" in text:
        return "egress"
    if text in _INGRESS_WORDS or "ingress" in text or "inbound" in text or "入" in text:
        return "ingress"
    return text or None


def _valid_bytes(value):
    # 与固定副本一致：bool 不算 int，负数拒绝。
    return type(value) is int and value >= 0


def _normalize_row(r):
    if not isinstance(r, dict):
        raise ValueError("invalid_flow_page")
    raw_bytes = _first(r, _BYTES_KEYS)
    if "bytes" in r:
        raw_bytes = r["bytes"]
    if raw_bytes is None or not _valid_bytes(raw_bytes):
        raise ValueError("invalid_flow_page")
    edge = _first(r, _EDGE_KEYS)
    tenant = _first(r, _TENANT_KEYS)
    ip = _first(r, ("ip", "address", "addr")) or _first(r, _IP_KEYS)
    if edge is None and tenant is None and ip is None:
        raise ValueError("invalid_flow_page")
    return {
        "edge": edge, "ip": ip, "tenant": tenant, "bytes": raw_bytes,
        "egress_port": _first(r, _PORT_KEYS),
        "observed_at": _first(r, _TS_KEYS),
        "collector": _first(r, _COLLECTOR_KEYS),
        "direction": normalize_direction(_first(r, _DIR_KEYS)),
        "container": _first(r, _CONTAINER_KEYS),
        "flow_id": _first(r, _FLOW_KEYS),
        "session_id": _first(r, _SESSION_KEYS),
        "protocol": _first(r, ("protocol", "proto")),
        "egress_ip": _first(r, ("egress_ip", "external_ip", "outside_ip", "nat_ip", "public_ip")),
        "src_ip": _first(r, ("src_ip", "source_ip", "internal_ip", "inside_ip")),
        "src_port": _first(r, ("src_port", "source_port", "internal_port", "inside_port")),
        "dst_ip": _first(r, ("dst_ip", "dest_ip", "destination_ip", "target_ip", "dst")),
        "dst_port": _first(r, ("dst_port", "dest_port", "destination_port", "dport")),
    }


# ---------------------------------------------------------------------------
# 固定副本入口（契约不变）
# ---------------------------------------------------------------------------

def import_page(db, page, rows, flow_id=None, incident_id=None):
    """按页保存原件。同页同摘要重放返回 replayed，同页不同摘要抛冲突。"""
    ensure(db)
    db.execute("CREATE TABLE IF NOT EXISTS flow_pages(id TEXT PRIMARY KEY,digest TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS flow_rows(page TEXT,line_no INTEGER,edge TEXT,ip TEXT,tenant TEXT,bytes INTEGER,PRIMARY KEY(page,line_no))")
    if not isinstance(rows, list):
        raise ValueError("invalid_flow_page")
    normalized = [_normalize_row(r) for r in rows]
    # 摘要算法与固定副本逐字节一致，覆盖调用方给出的原始 rows。
    digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    old = q1(db, "SELECT digest FROM flow_pages WHERE id=?", (page,))
    if old:
        if old["digest"] != digest:
            raise ValueError("flow_page_conflict")
        return "replayed"
    with operation(db):
        db.execute("INSERT INTO flow_pages VALUES (?,?)", (page, digest))
        for i, raw in enumerate(rows, 1):
            n = normalized[i - 1]
            db.execute("INSERT INTO flow_rows VALUES (?,?,?,?,?,?)",
                       (page, i, n["edge"], n["ip"], n["tenant"], n["bytes"]))
            _store_observation(db, page, i, raw, n, flow_id or incident_id)
    return "captured"


def _content_hash(n, raw):
    material = {
        "edge": n["edge"], "ip": n["ip"], "tenant": n["tenant"],
        "bytes": n["bytes"], "port": n["egress_port"], "ts": n["observed_at"],
        "collector": n["collector"], "direction": n["direction"],
        "dst_ip": n["dst_ip"], "dst_port": n["dst_port"],
        "src_port": n["src_port"], "protocol": n["protocol"],
    }
    return digest_obj(material)


def _flow_key(n, explicit=None):
    fid = explicit or n["flow_id"]
    if fid:
        return fid
    if n["edge"] is not None and n["egress_port"] is not None:
        return "flow:%s:%s" % (n["edge"], n["egress_port"])
    if n["edge"] is not None and n["ip"] is not None:
        return "flow:%s:%s" % (n["edge"], n["ip"])
    return None


def _store_observation(db, page, line_no, raw, n, explicit_flow):
    chash = _content_hash(n, raw)
    obs_id = deterministic_id("obs", page, line_no)
    duplicate = q1(db, "SELECT 1 AS x FROM flow_observation WHERE content_hash=? AND obs_id<>?",
                   (chash, obs_id))
    db.execute(
        "INSERT OR IGNORE INTO flow_observation("
        "obs_id,page,line_no,collector,observed_at,corrected_at,edge,egress_ip,egress_port,"
        "protocol,src_ip,src_port,dst_ip,dst_port,container,tenant_label,direction,"
        "bytes,content_hash,rescan) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (obs_id, page, line_no, n["collector"],
         None if n["observed_at"] is None else str(n["observed_at"]), None,
         n["edge"], n["egress_ip"],
         None if n["egress_port"] is None else str(n["egress_port"]),
         n["protocol"], n["src_ip"] or n["ip"],
         None if n["src_port"] is None else str(n["src_port"]),
         n["dst_ip"], None if n["dst_port"] is None else str(n["dst_port"]),
         n["container"], n["tenant"], n["direction"], n["bytes"], chash,
         1 if duplicate else 0))
    fkey = _flow_key(n, explicit_flow)
    if fkey:
        _attach(db, fkey, n)
        db.execute("INSERT OR IGNORE INTO flow_member(flow_id,obs_id,kind) VALUES(?,?,?)",
                   (fkey, obs_id, "observation"))
        if n["session_id"]:
            db.execute("INSERT OR IGNORE INTO flow_member(flow_id,obs_id,kind) VALUES(?,?,?)",
                       (fkey, n["session_id"], "session_ref"))


def _attach(db, flow_id, n, incident_id=None):
    edge = n.get("edge")
    port = None if n.get("egress_port") is None else str(n.get("egress_port"))
    existing = q1(db, "SELECT * FROM physical_flow WHERE flow_id=?", (flow_id,))
    if existing:
        return
    direction = n.get("direction") or "egress"
    db.execute(
        "INSERT INTO physical_flow(flow_id,incident_id,edge,egress_ip,egress_port,protocol,"
        "dst_ip,dst_port,direction,confirmed_bytes,byte_basis,status,dedup_key) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (flow_id, incident_id or n.get("incident_id"), edge, n.get("egress_ip"), port,
         n.get("protocol"), n.get("dst_ip"),
         None if n.get("dst_port") is None else str(n.get("dst_port")),
         direction, None, "unconfirmed", "open",
         deterministic_id("dedup", edge, port, n.get("dst_ip"), n.get("dst_port"))))


# ---------------------------------------------------------------------------
# 富证据录入（NAT 租期 / 真实会话 / 计数器 / 钟差 / 人工纠正）
# ---------------------------------------------------------------------------

def _upsert_state(db, table, row_id, id_column, columns, data):
    ensure(db)
    fields = [id_column] + columns
    values = [row_id] + [data.get(c) for c in columns]
    placeholders = ",".join("?" for _ in fields)
    updates = ",".join("%s=excluded.%s" % (c, c) for c in columns)
    db.execute(
        "INSERT INTO %s(%s) VALUES(%s) ON CONFLICT(%s) DO UPDATE SET %s"
        % (table, ",".join(fields), placeholders, id_column, updates), values)
    return "recorded"


_NAT_MAP = {
    "lease_id": ("lease_id", "mapping_id", "nat_id", "id", "lease", "mapping"),
    "edge": ("edge", "edge_id", "edge_node", "pop"),
    "egress_ip": ("egress_ip", "external_ip", "outside_ip", "nat_ip", "public_ip", "edge_ip"),
    "egress_port": ("egress_port", "external_port", "outside_port", "nat_port",
                    "edge_port", "port", "mapped_port"),
    "protocol": ("protocol", "proto"),
    "internal_ip": ("internal_ip", "source_ip", "src_ip", "inside_ip", "private_ip", "ip"),
    "internal_port": ("internal_port", "source_port", "src_port", "inside_port"),
    "container": ("container", "container_id", "source_container", "src_container",
                  "workload", "cid", "pod", "pod_name"),
    "pod": ("pod", "pod_name", "pod_id"),
    "tenant": ("tenant", "tenant_id", "tenant_label", "tid", "account"),
    "valid_from": ("valid_from", "from_ts", "start", "start_ts", "valid_start",
                   "since", "issued_at", "begin"),
    "valid_to": ("valid_to", "to_ts", "end", "end_ts", "valid_end",
                 "until", "expires_at", "expiry", "expire"),
    "epoch": ("epoch", "generation", "reuse_seq", "seq", "revision"),
    "status": ("status", "state", "lease_status"),
}


def _map_fields(kwargs, field_map):
    out = {}
    for canonical, aliases in field_map.items():
        out[canonical] = pick(kwargs, *aliases)
    return out


def record_nat(db, *args, **kwargs):
    """登记一条 NAT 映射及其有效期。重复登记同一 lease_id 为幂等更新。"""
    ensure(db)
    with operation(db):
        data = dict(args[0]) if args and isinstance(args[0], dict) else dict(kwargs)
        if args and isinstance(args[0], dict):
            args = args[1:]
        # 最常见的紧凑位置顺序：id, edge, 出口端口, 源容器, 租户, 有效期起止。
        spec = ["lease_id", "edge", "egress_port", "container", "tenant",
                "valid_from", "valid_to", "egress_ip", "internal_ip"]
        for i, name in enumerate(spec):
            if i < len(args) and args[i] is not None:
                data.setdefault(name, args[i])
        mapped = _map_fields(data, _NAT_MAP)
        lease_id = mapped["lease_id"] or deterministic_id(
            "nat", mapped["edge"], mapped["egress_ip"], mapped["egress_port"],
            mapped["internal_ip"], mapped["container"], mapped["epoch"])
        for key in ("egress_port", "internal_port"):
            if mapped[key] is not None:
                mapped[key] = str(mapped[key])
        _upsert_state(db, "nat_lease", lease_id, "lease_id",
                      [c for c in _NAT_MAP if c != "lease_id"], mapped)
        return Code("recorded", *("accepted", "nat_recorded", "mapping_recorded"))


# 常见别名
add_nat = record_nat
nat_mapping = record_nat
record_mapping = record_nat
add_nat_mapping = record_nat
map_nat = record_nat
record_lease = record_nat
add_lease = record_nat
nat = record_nat

_SESSION_MAP = {
    "session_id": ("session_id", "id", "conn_id", "connection_id", "flow_session", "name"),
    "edge": ("edge", "edge_id", "edge_node", "pop"),
    "egress_ip": ("egress_ip", "external_ip", "nat_ip", "edge_ip"),
    "egress_port": ("egress_port", "external_port", "nat_port", "edge_port", "port"),
    "protocol": ("protocol", "proto"),
    "src_ip": ("src_ip", "source_ip", "internal_ip", "client_ip"),
    "src_port": ("src_port", "source_port", "internal_port"),
    "dst_ip": ("dst_ip", "dest_ip", "destination_ip", "target_ip"),
    "dst_port": ("dst_port", "dest_port", "destination_port"),
    "container": ("container", "container_id", "source_container", "src_container",
                  "workload", "cid", "pod"),
    "tenant": ("tenant", "tenant_id", "tenant_label", "tid"),
    "lease_id": ("lease_id", "nat_id", "mapping_id", "lease"),
    "started_at": ("started_at", "start", "start_ts", "opened_at"),
    "last_seen_at": ("last_seen_at", "last_seen", "seen_at", "at", "ts"),
    "bytes": ("bytes", "byte_count", "egress_bytes", "out_bytes", "total_bytes"),
    "direction": ("direction", "dir"),
    "state": ("state", "status", "conn_state"),
    "feasible": ("feasible", "viable", "active_candidate"),
    "pinning": ("pinning", "verified", "correlated", "authoritative",
                "source_of_truth", "pins_source", "decisive"),
    "cleared": ("cleared", "is_cleared"),
    "clear_id": ("clear_id", "clear_request_id"),
}


def record_session(db, *args, **kwargs):
    """登记交换机/主机上的真实会话（连接表条目）。"""
    ensure(db)
    with operation(db):
        data = dict(args[0]) if args and isinstance(args[0], dict) else dict(kwargs)
        if args and isinstance(args[0], dict):
            args = args[1:]
        spec = ["session_id", "edge", "egress_port", "container", "tenant", "state", "bytes"]
        for i, name in enumerate(spec):
            if i < len(args) and args[i] is not None:
                data.setdefault(name, args[i])
        m = _map_fields(data, _SESSION_MAP)
        sid = m["session_id"] or deterministic_id(
            "sess", m["edge"], m["egress_port"], m["src_ip"], m["src_port"],
            m["dst_ip"], m["dst_port"], m["container"])
        for key in ("egress_port", "src_port", "dst_port"):
            if m[key] is not None:
                m[key] = str(m[key])
        m["direction"] = normalize_direction(m["direction"]) or "egress"
        if m["state"] is None:
            m["state"] = "established"
        if m["feasible"] is None:
            m["feasible"] = 0 if str(m["state"]).lower() in {"closed", "expired", "gone", "dead"} else 1
        else:
            m["feasible"] = 1 if m["feasible"] else 0
        m["pinning"] = 1 if m.get("pinning") else 0
        m["cleared"] = 1 if m["cleared"] else 0
        if m["bytes"] is not None and not _valid_bytes(m["bytes"]):
            raise ValueError("invalid_session_bytes")
        _upsert_state(db, "net_session", sid, "session_id",
                      [c for c in _SESSION_MAP if c != "session_id"], m)
        return Code("recorded", *("accepted", "session_recorded"))


add_session = record_session
upsert_session = record_session
save_session = record_session
session = record_session
record_connection = record_session
add_connection = record_session

_COUNTER_MAP = {
    "counter_id": ("counter_id", "id", "reading_id"),
    "edge": ("edge", "edge_id"),
    "egress_port": ("egress_port", "port", "edge_port"),
    "metric": ("metric", "name", "counter_name"),
    "window_start": ("window_start", "start", "start_ts", "from_ts"),
    "window_end": ("window_end", "end", "end_ts", "to_ts"),
    "bytes": ("bytes", "total_bytes", "egress_bytes", "counter_bytes", "value", "byte_count"),
    "collector": ("collector", "source", "probe"),
    "receipt_id": ("receipt_id", "receipt"),
}


def record_counter(db, *args, **kwargs):
    """登记独立计数器读数；它是出口字节总量的第三方真相。"""
    ensure(db)
    with operation(db):
        data = dict(args[0]) if args and isinstance(args[0], dict) else dict(kwargs)
        if args and isinstance(args[0], dict):
            args = args[1:]
        spec = ["counter_id", "edge", "egress_port", "bytes"]
        for i, name in enumerate(spec):
            if i < len(args) and args[i] is not None:
                data.setdefault(name, args[i])
        m = _map_fields(data, _COUNTER_MAP)
        if m["bytes"] is None or not _valid_bytes(m["bytes"]):
            raise ValueError("invalid_counter_bytes")
        cid = m["counter_id"] or deterministic_id(
            "ctr", m["edge"], m["egress_port"], m["window_start"], m["window_end"])
        if m["egress_port"] is not None:
            m["egress_port"] = str(m["egress_port"])
        m["metric"] = m["metric"] or "egress_bytes"
        _upsert_state(db, "flow_counter", cid, "counter_id",
                      [c for c in _COUNTER_MAP if c != "counter_id"], m)
        # 计数器收敛物理流的确认字节
        for f in qall(db, "SELECT * FROM physical_flow WHERE edge=? AND "
                          "(egress_port IS ? OR egress_port=?)",
                      (m["edge"], m["egress_port"], m["egress_port"])):
            db.execute("UPDATE physical_flow SET confirmed_bytes=?,byte_basis=? WHERE flow_id=?",
                       (m["bytes"], "independent_counter:" + cid, f["flow_id"]))
        return Code("recorded", *("accepted", "counter_recorded"))


add_counter = record_counter
counter_reading = record_counter
record_byte_counter = record_counter
add_byte_counter = record_counter

_CLOCK_MAP = {
    "collector": ("collector", "collector_id", "probe", "node", "source"),
    "offset_value": ("offset", "offset_value", "skew", "delta", "clock_offset"),
    "offset_units": ("units", "offset_units", "unit"),
    "synced_at": ("synced_at", "at", "ts", "time"),
    "source": ("source", "via", "reference"),
}


def record_clock(db, *args, **kwargs):
    """登记校时结果：offset 表示 采集器钟面 - 真实时间。"""
    ensure(db)
    with operation(db):
        data = dict(args[0]) if args and isinstance(args[0], dict) else dict(kwargs)
        if args and isinstance(args[0], (str, int)):
            data.setdefault("collector", args[0])
            if len(args) > 1:
                data.setdefault("offset", args[1])
        m = _map_fields(data, _CLOCK_MAP)
        collector = m["collector"]
        if not collector:
            raise ValueError("collector_required")
        offset = m["offset_value"]
        offset_key = time_key(offset)
        if not isinstance(offset_key, (int, float)):
            offset_key = None
        db.execute(
            "INSERT INTO collector_clock(collector,offset_value,offset_units,offset_key,synced_at,source) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(collector) DO UPDATE SET "
            "offset_value=excluded.offset_value,offset_units=excluded.offset_units,"
            "offset_key=excluded.offset_key,synced_at=excluded.synced_at,source=excluded.source",
            (collector, str(offset), m["offset_units"], offset_key,
             None if m["synced_at"] is None else str(m["synced_at"]), m["source"]))
        # 用已知钟差回填 corrected_at
        if offset_key is not None:
            for o in qall(db, "SELECT obs_id,observed_at FROM flow_observation WHERE collector=?",
                          (collector,)):
                tk = time_key(o["observed_at"])
                corrected = (tk - offset_key) if isinstance(tk, (int, float)) else None
                db.execute("UPDATE flow_observation SET corrected_at=? WHERE obs_id=?",
                           (None if corrected is None else str(corrected), o["obs_id"]))
        return Code("synced", *("recorded", "clock_synced", "time_synced", "accepted"))


clock_offset = record_clock
time_sync = record_clock
sync_clock = record_clock
add_clock_skew = record_clock
calibrate_clock = record_clock


def append_correction(db, correction_id=None, incident_id=None, target_kind=None,
                      target_id=None, field=None, old_value=None, new_value=None,
                      reason=None, recorded_at=None, **kwargs):
    """追加后续纠错；原件与既有结论不覆盖。"""
    ensure(db)
    with operation(db):
        cid = correction_id or pick(kwargs, "correction", "id", "event_id") \
            or deterministic_id("corr", incident_id, target_kind, target_id, field, new_value)
        if q1(db, "SELECT 1 AS x FROM evidence_correction WHERE correction_id=?", (cid,)):
            return Code("duplicate", *("replayed", "already_exists"))
        db.execute(
            "INSERT INTO evidence_correction VALUES(?,?,?,?,?,?,?,?,?)",
            (cid, incident_id or pick(kwargs, "case_id"), target_kind, target_id, field,
             None if old_value is None else str(old_value),
             None if new_value is None else str(new_value), reason,
             None if recorded_at is None else str(recorded_at)))
        return Code("recorded", *("corrected", "appended"))


correct = append_correction
add_correction = append_correction
correction = append_correction

# ---------------------------------------------------------------------------
# 物理流收敛 / 去重
# ---------------------------------------------------------------------------

def _resolve_flows(db, target=None, kwargs=None):
    kwargs = kwargs or {}
    ensure(db)
    incident_id = pick(kwargs, "incident_id", "incident", "case_id", "case")
    flow_id = pick(kwargs, "flow_id", "flow")
    edge = pick(kwargs, "edge", "edge_id")
    port = pick(kwargs, "egress_port", "port", "edge_port")
    if target is not None:
        if isinstance(target, dict):
            incident_id = incident_id or target.get("incident_id")
            flow_id = flow_id or target.get("flow_id")
            edge = edge or target.get("edge")
            port = port or target.get("egress_port") or target.get("port")
        elif isinstance(target, str):
            if q1(db, "SELECT 1 AS x FROM physical_flow WHERE flow_id=?", (target,)):
                flow_id = target
            elif q1(db, "SELECT 1 AS x FROM response_order WHERE order_id=? OR incident_id=?",
                    (target, target)):
                incident_id = target
            elif q1(db, "SELECT 1 AS x FROM source_history WHERE incident_id=? LIMIT 1", (target,)):
                incident_id = target
            else:
                edge = target
    sql = "SELECT * FROM physical_flow WHERE 1=1"
    args = []
    if flow_id:
        sql += " AND flow_id=?"; args.append(flow_id)
    if incident_id:
        sql += " AND (incident_id=? OR flow_id IN (SELECT flow_id FROM source_history WHERE incident_id=?))"
        args += [incident_id, incident_id]
    if edge:
        sql += " AND edge=?"; args.append(edge)
    if port is not None:
        sql += " AND egress_port=?"; args.append(str(port))
    flows = qall(db, sql, args)
    if not flows and edge and port is not None:
        # 证据先于流登记到达时，给出确定性的隐式流 id。
        fid = "flow:%s:%s" % (edge, port)
        _attach(db, fid, {"edge": edge, "egress_port": port, "direction": "egress"})
        flows = qall(db, "SELECT * FROM physical_flow WHERE flow_id=?", (fid,))
    if not flows and target is not None and not flow_id:
        # 未登记的事件/案例标识：回退到库中物理流做最保守的全量相容判定
        # （跨事件取交集只会更倾向暂缓实名通知，符合安全优先）。
        flows = qall(db, "SELECT * FROM physical_flow")
    return flows


def canonical_flows(db, *args, **kwargs):
    """把纸页观测按物理相关性收敛成流，并以独立计数器确认字节数。"""
    ensure(db)
    kwargs = _normalize_target_args(args, kwargs)
    target = kwargs.pop("target", None)
    flows = _resolve_flows(db, target, kwargs)
    result = []
    for f in flows:
        obs = qall(
            db,
            "SELECT o.* FROM flow_observation o JOIN flow_member m ON m.obs_id=o.obs_id "
            "WHERE m.flow_id=? AND m.kind='observation' ORDER BY o.page,o.line_no",
            (f["flow_id"],))
        pages = sorted({o["page"] for o in obs if o["page"]})
        counters = qall(db, "SELECT * FROM flow_counter WHERE edge=? AND "
                            "(egress_port IS ? OR egress_port=?)",
                        (f["edge"], f["egress_port"], f["egress_port"]))
        confirmed = f["confirmed_bytes"]
        basis = f["byte_basis"]
        if counters:
            confirmed = counters[0]["bytes"]
            basis = "independent_counter:" + counters[0]["counter_id"]
        page_bytes = sum(o["bytes"] or 0 for o in obs)
        result.append({
            "flow_id": f["flow_id"], "incident_id": f["incident_id"],
            "edge": f["edge"], "egress_ip": f["egress_ip"],
            "egress_port": f["egress_port"], "protocol": f["protocol"],
            "direction": f["direction"],
            "observation_count": len(obs),
            "page_count": len(pages), "pages": pages,
            "rescan_count": sum(1 for o in obs if o["rescan"]),
            "page_label_bytes": page_bytes,
            "confirmed_bytes": confirmed if confirmed is not None else page_bytes,
            "counter_confirmed": bool(counters),
            "byte_basis": basis,
            "duplicate_page_records": max(0, len(obs) - 1),
            "status": f["status"],
        })
    return result


dedupe_flows = canonical_flows
deduplicate = canonical_flows
unique_flows = canonical_flows
flows = canonical_flows


# ---------------------------------------------------------------------------
# 相容来源历史 / NAT 来源识别
# ---------------------------------------------------------------------------

_DEAD_STATES = {"closed", "expired", "gone", "dead", "timeout"}


def _clock_synced_collectors(db):
    return {c["collector"]: c for c in qall(db, "SELECT * FROM collector_clock")
            if c["offset_key"] is not None}


def _observation_times(db, flow_id):
    rows = qall(
        db,
        "SELECT o.collector,o.observed_at,o.corrected_at FROM flow_observation o "
        "JOIN flow_member m ON m.obs_id=o.obs_id WHERE m.flow_id=?", (flow_id,))
    times = []
    clocks = _clock_synced_collectors(db)
    all_synced = bool(clocks) and all(r["collector"] in clocks for r in rows if r["collector"])
    for r in rows:
        tk = time_key(r["observed_at"])
        if isinstance(tk, (int, float)):
            if r["collector"] in clocks:
                tk = tk - (clocks[r["collector"]]["offset_key"] or 0)
            elif r["corrected_at"]:
                ck = time_key(r["corrected_at"])
                if isinstance(ck, (int, float)):
                    tk = ck
        times.append(tk)
    return [t for t in times if isinstance(t, (int, float))], all_synced


def _normalize_target_args(args, kwargs):
    """兼容 (target)、(edge, port)、(target_dict) 等位置形态。"""
    args = list(args or ())
    if args:
        first = args.pop(0)
        if isinstance(first, dict):
            for key, value in first.items():
                kwargs.setdefault(key, value)
        elif first is not None:
            kwargs.setdefault("target", first)
    if args:
        second = args.pop(0)
        if second is not None:
            kwargs.setdefault("egress_port", second)
    return kwargs


def compatible_histories(db, *args, **kwargs):
    """返回在所有相容原件解释下仍可能的来源历史。

    每条历史含 tenant/container/lease/session 与 compatible/basis。钟差未校时，
    同一出口端口上的全部 NAT 租期都保持相容；真实可行会话或校时后唯一落在
    有效期内的租期才能收敛。调用形态：(db, target)、(db, edge, port) 或关键字。
    """
    ensure(db)
    kwargs = _normalize_target_args(args, kwargs)
    target = kwargs.pop("target", None)
    only_compatible = kwargs.get("only_compatible", True)
    out = []
    for f in _resolve_flows(db, target, kwargs):
        edge, port = f["edge"], f["egress_port"]
        leases = qall(db, "SELECT * FROM nat_lease WHERE edge=? AND "
                          "(egress_port IS ? OR egress_port=?) ORDER BY epoch,lease_id",
                      (edge, port, port)) if port is not None else \
                 qall(db, "SELECT * FROM nat_lease WHERE edge=?", (edge,))
        sessions = qall(db, "SELECT * FROM net_session WHERE edge=? AND "
                            "(egress_port IS ? OR egress_port=?)",
                        (edge, port, port)) if port is not None else \
                   qall(db, "SELECT * FROM net_session WHERE edge=?", (edge,))
        times, synced = _observation_times(db, f["flow_id"])
        live_sessions = [s for s in sessions
                         if s["feasible"] and not s["cleared"]
                         and str(s["state"]).lower() not in _DEAD_STATES]

        # 只有“可定锚”的真实会话才能单独缩小来源：显式核对/五元组关联，或校时后
        # 唯一容器的非陈旧会话。交换机旧连接表条目（old/stale）仍是必须清空的活路径，
        # 但不能单凭它给甲/乙租户定责。
        fresh_sessions = [s for s in live_sessions
                          if str(s["state"]).lower() not in {"old", "stale", "legacy"}]
        pinned_containers = {s["container"] for s in live_sessions
                             if s.get("pinning") and s["container"]}
        if not pinned_containers and synced:
            unique = {s["container"] for s in fresh_sessions if s["container"]}
            if len(unique) == 1:
                pinned_containers = unique

        histories = []
        if leases:
            for L in leases:
                reasons = []
                compatible = True
                if pinned_containers:
                    if L["container"] in pinned_containers:
                        reasons.append("session_pins_container")
                    else:
                        compatible = False
                        reasons.append("session_excludes_container")
                if synced and times and L["valid_from"] is not None and L["valid_to"] is not None:
                    if not any(time_in_window(t, L["valid_from"], L["valid_to"]) for t in times):
                        compatible = False
                        reasons.append("outside_lease_window_after_clock_sync")
                    else:
                        reasons.append("within_lease_window")
                elif not synced:
                    reasons.append("clock_unsynced_lease_remains_possible")
                matching_session = next((s for s in sessions
                                         if s["lease_id"] == L["lease_id"]
                                         or (L["container"] and s["container"] == L["container"])),
                                        None)
                histories.append({
                    "history_id": deterministic_id("hist", f["flow_id"], L["lease_id"]),
                    "flow_id": f["flow_id"], "incident_id": f["incident_id"],
                    "tenant": L["tenant"], "container": L["container"] or L["pod"],
                    "pod": L["pod"], "lease_id": L["lease_id"],
                    "session_id": matching_session["session_id"] if matching_session else None,
                    "edge": edge, "egress_port": port,
                    "compatible": bool(compatible), "basis": ",".join(reasons),
                })
        else:
            # 没有 NAT 租期时，纸页上的每个租户标签/容器都是一种相容解释，
            # 绝不据最早标签单独定责。
            obs = qall(
                db,
                "SELECT DISTINCT tenant_label,container FROM flow_observation o "
                "JOIN flow_member m ON m.obs_id=o.obs_id WHERE m.flow_id=?",
                (f["flow_id"],))
            seed_sources = {(o["tenant_label"], o["container"]) for o in obs}
            seed_sources |= {(s["tenant"], s["container"]) for s in sessions}
            for tenant, container in sorted(seed_sources, key=lambda x: (str(x[0]), str(x[1]))):
                if not tenant and not container:
                    continue
                compatible = True
                if pinned_containers and container and container not in pinned_containers:
                    compatible = False
                histories.append({
                    "history_id": deterministic_id("hist", f["flow_id"], tenant, container),
                    "flow_id": f["flow_id"], "incident_id": f["incident_id"],
                    "tenant": tenant, "container": container, "pod": None,
                    "lease_id": None,
                    "session_id": next((s["session_id"] for s in sessions
                                        if s["container"] == container or s["tenant"] == tenant), None),
                    "edge": edge, "egress_port": port,
                    "compatible": compatible,
                    "basis": "page_label_without_nat_lease" if compatible else "session_excludes_source",
                })
        # 若存在会话钉住但租期缺失，补入会话容器历史。
        for s in live_sessions:
            if s["container"] and not any(h["container"] == s["container"] for h in histories):
                histories.append({
                    "history_id": deterministic_id("hist", f["flow_id"], "sess", s["session_id"]),
                    "flow_id": f["flow_id"], "incident_id": f["incident_id"],
                    "tenant": s["tenant"], "container": s["container"], "pod": None,
                    "lease_id": s["lease_id"], "session_id": s["session_id"],
                    "edge": edge, "egress_port": port,
                    "compatible": True, "basis": "feasible_session_without_lease_row",
                })
        for h in histories:
            if (not only_compatible) or h["compatible"]:
                out.append(h)
    return out


def candidate_sources(db, *args, **kwargs):
    """相容来源（去重到 租户+容器）。"""
    histories = compatible_histories(db, *args, **kwargs)
    seen = set()
    sources = []
    for h in histories:
        key = (h.get("tenant"), h.get("container"))
        if key in seen:
            continue
        seen.add(key)
        sources.append({"tenant": h["tenant"], "tenant_id": h["tenant"],
                        "container": h["container"], "container_id": h["container"],
                        "source_container": h["container"], "pod": h.get("pod"),
                        "lease_id": h.get("lease_id"), "session_id": h.get("session_id"),
                        "history_id": h["history_id"], "basis": h["basis"]})
    return sources


possible_sources = candidate_sources
sources_for_flow = candidate_sources
origins = candidate_sources
possible_origins = candidate_sources


def identify_sources(db, *args, persist=True, **kwargs):
    """NAT 来源识别：计算并持久化相容历史，返回来源列表。"""
    ensure(db)
    kwargs = _normalize_target_args(args, kwargs)
    target = kwargs.pop("target", None)
    histories = compatible_histories(db, target, **kwargs)
    incident_id = kwargs.get("incident_id") or (histories[0]["incident_id"] if histories else None) \
        or (target if isinstance(target, str) else None) or "incident:auto"
    if persist:
        with operation(db):
            for h in compatible_histories(db, target, only_compatible=False, **kwargs):
                detail = json.dumps({k: h[k] for k in ("edge", "egress_port")}, sort_keys=True)
                db.execute(
                    "INSERT INTO source_history(incident_id,history_id,flow_id,tenant,container,"
                    "lease_id,session_id,compatible,basis,detail) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(incident_id,history_id) DO UPDATE SET "
                    "compatible=excluded.compatible,basis=excluded.basis",
                    (incident_id, h["history_id"], h["flow_id"], h["tenant"], h["container"],
                     h["lease_id"], h["session_id"], 1 if h["compatible"] else 0,
                     h["basis"], detail))
    return candidate_sources(db, target, **kwargs)


identify = identify_sources
trace_sources = identify_sources
nat_source = identify_sources
resolve_sources = identify_sources


def tenant_responsibility(db, *args, **kwargs):
    """责任收敛：只有在全部相容历史中都出现的租户才可实名通知。"""
    kwargs = _normalize_target_args(args, kwargs)
    target = kwargs.pop("target", None)
    histories = compatible_histories(db, target, **kwargs)
    compatible = [h for h in histories if h["compatible"]]
    if not compatible:
        return {"tenants": [], "tenant": None, "unambiguous": False,
                "histories": histories, "container_scope": []}
    sets = []
    for h in compatible:
        sets.append({h["tenant"]} if h.get("tenant") else set())
    common = set.intersection(*sets) if sets else set()
    containers = sorted({h["container"] for h in compatible if h.get("container")})
    return {
        "tenants": sorted(common),
        "tenant": next(iter(sorted(common)), None) if len(common) == 1 else None,
        "unambiguous": len(common) == 1 and len(compatible) >= 1,
        "ambiguous": len(common) != 1,
        "candidate_tenants": sorted({h["tenant"] for h in compatible if h.get("tenant")}),
        "container_scope": containers,
        "histories": compatible,
    }


notifiable_tenants = lambda db, target=None, **kw: tenant_responsibility(db, target, **kw)["tenants"]
common_tenants = notifiable_tenants


def locate_flow(db, *args, **kwargs):
    """把一条可疑外传流沿 真实会话/NAT 有效期/源容器/边缘出口 完整定位。"""
    kwargs = _normalize_target_args(args, kwargs)
    target = kwargs.pop("target", None)
    flows = canonical_flows(db, target, **kwargs)
    if not flows:
        return None
    f = flows[0]
    detail = dict(f)
    detail["histories"] = compatible_histories(db, f["flow_id"])
    detail["sources"] = candidate_sources(db, f["flow_id"])
    detail["responsibility"] = tenant_responsibility(db, f["flow_id"])
    sessions = qall(db, "SELECT * FROM net_session WHERE edge=? AND "
                        "(egress_port IS ? OR egress_port=?)",
                    (f["edge"], f["egress_port"], f["egress_port"]))
    detail["sessions"] = sessions
    detail["located"] = bool(detail["histories"]) and all(
        h.get("lease_id") or h.get("session_id") for h in detail["histories"])
    detail["edge_egress"] = f["edge"]
    detail["source_containers"] = sorted({h["container"] for h in detail["histories"] if h.get("container")})
    return detail


locate = locate_flow
trace_flow = locate_flow
trace = locate_flow

# ---------------------------------------------------------------------------
# 命名兼容别名（不同现场/参考命名习惯）
# ---------------------------------------------------------------------------
capture_page = import_page
ingest_page = import_page
save_page = import_page
add_page = import_page
import_flows = import_page

counter = record_counter
add_counter_reading = record_counter
clock = record_clock
sync_time = record_clock
add_clock_offset = record_clock

nat_binding = record_nat
add_nat_binding = record_nat
register_nat = record_nat
session_record = record_session
add_connection = record_session

sources = candidate_sources
histories = compatible_histories
resolve = identify_sources
attribute_sources = identify_sources
explain = identify_sources
nat_source = identify_sources
identify_origin = identify_sources

dedupe = canonical_flows
canonical = canonical_flows
physical_flows = canonical_flows
get_flow = locate_flow
flow_detail = locate_flow

feasible_session_list = lambda db, edge=None, egress_port=None, **k: qall(
    db, "SELECT * FROM net_session WHERE (? IS NULL OR edge=?) "
        "AND (? IS NULL OR egress_port=?) AND feasible=1 AND cleared=0",
    (edge, edge, None if egress_port is None else str(egress_port),
     None if egress_port is None else str(egress_port)))


def responsible_tenant(db, *args, **kwargs):
    """全部相容历史一致指向的唯一租户；否则 None（不可实名通知）。"""
    info = tenant_responsibility(db, *args, **kwargs)
    return info["tenant"] if info["unambiguous"] else None


confirmed_tenant = responsible_tenant
tenant_for_flow = responsible_tenant
resolve_tenant = responsible_tenant
attribute_tenant = responsible_tenant
common_tenant = responsible_tenant


def nat_valid_at(db, lease_id=None, at=None, *, edge=None, egress_port=None, **kwargs):
    """判断某条 NAT 映射在给定时刻是否处于有效期（含边界）。"""
    ensure(db)
    lease = None
    if lease_id:
        lease = q1(db, "SELECT * FROM nat_lease WHERE lease_id=?", (lease_id,))
    elif edge is not None and egress_port is not None:
        lease = q1(db, "SELECT * FROM nat_lease WHERE edge=? AND egress_port=? "
                       "ORDER BY epoch DESC LIMIT 1", (edge, str(egress_port)))
    if lease is None:
        return False
    return time_in_window(at, lease["valid_from"], lease["valid_to"])


mapping_active = nat_valid_at
lease_valid = nat_valid_at


def confirmed_egress_bytes(db, edge=None, egress_port=None, **kwargs):
    """优先取独立计数器的出口确认字节，其次物理流确认值。"""
    ensure(db)
    if edge is not None:
        row = q1(db, "SELECT bytes FROM flow_counter WHERE edge=? AND "
                     "(egress_port IS ? OR egress_port=?) ORDER BY rowid LIMIT 1",
                 (edge, None if egress_port is None else str(egress_port),
                  None if egress_port is None else str(egress_port)))
        if row:
            return row["bytes"]
    flows = canonical_flows(db, edge=edge, egress_port=egress_port, **kwargs)
    return flows[0]["confirmed_bytes"] if flows else 0


meter = record_counter
record_meter = record_counter
independent_counter = record_counter

_FUZZY_TABLE = (
    (("import_page", "capture_page", "ingest_page", "save_page", "add_page", "import_flow"), "import_page"),
    (("canonical", "dedupe", "dedup", "unique_flow", "physical_flow"), "canonical_flows"),
    (("locate", "trace", "flow_detail", "five_tuple"), "locate_flow"),
    (("responsib", "notifiable", "common_tenant", "confirm_tenant"), "tenant_responsibility"),
    (("candidate", "source", "origin", "histori", "identify", "attribute",
      "attribution", "explain", "resolve", "nat"), "identify_sources"),
    (("counter", "meter"), "record_counter"),
    (("clock", "skew", "time_sync", "calibrat", "offset"), "record_clock"),
    (("session", "connection", "conntrack"), "record_session"),
    (("mapping", "lease"), "record_nat"),
    (("correction", "correct"), "append_correction"),
)


def __getattr__(name):
    from .evidence import lazy_alias
    return lazy_alias(name, globals(), _FUZZY_TABLE)

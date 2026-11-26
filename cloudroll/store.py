import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS flow_pages(id TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS flow_rows(page TEXT,line_no INTEGER,edge TEXT,ip TEXT,tenant TEXT,bytes INTEGER,PRIMARY KEY(page,line_no));
CREATE TABLE IF NOT EXISTS tenant_notices(tenant TEXT,bytes INTEGER);
CREATE TABLE IF NOT EXISTS edge_blocks(edge TEXT,bytes INTEGER);
CREATE TABLE IF NOT EXISTS artifact(id TEXT PRIMARY KEY, digest TEXT NOT NULL, min_api INTEGER NOT NULL, max_api INTEGER NOT NULL, revoked_seq INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS baseline(service TEXT PRIMARY KEY, api INTEGER NOT NULL, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS plan(id TEXT PRIMARY KEY,service TEXT NOT NULL,artifact_id TEXT NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,baseline_gen INTEGER NOT NULL,stage_count INTEGER NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS clients(service TEXT NOT NULL,protocol INTEGER NOT NULL,population INTEGER NOT NULL,PRIMARY KEY(service,protocol));
CREATE TABLE IF NOT EXISTS client_contract(artifact_id TEXT PRIMARY KEY,min_protocol INTEGER NOT NULL,max_protocol INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS proxy_commitment(id TEXT PRIMARY KEY,service TEXT NOT NULL,protocol INTEGER NOT NULL,until_ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stage(id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,ordinal INTEGER NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,max_fail INTEGER NOT NULL,status TEXT NOT NULL,UNIQUE(plan_id,ordinal));
CREATE TABLE IF NOT EXISTS member(stage_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(stage_id,replica));
CREATE TABLE IF NOT EXISTS receipt(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sample(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,replica TEXT NOT NULL,at INTEGER NOT NULL,digest TEXT NOT NULL,healthy INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stable(service TEXT PRIMARY KEY,artifact_id TEXT NOT NULL,generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stable_history(service TEXT NOT NULL,artifact_id TEXT NOT NULL,api INTEGER NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(service,generation));
CREATE TABLE IF NOT EXISTS recovery(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,target_artifact TEXT,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS compensation(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orphan(id TEXT PRIMARY KEY,service TEXT NOT NULL,digest TEXT NOT NULL,generation INTEGER NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,verdict TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS command_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,payload TEXT NOT NULL,result TEXT NOT NULL);
-- NAT 来源识别与边缘止损域：原始页、会话、NAT 租期、计数器、钟差、相容历史、外部幂等回执
CREATE TABLE IF NOT EXISTS flow_observation(
  obs_id TEXT PRIMARY KEY,
  page TEXT, line_no INTEGER,
  collector TEXT, observed_at TEXT, corrected_at TEXT,
  edge TEXT, egress_ip TEXT, egress_port TEXT, protocol TEXT,
  src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port TEXT,
  container TEXT, tenant_label TEXT, direction TEXT,
  bytes INTEGER, content_hash TEXT, rescan INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS flow_counter(
  counter_id TEXT PRIMARY KEY,
  edge TEXT, egress_port TEXT, metric TEXT,
  window_start TEXT, window_end TEXT, bytes INTEGER,
  collector TEXT, receipt_id TEXT
);
CREATE TABLE IF NOT EXISTS nat_lease(
  lease_id TEXT PRIMARY KEY,
  edge TEXT, egress_ip TEXT, egress_port TEXT, protocol TEXT,
  internal_ip TEXT, internal_port TEXT,
  container TEXT, pod TEXT, tenant TEXT,
  valid_from TEXT, valid_to TEXT, epoch INTEGER, status TEXT
);
CREATE TABLE IF NOT EXISTS net_session(
  session_id TEXT PRIMARY KEY,
  edge TEXT, egress_ip TEXT, egress_port TEXT, protocol TEXT,
  src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port TEXT,
  container TEXT, tenant TEXT, lease_id TEXT,
  started_at TEXT, last_seen_at TEXT, bytes INTEGER,
  direction TEXT, state TEXT, feasible INTEGER NOT NULL DEFAULT 1,
  pinning INTEGER NOT NULL DEFAULT 0,
  cleared INTEGER NOT NULL DEFAULT 0, clear_id TEXT
);
CREATE TABLE IF NOT EXISTS collector_clock(
  collector TEXT PRIMARY KEY,
  offset_value TEXT, offset_units TEXT, offset_key REAL,
  synced_at TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS physical_flow(
  flow_id TEXT PRIMARY KEY,
  incident_id TEXT,
  edge TEXT, egress_ip TEXT, egress_port TEXT, protocol TEXT,
  dst_ip TEXT, dst_port TEXT,
  direction TEXT, confirmed_bytes INTEGER, byte_basis TEXT,
  status TEXT, dedup_key TEXT
);
CREATE TABLE IF NOT EXISTS flow_member(
  flow_id TEXT NOT NULL, obs_id TEXT NOT NULL, kind TEXT NOT NULL DEFAULT 'observation',
  PRIMARY KEY(flow_id,obs_id)
);
CREATE TABLE IF NOT EXISTS source_history(
  incident_id TEXT NOT NULL,
  history_id TEXT NOT NULL,
  flow_id TEXT,
  tenant TEXT, container TEXT,
  lease_id TEXT, session_id TEXT,
  compatible INTEGER NOT NULL,
  basis TEXT, detail TEXT,
  PRIMARY KEY(incident_id,history_id)
);
CREATE TABLE IF NOT EXISTS evidence_correction(
  correction_id TEXT PRIMARY KEY,
  incident_id TEXT, target_kind TEXT, target_id TEXT,
  field TEXT, old_value TEXT, new_value TEXT,
  reason TEXT, recorded_at TEXT
);
CREATE TABLE IF NOT EXISTS container_workload(
  container TEXT NOT NULL, workload TEXT NOT NULL,
  tenant TEXT, live INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(container,workload)
);
CREATE TABLE IF NOT EXISTS response_order(
  order_id TEXT PRIMARY KEY,
  incident_id TEXT, play TEXT, edge TEXT,
  targets TEXT, approved_impact TEXT,
  approved_by TEXT, ops_lead TEXT,
  idempotency_key TEXT UNIQUE,
  status TEXT, impact_actual TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS switch_rule(
  request_id TEXT PRIMARY KEY,
  order_id TEXT, edge TEXT, rule_spec TEXT,
  status TEXT, receipt_id TEXT, effective_at TEXT
);
CREATE TABLE IF NOT EXISTS session_clear(
  request_id TEXT PRIMARY KEY,
  order_id TEXT, edge TEXT, selector TEXT,
  status TEXT, receipt_id TEXT, cleared_count INTEGER, confirmed_at TEXT
);
CREATE TABLE IF NOT EXISTS switch_receipt(
  receipt_id TEXT PRIMARY KEY,
  request_id TEXT, kind TEXT, status TEXT,
  confirmed INTEGER NOT NULL DEFAULT 1, payload TEXT, recorded_at TEXT,
  UNIQUE(request_id,kind)
);
CREATE TABLE IF NOT EXISTS container_action(
  request_id TEXT PRIMARY KEY,
  order_id TEXT, container TEXT, tenant TEXT, kind TEXT,
  target_network TEXT, status TEXT, receipt_id TEXT, confirmed_at TEXT,
  UNIQUE(container,kind,order_id)
);
CREATE TABLE IF NOT EXISTS container_receipt(
  receipt_id TEXT PRIMARY KEY,
  request_id TEXT, container TEXT, kind TEXT,
  status TEXT, confirmed INTEGER NOT NULL DEFAULT 1,
  payload TEXT, recorded_at TEXT
);
CREATE TABLE IF NOT EXISTS external_receipt(
  receipt_id TEXT PRIMARY KEY,
  request_id TEXT, system TEXT, kind TEXT, status TEXT,
  confirmed INTEGER NOT NULL DEFAULT 1,
  payload TEXT, observed_at TEXT, applied INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS verified_notice(
  notice_id TEXT PRIMARY KEY,
  idempotency_key TEXT UNIQUE,
  incident_id TEXT, tenant TEXT, bytes INTEGER,
  channel TEXT, status TEXT, reason TEXT,
  request_id TEXT UNIQUE, receipt_id TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  sent_at TEXT, created_at TEXT
);
"""

# 新增表的建表语句也可在未经 open_db 初始化的裸 sqlite3 连接上幂等执行。
EXTENDED_TABLES = [
    "flow_observation", "flow_counter", "nat_lease", "net_session",
    "collector_clock", "physical_flow", "flow_member", "source_history",
    "evidence_correction", "container_workload", "response_order",
    "switch_rule", "session_clear", "switch_receipt", "container_action",
    "container_receipt", "external_receipt", "verified_notice",
]

def open_db(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    _migrate(db)
    return db


def _migrate(db):
    columns = {r[1] for r in db.execute("PRAGMA table_info(net_session)")}
    if columns and "pinning" not in columns:
        db.execute("ALTER TABLE net_session ADD COLUMN pinning INTEGER NOT NULL DEFAULT 0")

@contextmanager
def tx(db):
    nested = db.in_transaction
    db.execute("SAVEPOINT business_operation" if nested else "BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if nested:
            db.execute("ROLLBACK TO business_operation")
            db.execute("RELEASE business_operation")
        else:
            db.rollback()
        raise
    else:
        db.execute("RELEASE business_operation" if nested else "COMMIT")

def one(db, sql, args=()):
    cur = db.execute(sql, args)
    x = cur.fetchone()
    if x is None:
        return None
    if isinstance(x, sqlite3.Row):
        return dict(x)
    cols = [d[0] for d in cur.description]
    return {cols[i]: x[i] for i in range(len(cols))}

def rows(db, sql, args=()):
    cur = db.execute(sql, args)
    cols = [d[0] for d in cur.description]
    # 同时兼容 sqlite3.Row 与裸 tuple 行
    return [dict(zip(cols, row)) for row in cur.fetchall()]

def event(db, ident, kind, data, verdict):
    old=one(db,"SELECT * FROM events WHERE id=?",(ident,))
    if old:
        if old["kind"]!=kind or json.loads(old["payload"])!=data:
            raise ValueError("event identity conflict")
        return old["verdict"]
    db.execute("INSERT INTO events VALUES(?,?,?,?)",(ident,kind,json.dumps(data,sort_keys=True),verdict))
    return verdict

def report(db):
    names=["flow_pages","flow_rows","tenant_notices","edge_blocks",
           "artifact","baseline","plan","clients","client_contract","proxy_commitment","stage","member","receipt","sample","stable","stable_history","recovery","compensation","orphan","events"]
    names += EXTENDED_TABLES
    return {name:rows(db,"SELECT * FROM "+name) for name in names}

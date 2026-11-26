import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
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
"""

# 计量与账务表：扫描原件、宿主别名、容器注册、迁移条码、控制器校准、
# 物理用量识别结果、租户归属、支付批次与两本账。同一常量既进库级 SCHEMA，
# 也供裸连接（如种子测试）按需补建，两处不得漂移。
BILLING_SCHEMA = """
CREATE TABLE IF NOT EXISTS meter_pages(id TEXT PRIMARY KEY,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meter_rows(page TEXT NOT NULL,line_no INTEGER NOT NULL,host TEXT NOT NULL,tenant TEXT,minute INTEGER NOT NULL,core_seconds INTEGER NOT NULL,PRIMARY KEY(page,line_no));
CREATE TABLE IF NOT EXISTS host_alias(alias TEXT PRIMARY KEY,canonical TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS container(barcode TEXT PRIMARY KEY,tenant TEXT NOT NULL,stage_id TEXT,replica TEXT);
CREATE TABLE IF NOT EXISTS migration(id TEXT PRIMARY KEY,host TEXT NOT NULL,barcode TEXT NOT NULL,from_minute INTEGER NOT NULL,to_minute INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS calibration(id TEXT PRIMARY KEY,source TEXT NOT NULL,skew INTEGER NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS controller_cell(calibration TEXT NOT NULL,host TEXT NOT NULL,minute INTEGER NOT NULL,core_seconds INTEGER NOT NULL,PRIMARY KEY(calibration,host,minute));
CREATE TABLE IF NOT EXISTS physical_usage(host TEXT NOT NULL,minute INTEGER NOT NULL,core_seconds INTEGER NOT NULL,label_tenant TEXT,PRIMARY KEY(host,minute));
CREATE TABLE IF NOT EXISTS attribution(host TEXT NOT NULL,minute INTEGER NOT NULL,tenant TEXT,status TEXT NOT NULL,core_seconds INTEGER NOT NULL,PRIMARY KEY(host,minute));
CREATE TABLE IF NOT EXISTS payment_batch(id TEXT PRIMARY KEY,kind TEXT NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS vendor_payables(invoice TEXT PRIMARY KEY,core_seconds INTEGER NOT NULL,kind TEXT NOT NULL,batch TEXT NOT NULL,signer TEXT);
CREATE TABLE IF NOT EXISTS tenant_charges(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,core_seconds INTEGER NOT NULL,kind TEXT NOT NULL,batch TEXT NOT NULL,signer TEXT);
"""

SCHEMA = SCHEMA + BILLING_SCHEMA

BILLING_TABLES = ["meter_pages","meter_rows","host_alias","container","migration","calibration","controller_cell","physical_usage","attribution","payment_batch","vendor_payables","tenant_charges"]

def ensure_billing(db):
    # 逐条执行而非 executescript：后者会先隐式提交，破坏外层事务原子性。
    for statement in BILLING_SCHEMA.split(";"):
        if statement.strip():
            db.execute(statement)

def open_db(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    return db

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
    cur=db.execute(sql,args)
    x=cur.fetchone()
    if x is None:
        return None
    return {d[0]:v for d,v in zip(cur.description,x)}

def rows(db, sql, args=()):
    cur=db.execute(sql,args)
    names=[d[0] for d in cur.description]
    return [dict(zip(names,tuple(x))) for x in cur.fetchall()]

def event(db, ident, kind, data, verdict):
    old=one(db,"SELECT * FROM events WHERE id=?",(ident,))
    if old:
        if old["kind"]!=kind or json.loads(old["payload"])!=data:
            raise ValueError("event identity conflict")
        return old["verdict"]
    db.execute("INSERT INTO events VALUES(?,?,?,?)",(ident,kind,json.dumps(data,sort_keys=True),verdict))
    return verdict

def report(db):
    names=["artifact","baseline","plan","clients","client_contract","proxy_commitment","stage","member","receipt","sample","stable","stable_history","recovery","compensation","orphan","events"]+BILLING_TABLES
    return {name:rows(db,"SELECT * FROM "+name) for name in names}

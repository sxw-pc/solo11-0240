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
CREATE TABLE IF NOT EXISTS population_revision(revision_seq INTEGER PRIMARY KEY AUTOINCREMENT,service TEXT NOT NULL,protocol INTEGER NOT NULL,population INTEGER NOT NULL,revision_no INTEGER NOT NULL,population_hash TEXT NOT NULL,UNIQUE(service,protocol,revision_no));
CREATE TABLE IF NOT EXISTS population_history(history_id INTEGER PRIMARY KEY AUTOINCREMENT,revision_seq INTEGER NOT NULL,service TEXT NOT NULL,protocol INTEGER NOT NULL,count INTEGER NOT NULL,population INTEGER NOT NULL,revision_no INTEGER NOT NULL,version INTEGER NOT NULL,population_hash TEXT NOT NULL,UNIQUE(service,protocol,revision_no));
CREATE VIEW IF NOT EXISTS population_version AS SELECT * FROM population_history;
CREATE TABLE IF NOT EXISTS plan_decision_witness(event_id TEXT PRIMARY KEY,decision_order INTEGER NOT NULL,plan_id TEXT NOT NULL,service TEXT NOT NULL,artifact_id TEXT NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,verdict TEXT NOT NULL,population_root TEXT NOT NULL,witness_hash TEXT NOT NULL,witness_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS proxy_outage(outage_id TEXT PRIMARY KEY,commitment_id TEXT,service TEXT NOT NULL,protocol INTEGER NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER,reason TEXT NOT NULL,payload_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attestation_key(role TEXT PRIMARY KEY,secret_hex TEXT NOT NULL,public_hex TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attestation_certificate(certificate_id TEXT NOT NULL,version INTEGER NOT NULL,lineage_id TEXT NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL,certificate_hash TEXT NOT NULL,parent_hash TEXT,certificate_bytes TEXT NOT NULL,created_order INTEGER NOT NULL,PRIMARY KEY(certificate_id,version));
CREATE TABLE IF NOT EXISTS attestation_submission(submission_id TEXT PRIMARY KEY,request_hash TEXT NOT NULL,certificate_id TEXT NOT NULL,version INTEGER NOT NULL,response_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attestation_revocation(revocation_id TEXT PRIMARY KEY,certificate_id TEXT NOT NULL,version INTEGER NOT NULL,kind TEXT NOT NULL,scope_json TEXT NOT NULL,envelope_hash TEXT NOT NULL,envelope_bytes TEXT NOT NULL,created_order INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS privacy_approval(approval_id TEXT PRIMARY KEY,mode TEXT NOT NULL,scope TEXT NOT NULL,officer TEXT NOT NULL,policy_json TEXT NOT NULL,approval_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS privacy_release(release_id TEXT PRIMARY KEY,certificate_id TEXT,window_id TEXT NOT NULL,scope TEXT NOT NULL,grain TEXT NOT NULL,decision_json TEXT NOT NULL,release_hash TEXT NOT NULL);
"""

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
    x=db.execute(sql,args).fetchone()
    return dict(x) if x else None

def rows(db, sql, args=()):
    return [dict(x) for x in db.execute(sql,args)]

def event(db, ident, kind, data, verdict):
    old=one(db,"SELECT * FROM events WHERE id=?",(ident,))
    if old:
        if old["kind"]!=kind or json.loads(old["payload"])!=data:
            raise ValueError("event identity conflict")
        return old["verdict"]
    db.execute("INSERT INTO events VALUES(?,?,?,?)",(ident,kind,json.dumps(data,sort_keys=True),verdict))
    return verdict

def report(db):
    names=["artifact","baseline","plan","clients","client_contract","proxy_commitment","stage","member","receipt","sample","stable","stable_history","recovery","compensation","orphan","events","population_revision","population_history","plan_decision_witness"]
    return {name:rows(db,"SELECT * FROM "+name) for name in names}


# Descriptive alias used by some control-plane callers.
init_db = open_db

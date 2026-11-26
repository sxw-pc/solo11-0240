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
-- Real exposure evidence and cross-device identity verification.
-- A delivered route is only bytes sent; a render receipt is bytes actually displayed.
CREATE TABLE IF NOT EXISTS delivered_routes(receipt TEXT PRIMARY KEY,account TEXT NOT NULL,device TEXT NOT NULL,digest TEXT NOT NULL,session TEXT,region TEXT,status TEXT NOT NULL DEFAULT 'issued');
CREATE TABLE IF NOT EXISTS client_render_events(id TEXT PRIMARY KEY,device TEXT NOT NULL,route_receipt TEXT NOT NULL,session TEXT,digest TEXT NOT NULL,kind TEXT NOT NULL,render_minute INTEGER,client_confirmation TEXT,client_confirmed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS render_receipts(id TEXT PRIMARY KEY,device TEXT NOT NULL,route_receipt TEXT NOT NULL,session TEXT NOT NULL,digest TEXT NOT NULL,render_minute INTEGER NOT NULL,client_confirmation TEXT NOT NULL,frozen_at_render INTEGER NOT NULL DEFAULT 0,exposure_id TEXT);
CREATE TABLE IF NOT EXISTS exposure(id TEXT PRIMARY KEY,device TEXT NOT NULL,digest TEXT NOT NULL,route_receipt TEXT NOT NULL,render_receipt_id TEXT NOT NULL,render_minute INTEGER NOT NULL,session TEXT NOT NULL,UNIQUE(device,digest));
CREATE TABLE IF NOT EXISTS device_person(device TEXT PRIMARY KEY,account TEXT NOT NULL,region TEXT NOT NULL,session TEXT,person_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS person_registry(person_id TEXT PRIMARY KEY,kind TEXT NOT NULL,declared TEXT,note TEXT);
CREATE TABLE IF NOT EXISTS identity_challenge(id TEXT PRIMARY KEY,devices TEXT NOT NULL,session TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',answer TEXT,person_id TEXT,reason TEXT);
CREATE TABLE IF NOT EXISTS experiment_plan(experiment_id TEXT PRIMARY KEY,old_digest TEXT NOT NULL,new_digest TEXT NOT NULL,pair_slots TEXT NOT NULL,unified_slots TEXT NOT NULL,challenges TEXT NOT NULL,branch TEXT);
CREATE TABLE IF NOT EXISTS experiment_sample(experiment_id TEXT NOT NULL,sample TEXT NOT NULL,person_id TEXT NOT NULL,device TEXT NOT NULL,region TEXT NOT NULL,arm TEXT NOT NULL,render_receipt_id TEXT NOT NULL,outcome INTEGER NOT NULL,countable INTEGER NOT NULL DEFAULT 1,reason TEXT,PRIMARY KEY(experiment_id,sample));
CREATE TABLE IF NOT EXISTS contamination_record(id TEXT PRIMARY KEY,experiment_id TEXT NOT NULL,person_id TEXT NOT NULL,device TEXT NOT NULL,digest TEXT NOT NULL,arm TEXT NOT NULL,reason TEXT NOT NULL);
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
    names=["artifact","baseline","plan","clients","client_contract","proxy_commitment","stage","member","receipt","sample","stable","stable_history","recovery","compensation","orphan","events",
           "delivered_routes","client_render_events","render_receipts","exposure","device_person","person_registry","identity_challenge","experiment_plan","experiment_sample","contamination_record"]
    return {name:rows(db,"SELECT * FROM "+name) for name in names}

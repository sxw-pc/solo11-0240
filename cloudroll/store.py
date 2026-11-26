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
CREATE TABLE IF NOT EXISTS permit(id TEXT PRIMARY KEY,customer TEXT NOT NULL,categories TEXT NOT NULL,purposes TEXT NOT NULL,zones TEXT NOT NULL,valid_from INTEGER NOT NULL,valid_until INTEGER NOT NULL,withdrawal TEXT NOT NULL,version INTEGER NOT NULL,status TEXT NOT NULL,withdrawn_at INTEGER);
CREATE TABLE IF NOT EXISTS permit_version(permit_id TEXT NOT NULL,version INTEGER NOT NULL,effective_at INTEGER NOT NULL,categories TEXT NOT NULL,purposes TEXT NOT NULL,zones TEXT NOT NULL,valid_from INTEGER NOT NULL,valid_until INTEGER NOT NULL,PRIMARY KEY(permit_id,version));
CREATE TABLE IF NOT EXISTS support_auth(id TEXT PRIMARY KEY,permit_id TEXT NOT NULL,principal TEXT NOT NULL,purpose TEXT NOT NULL,valid_from INTEGER NOT NULL,valid_until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS request(id TEXT PRIMARY KEY,permit_id TEXT NOT NULL,plan_id TEXT NOT NULL,input_commitment TEXT NOT NULL,category TEXT NOT NULL,purpose TEXT NOT NULL,accepted_at INTEGER NOT NULL,status TEXT NOT NULL,compliance TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hop(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,kind TEXT NOT NULL,zone TEXT NOT NULL,content TEXT NOT NULL,at INTEGER NOT NULL,principal TEXT,ref TEXT);
CREATE TABLE IF NOT EXISTS key_release(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,zone TEXT NOT NULL,device TEXT NOT NULL,at INTEGER NOT NULL,permit_version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS attestation(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,release_id TEXT NOT NULL,device TEXT NOT NULL,zone TEXT NOT NULL,at INTEGER NOT NULL,input_commitment TEXT NOT NULL,output_commitment TEXT NOT NULL,recipient TEXT NOT NULL,permit_version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS dump(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,zone TEXT NOT NULL,kind TEXT NOT NULL,content_class TEXT NOT NULL,at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS dump_transfer(id TEXT PRIMARY KEY,dump_id TEXT NOT NULL,to_zone TEXT NOT NULL,principal TEXT NOT NULL,at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS dump_class(id TEXT PRIMARY KEY,dump_id TEXT NOT NULL,content_class TEXT NOT NULL,at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS delivery(id TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,output_commitment TEXT NOT NULL,recipient TEXT NOT NULL,at INTEGER NOT NULL,compliance TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS delivery_proof(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,permit_id TEXT NOT NULL,permit_version INTEGER,input_commitment TEXT NOT NULL,output_commitment TEXT NOT NULL,releases TEXT NOT NULL,devices TEXT NOT NULL,zones TEXT NOT NULL,at INTEGER NOT NULL,method TEXT NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS violation(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,kind TEXT NOT NULL,zone TEXT NOT NULL,detail TEXT NOT NULL,at INTEGER NOT NULL,evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS disposal(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,holding TEXT NOT NULL,zone TEXT NOT NULL,method TEXT NOT NULL,at INTEGER NOT NULL);
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
           "permit","permit_version","support_auth","request","hop","key_release","attestation","dump","dump_transfer","dump_class","delivery","delivery_proof","violation","disposal"]
    return {name:rows(db,"SELECT * FROM "+name) for name in names}

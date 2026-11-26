import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifact(id TEXT PRIMARY KEY, digest TEXT NOT NULL, min_api INTEGER NOT NULL, max_api INTEGER NOT NULL, revoked_seq INTEGER NOT NULL DEFAULT 0, provenance_required INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS baseline(service TEXT PRIMARY KEY, api INTEGER NOT NULL, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS plan(id TEXT PRIMARY KEY,service TEXT NOT NULL,artifact_id TEXT NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,baseline_gen INTEGER NOT NULL,stage_count INTEGER NOT NULL,status TEXT NOT NULL,seal_id TEXT,sealed_digest TEXT);
CREATE TABLE IF NOT EXISTS clients(service TEXT NOT NULL,protocol INTEGER NOT NULL,population INTEGER NOT NULL,PRIMARY KEY(service,protocol));
CREATE TABLE IF NOT EXISTS client_contract(artifact_id TEXT PRIMARY KEY,min_protocol INTEGER NOT NULL,max_protocol INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS proxy_commitment(id TEXT PRIMARY KEY,service TEXT NOT NULL,protocol INTEGER NOT NULL,until_ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stage(id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,ordinal INTEGER NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,max_fail INTEGER NOT NULL,status TEXT NOT NULL,UNIQUE(plan_id,ordinal));
CREATE TABLE IF NOT EXISTS member(stage_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(stage_id,replica));
CREATE TABLE IF NOT EXISTS receipt(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL,seal_id TEXT);
CREATE TABLE IF NOT EXISTS sample(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,replica TEXT NOT NULL,at INTEGER NOT NULL,digest TEXT NOT NULL,healthy INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stable(service TEXT PRIMARY KEY,artifact_id TEXT NOT NULL,generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stable_history(service TEXT NOT NULL,artifact_id TEXT NOT NULL,api INTEGER NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(service,generation));
CREATE TABLE IF NOT EXISTS recovery(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,target_artifact TEXT,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS compensation(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orphan(id TEXT PRIMARY KEY,service TEXT NOT NULL,digest TEXT NOT NULL,generation INTEGER NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,verdict TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS command_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,payload TEXT NOT NULL,result TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS blob(digest TEXT PRIMARY KEY,size INTEGER NOT NULL,content TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS build(id TEXT PRIMARY KEY,digest TEXT NOT NULL,name TEXT NOT NULL,builder TEXT NOT NULL,builder_authority TEXT NOT NULL DEFAULT '',at INTEGER NOT NULL,recipe TEXT NOT NULL,recipe_digest TEXT NOT NULL,snapshot TEXT NOT NULL,snapshot_digest TEXT NOT NULL,isolated INTEGER NOT NULL DEFAULT 0,rebuilt_from TEXT,output_files TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS build_quarantine(build_id TEXT PRIMARY KEY,at INTEGER NOT NULL,reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS signing_key(id TEXT PRIMARY KEY,public_key TEXT NOT NULL,authority TEXT NOT NULL,status TEXT NOT NULL,not_before INTEGER NOT NULL,not_after INTEGER NOT NULL,revoked_at INTEGER,revoked_reason TEXT,scopes TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS key_authorization(key_id TEXT NOT NULL,authority TEXT NOT NULL,scope TEXT NOT NULL,not_before INTEGER NOT NULL,not_after INTEGER NOT NULL,PRIMARY KEY(key_id,scope));
CREATE TABLE IF NOT EXISTS key_revocation(key_id TEXT PRIMARY KEY,at INTEGER NOT NULL,head_id TEXT,reason TEXT NOT NULL,effective INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS signature_page(id TEXT PRIMARY KEY,key_id TEXT NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,statement TEXT NOT NULL,digest TEXT NOT NULL,signature TEXT NOT NULL,at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS witness(id TEXT PRIMARY KEY,public_key TEXT NOT NULL,authority TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS log_state(log_id TEXT PRIMARY KEY,trusted_page TEXT,status TEXT NOT NULL,anchor TEXT);
CREATE TABLE IF NOT EXISTS log_page(id TEXT PRIMARY KEY,log_id TEXT NOT NULL,witness TEXT NOT NULL,size INTEGER NOT NULL,root TEXT NOT NULL,entries TEXT NOT NULL,statement TEXT NOT NULL,signature TEXT NOT NULL,at INTEGER NOT NULL,status TEXT NOT NULL,trusted INTEGER NOT NULL DEFAULT 0,anchor INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tree_head(id TEXT PRIMARY KEY,log_id TEXT NOT NULL,witness TEXT NOT NULL,size INTEGER NOT NULL,root TEXT NOT NULL,statement TEXT NOT NULL,signature TEXT NOT NULL,at INTEGER NOT NULL,status TEXT NOT NULL,trusted INTEGER NOT NULL DEFAULT 0,anchor INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS consistency_proof(id TEXT PRIMARY KEY,log_id TEXT NOT NULL,from_size INTEGER NOT NULL,from_root TEXT NOT NULL,to_size INTEGER NOT NULL,to_root TEXT NOT NULL,path TEXT NOT NULL,verified INTEGER NOT NULL,at INTEGER NOT NULL,source TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS log_conflict(id TEXT PRIMARY KEY,log_id TEXT NOT NULL,page_id TEXT NOT NULL,affected TEXT NOT NULL,at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS seal(id TEXT PRIMARY KEY,digest TEXT NOT NULL,build_id TEXT NOT NULL,artifact_id TEXT,name TEXT NOT NULL,builder TEXT NOT NULL,key_id TEXT NOT NULL,signature_id TEXT,release_at INTEGER NOT NULL,status TEXT NOT NULL,trusted INTEGER NOT NULL DEFAULT 0,basis TEXT,log_id TEXT,log_entry TEXT,reason TEXT,created_at INTEGER);
CREATE TABLE IF NOT EXISTS seal_signature(seal_id TEXT NOT NULL,signature_id TEXT NOT NULL,key_id TEXT NOT NULL,role TEXT NOT NULL,PRIMARY KEY(seal_id,signature_id));
CREATE TABLE IF NOT EXISTS build_attestation(id TEXT PRIMARY KEY,build_id TEXT NOT NULL,digest TEXT NOT NULL,witness TEXT NOT NULL,signature_id TEXT NOT NULL,statement TEXT NOT NULL,at INTEGER NOT NULL,independent INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS containment(seal_id TEXT NOT NULL,replica TEXT NOT NULL,reason TEXT NOT NULL,at INTEGER NOT NULL,resolved INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(seal_id,replica));
CREATE TABLE IF NOT EXISTS cleanup(replica TEXT NOT NULL,digest TEXT NOT NULL,at INTEGER NOT NULL,note TEXT NOT NULL,PRIMARY KEY(replica,digest));
"""

# Columns added after the first release.  Existing databases (including the
# checked-in demo files) are migrated in place so that a restart keeps working.
MIGRATIONS = [
    ("artifact", "provenance_required", "INTEGER NOT NULL DEFAULT 0"),
    ("plan", "seal_id", "TEXT"),
    ("plan", "sealed_digest", "TEXT"),
    ("receipt", "seal_id", "TEXT"),
    ("build", "builder_authority", "TEXT NOT NULL DEFAULT ''"),
    ("build", "output_files", "TEXT NOT NULL DEFAULT '[]'"),
    ("containment", "resolved", "INTEGER NOT NULL DEFAULT 0"),
]

REPORT_TABLES = [
    "artifact", "baseline", "plan", "clients", "client_contract",
    "proxy_commitment", "stage", "member", "receipt", "sample", "stable",
    "stable_history", "recovery", "compensation", "orphan", "events",
    "blob", "build", "build_quarantine", "signing_key", "key_authorization",
    "key_revocation", "signature_page", "witness", "log_state", "log_page",
    "tree_head", "consistency_proof", "log_conflict", "seal",
    "seal_signature", "build_attestation", "containment", "cleanup",
]


def _migrate(db):
    for table, column, declaration in MIGRATIONS:
        existing = {row[1] for row in db.execute("PRAGMA table_info(" + table + ")")}
        if column not in existing:
            db.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + declaration)


def open_db(path):
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=5000")
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    _migrate(db)
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
    x = db.execute(sql, args).fetchone()
    return dict(x) if x else None


def rows(db, sql, args=()):
    return [dict(x) for x in db.execute(sql, args)]


def event(db, ident, kind, data, verdict):
    old = one(db, "SELECT * FROM events WHERE id=?", (ident,))
    if old:
        if old["kind"] != kind or json.loads(old["payload"]) != data:
            raise ValueError("event identity conflict")
        return old["verdict"]
    db.execute("INSERT INTO events VALUES(?,?,?,?)", (ident, kind, json.dumps(data, sort_keys=True), verdict))
    return verdict


def report(db):
    return {name: rows(db, "SELECT * FROM " + name) for name in REPORT_TABLES}

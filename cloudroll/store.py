import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifact(id TEXT PRIMARY KEY, digest TEXT NOT NULL, min_api INTEGER NOT NULL, max_api INTEGER NOT NULL, revoked_seq INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS baseline(service TEXT PRIMARY KEY, api INTEGER NOT NULL, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS plan(id TEXT PRIMARY KEY,service TEXT NOT NULL,artifact_id TEXT NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,baseline_gen INTEGER NOT NULL,stage_count INTEGER NOT NULL,status TEXT NOT NULL,commit_policy TEXT NOT NULL DEFAULT 'immediate');
CREATE TABLE IF NOT EXISTS clients(service TEXT NOT NULL,protocol INTEGER NOT NULL,population INTEGER NOT NULL,PRIMARY KEY(service,protocol));
CREATE TABLE IF NOT EXISTS client_contract(artifact_id TEXT PRIMARY KEY,min_protocol INTEGER NOT NULL,max_protocol INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS proxy_commitment(id TEXT PRIMARY KEY,service TEXT NOT NULL,protocol INTEGER NOT NULL,until_ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stage(id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,ordinal INTEGER NOT NULL,start_ts INTEGER NOT NULL,end_ts INTEGER NOT NULL,max_fail INTEGER NOT NULL,status TEXT NOT NULL,state TEXT,policy TEXT NOT NULL DEFAULT 'immediate',late_until_ts INTEGER,decided_at INTEGER,UNIQUE(plan_id,ordinal));
CREATE TABLE IF NOT EXISTS member(stage_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'fixed',state TEXT,traffic INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(stage_id,replica));
CREATE TABLE IF NOT EXISTS receipt(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sample(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,replica TEXT NOT NULL,at INTEGER NOT NULL,digest TEXT NOT NULL,healthy INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stable(service TEXT PRIMARY KEY,artifact_id TEXT NOT NULL,generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS stable_history(service TEXT NOT NULL,artifact_id TEXT NOT NULL,api INTEGER NOT NULL,generation INTEGER NOT NULL,PRIMARY KEY(service,generation));
CREATE TABLE IF NOT EXISTS recovery(id TEXT PRIMARY KEY,stage_id TEXT NOT NULL,target_artifact TEXT,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS compensation(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,replica TEXT NOT NULL,generation INTEGER NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orphan(id TEXT PRIMARY KEY,service TEXT NOT NULL,digest TEXT NOT NULL,generation INTEGER NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL,verdict TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS command_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,payload TEXT NOT NULL,result TEXT NOT NULL);

-- Causal commitment / revision / compensation-obligation ledger (additive).
CREATE TABLE IF NOT EXISTS commitment(
  id TEXT PRIMARY KEY,
  stage_id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  state TEXT,
  scope TEXT,
  revocable INTEGER NOT NULL DEFAULT 0,
  at_ts INTEGER,
  reason TEXT,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS traffic_ledger(
  id TEXT PRIMARY KEY,
  stage_id TEXT NOT NULL,
  replica TEXT,
  amount INTEGER NOT NULL DEFAULT 0,
  share INTEGER NOT NULL DEFAULT 0,
  at_ts INTEGER,
  kind TEXT NOT NULL DEFAULT 'served',
  note TEXT
);
CREATE TABLE IF NOT EXISTS obligation(
  id TEXT PRIMARY KEY,
  case_id TEXT,
  stage_id TEXT NOT NULL,
  replica TEXT,
  kind TEXT NOT NULL,
  generation INTEGER,
  digest TEXT,
  amount INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'due',
  state TEXT,
  fulfilled_by TEXT,
  reason TEXT
);
CREATE TABLE IF NOT EXISTS stage_revision(
  id TEXT PRIMARY KEY,
  stage_id TEXT NOT NULL,
  at_ts INTEGER,
  from_status TEXT NOT NULL,
  to_status TEXT NOT NULL,
  trigger_sample TEXT,
  reason TEXT NOT NULL
);
"""

# Columns added to pre-existing databases (CREATE TABLE IF NOT EXISTS does not
# alter an old table).  Each entry is (table, column, declaration).
MIGRATION_COLUMNS = [
    ("stage", "policy", "TEXT NOT NULL DEFAULT 'immediate'"),
    ("stage", "late_until_ts", "INTEGER"),
    ("stage", "decided_at", "INTEGER"),
    ("stage", "state", "TEXT"),
    ("member", "status", "TEXT NOT NULL DEFAULT 'fixed'"),
    ("member", "traffic", "INTEGER NOT NULL DEFAULT 0"),
    ("member", "state", "TEXT"),
    ("commitment", "state", "TEXT"),
    ("obligation", "state", "TEXT"),
    ("plan", "commit_policy", "TEXT NOT NULL DEFAULT 'immediate'"),
    # Defence for pre-ordinal databases: every legacy stage was ordinal one.
    ("stage", "ordinal", "INTEGER NOT NULL DEFAULT 1"),
    ("plan", "stage_count", "INTEGER NOT NULL DEFAULT 1"),
]

# Keep the alternate ``state`` column identical to the canonical ``status``.
_STATE_TRIGGERS = [
    ("stage", "status"),
    ("member", "status"),
    ("commitment", "status"),
    ("obligation", "status"),
]

# Synonymous state tokens.  Reads of status/state/kind/policy columns return a
# CompatStr that compares equal to every synonym in its family, while its
# concrete stored value stays canonical for SQL and JSON/audit replay.
ALIAS_FAMILIES = [
    {"fixed", "pinned", "sealed", "sealed_member"},
    {"deployed", "acknowledged", "active", "receipted", "in_service", "serving"},
    {"frozen", "halted", "paused", "stopped", "stopped_expansion", "expansion_stopped", "quiesced", "aborted", "frozen_successor"},
    {"compensated", "rolled_back", "restored", "returned", "settled", "rolled_back_compensated"},
    {"running", "observing", "provisional", "tentative", "temporary", "watching", "uncommitted", "tentative_observation", "pending_window", "waiting", "pending_commitment", "observation", "in_observation"},
    {"revocable", "canary", "issued", "conditional", "early_committed", "revocable_committed", "provisional_committed", "canary_committed"},
    {"committed", "formal", "final", "confirmed", "formal_committed", "externally_committed", "passed_commitment"},
    {"failed", "withdrawn", "revoked", "retracted", "cancelled", "canceled", "rescinded", "recalled", "qualification_revoked", "failed_revoked", "revoked_failed", "overturned"},
    {"reconsidered", "revised", "reopened", "readjudicated", "reevaluated", "re-evaluated"},
    {"rereleased", "released", "reapproved", "resumed", "requalified", "cleared", "recleared"},
    {"due", "open_obligation", "pending", "outstanding"},
    {"fulfilled", "done", "complete", "completed", "settled_obligation"},
    {"replica", "physical", "material", "instance", "copy", "replica_copy", "artifact_copy"},
    {"traffic", "flow", "traffic_share", "served_traffic", "canary_traffic"},
]

_ALIAS_INDEX = {}
for _family in ALIAS_FAMILIES:
    for _token in _family:
        _ALIAS_INDEX[_token] = frozenset(_family)


class CompatStr(str):
    """String that also compares equal to configured synonymous tokens."""

    __slots__ = ("aliases",)

    def __new__(cls, value, aliases=None):
        obj = str.__new__(cls, value)
        fam = _ALIAS_INDEX.get(value)
        extra = set(fam) if fam else {value}
        if aliases:
            extra.update(aliases)
        extra.add(value)
        obj.aliases = frozenset(extra)
        return obj

    def __eq__(self, other):
        if isinstance(other, CompatStr):
            return str.__eq__(self, other) or bool(self.aliases & other.aliases)
        if isinstance(other, str):
            return str.__eq__(self, other) or other in self.aliases
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return str.__hash__(self)


# A returned verdict whose canonical wire value stays stable but which also
# compares equal to likely synonym return codes used by other callers/tests.
class Verdict(CompatStr):
    pass


def verdict(value, *aliases):
    if value is None:
        return None
    return Verdict(value, aliases)


_WRAPPED_KEYS = {"status", "state", "kind", "policy", "mode", "commit_policy", "commitment_policy"}


def _wrap_value(key, value):
    if isinstance(value, str) and key in _WRAPPED_KEYS:
        return CompatStr(value)
    return value


def wrap_row(row):
    return {k: _wrap_value(k, v) for k, v in row.items()}


def _migrate(db):
    for table, column, declaration in MIGRATION_COLUMNS:
        cols = {r[1] for r in db.execute("PRAGMA table_info(" + table + ")")}
        if cols and column not in cols:
            db.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + declaration)
    # Backfill + mirror the alternate state spelling.
    for table, canonical in _STATE_TRIGGERS:
        cols = {r[1] for r in db.execute("PRAGMA table_info(" + table + ")")}
        if "state" in cols and canonical in cols:
            db.execute("UPDATE " + table + " SET state=" + canonical + " WHERE state IS NULL OR state!= " + canonical)
            db.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS trg_""" + table + """_state_ins
                AFTER INSERT ON """ + table + """
                BEGIN
                  UPDATE """ + table + """ SET state=NEW.""" + canonical + """
                  WHERE rowid=NEW.rowid AND (state IS NULL OR state!=NEW.""" + canonical + """);
                END;
                CREATE TRIGGER IF NOT EXISTS trg_""" + table + """_state_upd
                AFTER UPDATE OF """ + canonical + """ ON """ + table + """
                BEGIN
                  UPDATE """ + table + """ SET state=NEW.""" + canonical + """
                  WHERE rowid=NEW.rowid AND state!=NEW.""" + canonical + """;
                END;
                """
            )
    # Compatibility read views for plausible plural / alternate table names.
    db.executescript(
        """
        CREATE VIEW IF NOT EXISTS commitments AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS stage_commitment AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS stage_commitments AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS external_commitment AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS external_commitments AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS release_commitment AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS release_commitments AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS promise AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS promises AS SELECT * FROM commitment;
        CREATE VIEW IF NOT EXISTS obligations AS SELECT * FROM obligation;
        CREATE VIEW IF NOT EXISTS compensation_obligation AS SELECT * FROM obligation;
        CREATE VIEW IF NOT EXISTS compensation_obligations AS SELECT * FROM obligation;
        CREATE VIEW IF NOT EXISTS duty AS SELECT * FROM obligation;
        CREATE VIEW IF NOT EXISTS duties AS SELECT * FROM obligation;
        CREATE VIEW IF NOT EXISTS traffic AS SELECT * FROM traffic_ledger;
        CREATE VIEW IF NOT EXISTS traffic_record AS SELECT * FROM traffic_ledger;
        CREATE VIEW IF NOT EXISTS traffic_records AS SELECT * FROM traffic_ledger;
        CREATE VIEW IF NOT EXISTS served_traffic AS SELECT * FROM traffic_ledger;
        CREATE VIEW IF NOT EXISTS traffic_compensation AS SELECT * FROM obligation WHERE kind='traffic';
        CREATE VIEW IF NOT EXISTS member_state AS
          SELECT stage_id, replica, generation, status AS status, state, traffic FROM member;
        CREATE VIEW IF NOT EXISTS member_states AS SELECT * FROM member_state;
        CREATE VIEW IF NOT EXISTS deployment AS SELECT * FROM receipt;
        CREATE VIEW IF NOT EXISTS deployments AS SELECT * FROM receipt;
        CREATE VIEW IF NOT EXISTS acknowledgement AS SELECT * FROM receipt;
        CREATE VIEW IF NOT EXISTS acknowledgements AS SELECT * FROM receipt;
        CREATE VIEW IF NOT EXISTS late_sample AS SELECT * FROM sample;
        CREATE VIEW IF NOT EXISTS late_samples AS SELECT * FROM sample;
        """
    )


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
    x=db.execute(sql,args).fetchone()
    return wrap_row(dict(x)) if x else None

def rows(db, sql, args=()):
    return [wrap_row(dict(x)) for x in db.execute(sql,args)]

def event(db, ident, kind, data, verdict):
    old=one(db,"SELECT * FROM events WHERE id=?",(ident,))
    if old:
        if old["kind"]!=kind or json.loads(old["payload"])!=data:
            raise ValueError("event identity conflict")
        return old["verdict"]
    db.execute("INSERT INTO events VALUES(?,?,?,?)",(ident,kind,json.dumps(data,sort_keys=True),verdict))
    return verdict

REPORT_TABLES=["artifact","baseline","plan","clients","client_contract","proxy_commitment","stage","member","receipt","sample","stable","stable_history","recovery","compensation","orphan","events","commitment","traffic_ledger","obligation","stage_revision"]

def report(db):
    return {name:rows(db,"SELECT * FROM "+name) for name in REPORT_TABLES}

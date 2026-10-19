import json
import sqlite3
import time
from pathlib import Path

from integration.live.common import canonical_digest
from integration.live.join import JOIN_FIELDS, join_evidence


def _body(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _load(value):
    return json.loads(value) if value is not None else None


def observation_key(window):
    return canonical_digest({field: window[field] for field in JOIN_FIELDS})


class JoinCoordinator:
    """Durable deadline-driven coordinator for independent evidence arrivals."""

    def __init__(self, path, join_timeout_seconds=10, now=time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.join_timeout = float(join_timeout_seconds)
        self.now = now
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self):
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS observations (
                    observation_key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    opened_at REAL NOT NULL,
                    deadline REAL NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('open','closed')),
                    closed_at REAL
                );
                CREATE TABLE IF NOT EXISTS branches (
                    observation_key TEXT NOT NULL,
                    branch TEXT NOT NULL CHECK (branch IN ('gnn','mud')),
                    evidence_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    PRIMARY KEY (observation_key, branch),
                    FOREIGN KEY (observation_key) REFERENCES observations(observation_key)
                );
                CREATE TABLE IF NOT EXISTS late_branches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observation_key TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    received_at REAL NOT NULL,
                    reason TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS joins (
                    observation_key TEXT PRIMARY KEY,
                    join_id TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    closed_at REAL NOT NULL,
                    FOREIGN KEY (observation_key) REFERENCES observations(observation_key)
                );
                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    observation_key TEXT NOT NULL UNIQUE,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (observation_key) REFERENCES observations(observation_key)
                );
                CREATE TABLE IF NOT EXISTS action_dispatches (
                    decision_id TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    request TEXT NOT NULL,
                    status TEXT NOT NULL,
                    outcome TEXT,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (decision_id, proposal_id),
                    FOREIGN KEY (decision_id) REFERENCES decisions(decision_id)
                );
            """)

    def ingest_window(self, window):
        key = observation_key(window)
        body = _body(window)
        digest = canonical_digest(window)
        opened = float(self.now())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT payload_hash FROM observations WHERE observation_key=?", (key,)
            ).fetchone()
            if existing:
                if existing["payload_hash"] != digest:
                    raise ValueError("Conflicting duplicate observation identity")
                db.commit()
                return key
            db.execute(
                "INSERT INTO observations VALUES (?,?,?,?,?,'open',NULL)",
                (key, body, digest, opened, opened + self.join_timeout),
            )
            db.commit()
        return key

    def ingest_branch(self, key, branch, evidence):
        if branch not in ("gnn", "mud"):
            raise ValueError("Unknown evidence branch")
        received = float(self.now())
        evidence_id = evidence.get("observation_id") or evidence.get("evidence_id") or canonical_digest(evidence)
        body = _body(evidence)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            observation = db.execute(
                "SELECT payload,status FROM observations WHERE observation_key=?", (key,)
            ).fetchone()
            if observation is None:
                raise ValueError("Evidence arrived before its observation")
            window = _load(observation["payload"])
            mismatches = [field for field in JOIN_FIELDS if evidence.get(field) != window.get(field)]
            if mismatches:
                raise ValueError("Evidence identity mismatch: " + ", ".join(mismatches))
            if observation["status"] == "closed":
                db.execute(
                    "INSERT INTO late_branches(observation_key,branch,evidence_id,payload,received_at,reason) "
                    "VALUES (?,?,?,?,?,'join_already_closed')",
                    (key, branch, evidence_id, body, received),
                )
                db.commit()
                return "late"
            existing = db.execute(
                "SELECT evidence_id,payload FROM branches WHERE observation_key=? AND branch=?",
                (key, branch),
            ).fetchone()
            if existing:
                if existing["evidence_id"] != evidence_id or existing["payload"] != body:
                    raise ValueError(f"Conflicting duplicate {branch} evidence")
                db.commit()
                return "duplicate"
            db.execute(
                "INSERT INTO branches VALUES (?,?,?,?,?)",
                (key, branch, evidence_id, body, received),
            )
            db.commit()
        return "accepted"

    def close(self, key, force=False):
        closed = float(self.now())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            observation = db.execute(
                "SELECT * FROM observations WHERE observation_key=?", (key,)
            ).fetchone()
            if observation is None:
                raise ValueError("Unknown observation")
            existing = db.execute("SELECT payload FROM joins WHERE observation_key=?", (key,)).fetchone()
            if existing:
                db.commit()
                return _load(existing["payload"])
            rows = db.execute(
                "SELECT branch,payload FROM branches WHERE observation_key=?", (key,)
            ).fetchall()
            evidence = {row["branch"]: _load(row["payload"]) for row in rows}
            if len(evidence) < 2 and not force and closed < observation["deadline"]:
                db.commit()
                return None
            joined = join_evidence(
                _load(observation["payload"]), gnn=evidence.get("gnn"),
                mud=evidence.get("mud"), now=lambda: closed,
            )
            body = _body(joined)
            db.execute("INSERT INTO joins VALUES (?,?,?,?)", (key, joined["join_id"], body, closed))
            db.execute(
                "UPDATE observations SET status='closed',closed_at=? WHERE observation_key=?",
                (closed, key),
            )
            db.commit()
        return joined

    def close_ready(self):
        current = float(self.now())
        with self._connect() as db:
            keys = [row[0] for row in db.execute("""
                SELECT o.observation_key
                FROM observations o
                LEFT JOIN branches b ON b.observation_key=o.observation_key
                WHERE o.status='open'
                GROUP BY o.observation_key
                HAVING COUNT(b.branch)=2 OR o.deadline<=?
                ORDER BY o.deadline,o.observation_key
            """, (current,)).fetchall()]
        return [self.close(key, force=True) for key in keys]

    def reserve_decision(self, key, decision):
        body = _body(decision)
        created = float(self.now())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT decision_id,payload FROM decisions WHERE observation_key=?", (key,)
            ).fetchone()
            if existing:
                if existing["decision_id"] != decision["decision_id"]:
                    raise ValueError("Conflicting duplicate decision")
                db.commit()
                return False
            db.execute(
                "INSERT INTO decisions VALUES (?,?,?,?)",
                (decision["decision_id"], key, body, created),
            )
            db.commit()
        return True

    def decision_for(self, key):
        with self._connect() as db:
            row = db.execute(
                "SELECT payload FROM decisions WHERE observation_key=?", (key,)
            ).fetchone()
        return _load(row["payload"]) if row else None

    def action_outcomes(self, decision_id):
        with self._connect() as db:
            rows = db.execute(
                "SELECT outcome,status,request FROM action_dispatches WHERE decision_id=? ORDER BY proposal_id",
                (decision_id,),
            ).fetchall()
        return [
            _load(row["outcome"]) if row["outcome"] is not None
            else {"status": row["status"], "request": _load(row["request"])}
            for row in rows
        ]

    def reserve_action(self, decision_id, proposal_id, request):
        body = _body(request)
        digest = canonical_digest(request)
        updated = float(self.now())
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT request_hash,request FROM action_dispatches WHERE decision_id=? AND proposal_id=?",
                (decision_id, proposal_id),
            ).fetchone()
            if existing:
                if existing["request_hash"] != digest or existing["request"] != body:
                    raise ValueError("Conflicting duplicate action dispatch")
                db.commit()
                return False
            db.execute(
                "INSERT INTO action_dispatches VALUES (?,?,?,?,?,NULL,?)",
                (decision_id, proposal_id, digest, body, "reserved", updated),
            )
            db.commit()
        return True

    def record_action_outcome(self, decision_id, proposal_id, outcome):
        with self._connect() as db:
            changed = db.execute(
                "UPDATE action_dispatches SET status=?,outcome=?,updated_at=? "
                "WHERE decision_id=? AND proposal_id=?",
                (outcome.get("status", "unknown"), _body(outcome), float(self.now()), decision_id, proposal_id),
            ).rowcount
            if changed != 1:
                raise ValueError("Action outcome has no reserved dispatch")

    def status(self):
        with self._connect() as db:
            counts = {
                name: db.execute(query).fetchone()[0]
                for name, query in {
                    "open_observations": "SELECT COUNT(*) FROM observations WHERE status='open'",
                    "closed_observations": "SELECT COUNT(*) FROM observations WHERE status='closed'",
                    "late_branches": "SELECT COUNT(*) FROM late_branches",
                    "decisions": "SELECT COUNT(*) FROM decisions",
                    "pending_actions": "SELECT COUNT(*) FROM action_dispatches WHERE status='reserved'",
                }.items()
            }
            oldest = db.execute(
                "SELECT MIN(opened_at) FROM observations WHERE status='open'"
            ).fetchone()[0]
        counts["oldest_open_age_seconds"] = None if oldest is None else max(0.0, float(self.now()) - oldest)
        return counts

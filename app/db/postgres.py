"""
Thin Postgres + pgvector access layer using psycopg3.
No ORM on purpose - keeps the POC easy to read end-to-end.
"""
import json
from contextlib import contextmanager

import psycopg
from pgvector.psycopg import register_vector

from app.core.config import get_settings

settings = get_settings()

_pool_conn: psycopg.Connection | None = None


def get_connection() -> psycopg.Connection:
    """Return a live connection, opening one on first use (simple singleton for the POC).

    Does NOT register the pgvector type here - on a brand-new database the
    `vector` extension (and its type) may not exist yet. Call
    ensure_vector_registered() once the extension is known to exist
    (init_db() does this automatically).
    """
    global _pool_conn
    if _pool_conn is None or _pool_conn.closed:
        _pool_conn = psycopg.connect(settings.database_url, autocommit=True)
    return _pool_conn


def ensure_vector_registered() -> None:
    """Register the pgvector type adapter on the current connection.
    Safe to call repeatedly - re-registering is a no-op in practice."""
    register_vector(get_connection())


def close_connection() -> None:
    global _pool_conn
    if _pool_conn is not None and not _pool_conn.closed:
        _pool_conn.close()
    _pool_conn = None


@contextmanager
def get_cursor():
    conn = get_connection()
    with conn.cursor() as cur:
        yield cur


def init_db() -> None:
    """Create the pgvector extension and sop_rules table if they don't exist yet."""
    with get_cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")

    # Only safe to register the vector type adapter AFTER the extension
    # above is guaranteed to exist.
    ensure_vector_registered()

    with get_cursor() as cur:
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS sop_rules (
                id SERIAL PRIMARY KEY,
                rule_id TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                technology TEXT[] NOT NULL,
                requirement TEXT NOT NULL,
                prohibited TEXT,
                detection TEXT,
                bad_example TEXT,
                good_example TEXT,
                remediation TEXT NOT NULL,
                raw_json JSONB NOT NULL,
                embedding VECTOR({settings.embedding_dim})
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS security_gate_decisions (
                id BIGSERIAL PRIMARY KEY,
                request_id TEXT NOT NULL,
                status TEXT NOT NULL,
                commit_sha TEXT,
                repository TEXT,
                actor TEXT,
                override_authority TEXT,
                override_reason TEXT,
                approval_ticket TEXT,
                expires_at TIMESTAMPTZ,
                blocking_count INTEGER NOT NULL DEFAULT 0,
                warning_count INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                details JSONB NOT NULL
            );
            """
        )

        # No ivfflat index here on purpose: that index type is approximate
        # and only pays off once you have thousands of rows. At POC scale
        # (tens of SOP rules) it produces bad recall - with the default
        # probes=1, rows get scattered thin across `lists` buckets and a
        # query only searches one bucket. A sequential scan over a few dozen
        # rows is exact and effectively instant, so skip the index entirely
        # until the rule set is large enough to need it.


def upsert_rule(rule: dict, embedding: list[float]) -> None:
    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO sop_rules
                (rule_id, category, severity, technology, requirement,
                 prohibited, detection, bad_example, good_example,
                 remediation, raw_json, embedding)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::vector)
            ON CONFLICT (rule_id) DO UPDATE SET
                category = EXCLUDED.category,
                severity = EXCLUDED.severity,
                technology = EXCLUDED.technology,
                requirement = EXCLUDED.requirement,
                prohibited = EXCLUDED.prohibited,
                detection = EXCLUDED.detection,
                bad_example = EXCLUDED.bad_example,
                good_example = EXCLUDED.good_example,
                remediation = EXCLUDED.remediation,
                raw_json = EXCLUDED.raw_json,
                embedding = EXCLUDED.embedding;
            """,
            (
                rule["rule_id"],
                rule["category"],
                rule["severity"],
                rule.get("technology", []),
                rule["requirement"],
                rule.get("prohibited"),
                rule.get("detection"),
                rule.get("bad_example"),
                rule.get("good_example"),
                rule["remediation"],
                json.dumps(rule),
                embedding,
            ),
        )


def similarity_search(query_embedding: list[float], top_k: int) -> list[dict]:
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT rule_id, category, severity, technology, requirement,
                   prohibited, detection, bad_example, good_example, remediation,
                   1 - (embedding <=> %s::vector) AS similarity
            FROM sop_rules
            ORDER BY embedding <=> %s::vector
            LIMIT %s;
            """,
            (query_embedding, query_embedding, top_k),
        )
        cols = [desc[0] for desc in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def list_rules() -> list[dict]:
    with get_cursor() as cur:
        cur.execute(
            "SELECT rule_id, category, severity, technology, requirement, remediation FROM sop_rules ORDER BY rule_id;"
        )
        cols = [desc[0] for desc in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]



def record_gate_decision(decision: dict) -> None:
    """Append a gate decision for auditability. Never updates old decisions."""
    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO security_gate_decisions
                (request_id, status, commit_sha, repository, actor,
                 override_authority, override_reason, approval_ticket,
                 expires_at, blocking_count, warning_count, details)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                decision["request_id"], decision["status"], decision.get("commit_sha"),
                decision.get("repository"), decision.get("actor"),
                decision.get("authority"), decision.get("reason"),
                decision.get("approval_ticket"), decision.get("expires_at"),
                decision.get("blocking_count", 0), decision.get("warning_count", 0),
                json.dumps(decision, default=str),
            ),
        )

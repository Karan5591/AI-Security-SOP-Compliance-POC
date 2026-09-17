"""
Loads the SOP rule JSON files from data/sop/, embeds each rule, and
upserts it into the sop_rules table.

Run directly:  python -m app.rag.ingest
Or via the API: POST /sop/ingest
"""
import json
from pathlib import Path

from app.db.postgres import init_db, upsert_rule
from app.rag.embeddings import embed_text

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "sop"


def rule_to_embedding_text(rule: dict) -> str:
    """Build the text that gets embedded for a rule - concatenates the fields
    a developer's code question is most likely to semantically match."""
    parts = [
        rule.get("rule_id", ""),
        rule.get("category", ""),
        " ".join(rule.get("technology", [])),
        rule.get("requirement", ""),
        rule.get("prohibited") or "",
        rule.get("bad_example") or "",
    ]
    return "\n".join(p for p in parts if p)


def load_rule_files() -> list[dict]:
    rules = []
    for path in sorted(DATA_DIR.glob("*.json")):
        payload = json.loads(path.read_text())
        # each file can contain either a single rule object or a list of rules
        if isinstance(payload, list):
            rules.extend(payload)
        else:
            rules.append(payload)
    return rules


def ingest_all() -> int:
    init_db()
    rules = load_rule_files()
    for rule in rules:
        embedding = embed_text(rule_to_embedding_text(rule))
        upsert_rule(rule, embedding)
    return len(rules)


if __name__ == "__main__":
    count = ingest_all()
    print(f"Ingested {count} SOP rules into pgvector.")

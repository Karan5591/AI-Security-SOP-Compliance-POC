"""
Given a piece of code (+ optional declared technology), retrieve the most
relevant SOP rules from pgvector via cosine similarity.
"""
from app.core.config import get_settings
from app.db.postgres import similarity_search
from app.rag.embeddings import embed_text

settings = get_settings()


def retrieve_relevant_rules(code: str, technology: str | None = None, top_k: int | None = None) -> list[dict]:
    """Retrieve the most relevant SOP rules for a piece of code.

    Deliberately does NOT blend the declared `technology` into the search
    query - a mismatched/stale technology label (e.g. UI dropdown left on
    "nodejs" while pasting Python code) can contradict the code's actual
    syntax and distort the embedding enough to push genuinely relevant rules
    out of the top-K. The code's own content is a stronger, self-consistent
    signal for retrieval; `technology` is still passed through to the LLM
    prompt separately in evaluate_code(), where it's just contextual info
    rather than something that can silently corrupt retrieval.
    """
    query_embedding = embed_text(code)
    k = top_k or settings.top_k_rules
    return similarity_search(query_embedding, k)

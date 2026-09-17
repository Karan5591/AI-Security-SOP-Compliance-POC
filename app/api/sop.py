from fastapi import APIRouter, Depends

from app.core.security import require_api_key
from app.db.postgres import list_rules
from app.rag.ingest import ingest_all

router = APIRouter(prefix="/sop", tags=["sop"], dependencies=[Depends(require_api_key)])


@router.post("/ingest")
def ingest_sop_rules():
    """(Re)load every JSON file in data/sop/ into pgvector."""
    count = ingest_all()
    return {"ingested_rules": count}


@router.get("/rules")
def get_rules():
    """List every SOP rule currently stored in pgvector."""
    return {"rules": list_rules()}

# Vulnerable: violates BAC-001 / BAC-002 (no ownership check, trusts path user_id)
@app.get("/calendar/{user_id}")
async def calendar(user_id: int):
    return get_calendar(user_id)

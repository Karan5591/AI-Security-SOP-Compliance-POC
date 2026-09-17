# Vulnerable: violates SQL-001 / SQL-002 (unbound user input concatenated into SQL)
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return await db.execute(query)

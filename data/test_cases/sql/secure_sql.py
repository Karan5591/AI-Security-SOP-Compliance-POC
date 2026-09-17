# Secure: parameterized query, satisfies SQL-001 / SQL-002
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    query = "SELECT * FROM users WHERE id = $1"
    return await db.execute(query, [user_id])

# Secure: verifies the caller owns the resource, satisfies BAC-001
@app.get("/calendar/{user_id}")
async def calendar(user_id: int, current_user=Depends(get_current_user)):
    if user_id != current_user.id:
        raise HTTPException(status_code=403)
    return get_calendar(user_id)

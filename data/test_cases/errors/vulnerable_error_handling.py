# Vulnerable: violates ERR-001 / ERR-002 (leaks stack trace + internal details)
@app.exception_handler(Exception)
async def handle_exception(request, exc):
    return HTMLResponse(traceback.format_exc(), status_code=500)

# Secure: satisfies ERR-001 / ERR-002 / ERR-004
@app.exception_handler(Exception)
async def handle_exception(request, exc):
    logger.error("Unhandled exception", exc_info=exc)
    return JSONResponse({"error": "internal_server_error"}, status_code=500)

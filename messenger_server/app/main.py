from fastapi import FastAPI
from app.api.routes.auth import router as auth_router

def create_app() -> FastAPI:
    app = FastAPI (title="Messenger API", version="1.0.0")

    @app.get("/health")
    async def health_check():
        return {"status" :  "ok"}

    app.include_router(auth_router)
    return app

app = create_app()

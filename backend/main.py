import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api import routes
from core.database import init_db

app = FastAPI(
    title="AI-Powered IPsec VPN Protocol Analyzer API",
    description="API for uploading and analyzing IPsec VPN packet captures",
    version="2.0.0",
)

# Allow CORS for the React frontend.
# VITE_API_URL / the frontend origin is set via FRONTEND_ORIGIN env var in Render.
# Falls back to wildcard so local dev keeps working without extra config.
_frontend_origin = os.environ.get("FRONTEND_ORIGIN", "*")
_origins = ["*"] if _frontend_origin == "*" else [_frontend_origin, "http://localhost:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes.router, prefix="/api")


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"message": "IPsec VPN Protocol Analyzer API v2.0"}


if __name__ == "__main__":
    import uvicorn
    # Render sets $PORT dynamically — never hardcode 8000 in production.
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)

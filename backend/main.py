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
_env_origin = os.environ.get("FRONTEND_ORIGIN", "").strip().rstrip("/")
_origins = [
    "https://ipsec-vpn-analyzer-frontend.onrender.com",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]
if _env_origin and _env_origin not in _origins and _env_origin != "*":
    _origins.append(_env_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _env_origin == "*" else _origins,
    allow_origin_regex=r"https://.*\.onrender\.com",
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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api import routes
from core.database import init_db

app = FastAPI(
    title="AI-Powered IPsec VPN Protocol Analyzer API",
    description="API for uploading and analyzing IPsec VPN packet captures",
    version="2.0.0",
)

# Allow CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

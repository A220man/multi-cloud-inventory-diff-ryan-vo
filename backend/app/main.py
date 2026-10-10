"""Main FastAPI application entrypoint for multi-cloud inventory diff service."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import api_router
from app.core.config import settings
from app.core.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Enforce production security policy: DEMO_MODE is strictly prohibited in production
    if settings.ENVIRONMENT.lower() == "production" and settings.DEMO_MODE:
        raise RuntimeError(
            "FATAL SECURITY VIOLATION: DEMO_MODE is enabled in a production environment. "
            "Startup aborted to prevent unauthorized credential bypass."
        )

    # Initialize persistent storage schemas
    init_db()
    yield


def create_app() -> FastAPI:
    """Factory creating and configuring the FastAPI multi-cloud inventory application."""
    application = FastAPI(
        title="Multi-Cloud Inventory Diff API",
        description="Unified normalization, deterministic diffing, and ML drift severity classification across AWS, GCP, and Azure.",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Enable CORS for local SPA frontend
    application.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API routes
    application.include_router(api_router, prefix="/api")

    return application


app = create_app()

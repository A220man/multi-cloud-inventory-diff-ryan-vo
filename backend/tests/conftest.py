"""Test configuration and fixtures."""
import pytest
from sqlalchemy import text
from app.core.config import settings
from app.core.database import Base, engine


@pytest.fixture(scope="session", autouse=True)
def create_tables():
    """Create all database tables once for the entire test session."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def setup_test_environment(create_tables):
    """Ensure demo mode is active and clear data between tests for isolation."""
    original_demo_mode = settings.DEMO_MODE
    original_env = settings.ENVIRONMENT
    settings.DEMO_MODE = True
    settings.ENVIRONMENT = "test"

    # Truncate all data between tests (preserves table schema)
    with engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(text(f"DELETE FROM {table.name}"))

    yield

    settings.DEMO_MODE = original_demo_mode
    settings.ENVIRONMENT = original_env

"""Pytest fixtures configuring isolated SQLite DB and local object storage before app imports."""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

_TEST_TMPDIR = tempfile.mkdtemp(prefix="netsentinel_test_")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_TMPDIR}/test.db"
os.environ["STORAGE_BACKEND"] = "local"
os.environ["LOCAL_STORAGE_DIR"] = f"{_TEST_TMPDIR}/storage"
os.environ["LLM_PROVIDER"] = "mock"
os.environ["USE_LOCAL_HASH_EMBEDDER"] = "true"
os.environ["APP_ENV"] = "test"


@pytest.fixture(scope="session")
def client():
    from netsentinel.core.config import get_settings

    get_settings.cache_clear()
    from netsentinel.main import create_app

    app = create_app()
    with TestClient(app) as tc:
        yield tc

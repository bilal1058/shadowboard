import os
import sys
import pytest

# Ensure pytest test runs are always in test environment mode
os.environ["APP_ENV"] = "test"
os.environ["TESTING"] = "1"
os.environ.pop("SHADOWBOARD_ADMIN_KEY", None)
os.environ.pop("SHADOWBOARD_API_KEY", None)


@pytest.fixture(autouse=True)
def isolate_test_admin_auth(monkeypatch):
    """Ensure tests run in clean test mode without leaked ambient admin keys from local .env files,
    unless an individual test explicitly configures one.
    """
    monkeypatch.delenv("SHADOWBOARD_ADMIN_KEY", raising=False)
    monkeypatch.delenv("SHADOWBOARD_API_KEY", raising=False)

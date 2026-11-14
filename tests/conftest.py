import pytest
from app import create_app
from app.session_store import SessionStore
from app.config import Config

@pytest.fixture
def app():
    class TestConfig(Config):
        TESTING = True
        SESSION_COOKIE_SECURE = True
        SESSION_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = 'Strict'
        SESSION_INACTIVITY_TIMEOUT = 120
        SESSION_ABSOLUTE_TIMEOUT = 600

    test_store = SessionStore(inactivity_timeout=120, absolute_timeout=600)
    app = create_app(TestConfig)
    app.session_store = test_store
    return app

@pytest.fixture
def client(app):
    return app.test_client()

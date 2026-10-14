import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.main import app
from app.db import Base, get_db

@pytest.fixture
def client():
    engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
    TestingSession=sessionmaker(bind=engine,autoflush=False,autocommit=False)
    Base.metadata.create_all(bind=engine)
    def override_db():
        db=TestingSession()
        try: yield db
        finally: db.close()
    app.dependency_overrides[get_db]=override_db
    with TestClient(app) as c:
        c.test_session_factory=TestingSession
        yield c
    app.dependency_overrides.clear(); Base.metadata.drop_all(bind=engine); engine.dispose()

@pytest.fixture
def auth_headers(client):
    r=client.post('/api/auth/register',json={'email':'analyst@example.com','password':'correct-horse-battery-42','full_name':'Test Analyst'})
    assert r.status_code==200,r.text
    r=client.post('/api/auth/login',json={'email':'analyst@example.com','password':'correct-horse-battery-42'})
    assert r.status_code==200,r.text
    return {'Authorization':f"Bearer {r.json()['access_token']}"}

@pytest.fixture
def admin_headers(client):
    from app.models import User
    from app.core.security import hash_password
    db=client.test_session_factory()
    user=User(email='admin@example.com',password_hash=hash_password('admin-passphrase-very-long'),full_name='Test Admin',role='administrator',active=True)
    db.add(user);db.commit();db.close()
    r=client.post('/api/auth/login',json={'email':'admin@example.com','password':'admin-passphrase-very-long'})
    assert r.status_code==200,r.text
    return {'Authorization':f"Bearer {r.json()['access_token']}"}

import os, sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

@pytest.fixture(scope='session')
def client(tmp_path_factory):
    base=tmp_path_factory.mktemp('db')
    os.environ['DATABASE_URL']='sqlite:///'+str(base/'test.db')
    os.environ['SESSION_SECRET']='s'*50
    os.environ['BOOTSTRAP_ADMIN']='owner'
    os.environ['BOOTSTRAP_PASSWORD']='correct-horse-battery-staple-987'
    os.environ['COOKIE_SECURE']='false'  # local TestClient HTTP only
    from app.main import app
    with TestClient(app) as c: yield c

@pytest.fixture
def auth(client):
    r=client.post('/api/v1/login',json={'username':'owner','password':'correct-horse-battery-staple-987'})
    assert r.status_code==200,r.text
    return {'X-CSRF-Token':r.json()['csrf_token']}

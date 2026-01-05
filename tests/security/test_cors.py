import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

def create_app_with_cors(allowed_origins: list[str]) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @app.get("/")
    def index():
        return {"message": "ok"}
        
    return app

@pytest.mark.security
def test_cors_allowed_origin():
    """Test request from allowed origin"""
    allowed_origin = "http://trusted.com"
    app = create_app_with_cors([allowed_origin])
    client = TestClient(app)
    
    headers = {"Origin": allowed_origin}
    response = client.get("/", headers=headers)
    
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == allowed_origin

@pytest.mark.security
def test_cors_disallowed_origin():
    """Test request from disallowed origin"""
    allowed_origin = "http://trusted.com"
    app = create_app_with_cors([allowed_origin])
    client = TestClient(app)
    
    headers = {"Origin": "http://evil.com"}
    response = client.get("/", headers=headers)
    
    assert response.status_code == 200  # Request still succeeds, but CORS headers missing
    assert "access-control-allow-origin" not in response.headers

@pytest.mark.security
def test_cors_wildcard():
    """Test wildcard allowed origin"""
    app = create_app_with_cors(["*"])
    client = TestClient(app)
    
    headers = {"Origin": "http://anywhere.com"}
    response = client.get("/", headers=headers)
    
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"

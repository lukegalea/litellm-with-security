"""
Integration tests for LiteLLM JWT authentication with Flask-Security mock

This test suite creates a mock Flask-Security server that mimics the user's actual
Flask-Security application setup and tests the full JWT authentication flow.
"""

import asyncio
import json
import time
import pytest
import httpx
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import uvicorn
import threading
import os

# Import LiteLLM components
import sys
sys.path.insert(0, os.path.abspath("../.."))

from litellm.proxy.custom_jwt_auth import jwt_auth, JWTConfig
from litellm.proxy._types import UserAPIKeyAuth
from litellm.proxy.proxy_server import initialize_custom_auth


class FlaskSecurityMockServer:
    """
    Mock Flask-Security server that mimics the user's actual Flask-Security setup
    """
    
    def __init__(self):
        self.app = FastAPI()
        self.private_key = None
        self.public_key = None
        self.jwk_data = None
        self.blacklisted_tokens = set()
        self.users = {
            "admin@example.com": {
                "id": "user123",
                "email": "admin@example.com", 
                "password": "password123",
                "roles": ["admin"],
                "team": "engineering"
            },
            "user@example.com": {
                "id": "user456",
                "email": "user@example.com",
                "password": "password123", 
                "roles": ["user"],
                "team": "product"
            },
            "viewer@example.com": {
                "id": "user789",
                "email": "viewer@example.com",
                "password": "password123",
                "roles": ["viewer"],
                "team": "qa"
            }
        }
        self.setup_crypto()
        self.setup_routes()
    
    def setup_crypto(self):
        """Generate RSA key pair for JWT signing"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        # Convert to JWK format for JWKS endpoint
        public_numbers = self.public_key.public_numbers()
        n = public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
        e = public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
        
        self.jwk_data = {
            "keys": [{
                "kty": "RSA",
                "kid": "flask-security-key-1",
                "n": jwt.utils.base64url_encode(n).decode('ascii'),
                "e": jwt.utils.base64url_encode(e).decode('ascii'),
                "use": "sig",
                "alg": "RS256"
            }]
        }
    
    def create_jwt_token(self, user_data, token_type="access"):
        """Create JWT token like Flask-Security does"""
        now = datetime.utcnow()
        exp_delta = timedelta(hours=1) if token_type == "access" else timedelta(days=30)
        
        payload = {
            "sub": user_data["id"],
            "email": user_data["email"],
            "role": user_data["roles"][0] if user_data["roles"] else "user",
            "team": user_data.get("team"),
            "iss": "http://localhost:5000",  # Mock Flask-Security issuer
            "aud": "litellm-proxy",
            "iat": int(now.timestamp()),
            "exp": int((now + exp_delta).timestamp()),
            "type": token_type
        }
        
        # Sign with private key
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return jwt.encode(payload, private_key_pem, algorithm="RS256")
    
    def setup_routes(self):
        """Setup Flask-Security compatible routes"""
        
        @self.app.post("/api/login")
        async def api_login(request: Request):
            """Mock Flask-Security login endpoint"""
            try:
                data = await request.json()
                email = data.get("email")
                password = data.get("password")
                
                if not email or not password:
                    raise HTTPException(status_code=400, detail="Email and password required")
                
                user = self.users.get(email)
                if not user or user["password"] != password:
                    raise HTTPException(status_code=401, detail="Invalid credentials")
                
                access_token = self.create_jwt_token(user, "access")
                refresh_token = self.create_jwt_token(user, "refresh")
                
                return {
                    "success": True,
                    "user": {
                        "email": user["email"],
                        "roles": user["roles"]
                    },
                    "tokens": {
                        "access_token": access_token,
                        "refresh_token": refresh_token
                    }
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/logout") 
        async def api_logout(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))):
            """Mock Flask-Security logout with JWT blacklisting"""
            if credentials:
                token = credentials.credentials
                try:
                    # Decode without verification to get JTI for blacklisting
                    unverified = jwt.get_unverified_claims(token)
                    jti = unverified.get("jti", token[-10:])  # Use last 10 chars if no jti
                    self.blacklisted_tokens.add(jti)
                except:
                    pass
            
            return {"success": True}
        
        @self.app.post("/api/token/refresh")
        async def api_token_refresh(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
            """Mock JWT refresh endpoint"""
            token = credentials.credentials
            try:
                # Verify refresh token
                private_key_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                payload = jwt.decode(
                    token, 
                    private_key_pem,
                    algorithms=["RS256"],
                    audience="litellm-proxy",
                    issuer="http://localhost:5000"
                )
                
                if payload.get("type") != "refresh":
                    raise HTTPException(status_code=401, detail="Invalid refresh token")
                
                # Find user and create new access token
                user_email = payload["email"]
                user = self.users.get(user_email)
                if not user:
                    raise HTTPException(status_code=404, detail="User not found")
                
                new_access_token = self.create_jwt_token(user, "access")
                
                return {"access_token": new_access_token}
                
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Refresh token expired")
            except jwt.JWTError:
                raise HTTPException(status_code=401, detail="Invalid refresh token")
        
        @self.app.get("/auth-test")
        async def auth_test(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
            """Mock Flask-Security auth test endpoint"""
            token = credentials.credentials
            try:
                private_key_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                payload = jwt.decode(
                    token,
                    private_key_pem, 
                    algorithms=["RS256"],
                    audience="litellm-proxy",
                    issuer="http://localhost:5000"
                )
                
                return {
                    "authenticated": True,
                    "message": f"You are authenticated as {payload['email']}",
                    "user": {
                        "id": payload["sub"],
                        "email": payload["email"],
                        "roles": [payload.get("role", "user")]
                    }
                }
            except jwt.JWTError:
                raise HTTPException(status_code=401, detail="Invalid token")
        
        @self.app.get("/.well-known/jwks.json")
        async def jwks_endpoint():
            """JWKS endpoint for public key retrieval"""
            return self.jwk_data


@pytest.fixture
async def mock_flask_server():
    """Start mock Flask-Security server for testing"""
    server = FlaskSecurityMockServer()
    
    # Start server in background thread
    config = uvicorn.Config(server.app, host="127.0.0.1", port=5000, log_level="error")
    server_instance = uvicorn.Server(config)
    
    server_thread = threading.Thread(target=server_instance.run, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    await asyncio.sleep(0.5)
    
    # Verify server is running
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:5000/.well-known/jwks.json")
            assert response.status_code == 200
    except:
        pytest.skip("Mock server failed to start")
    
    yield server
    
    # Cleanup - server will stop when test process ends


@pytest.fixture
def jwt_config():
    """JWT configuration for testing"""
    return {
        "issuer": "http://localhost:5000",
        "audience": "litellm-proxy", 
        "public_key_url": "http://localhost:5000/.well-known/jwks.json",
        "user_claim_mappings": {
            "user_id": "sub",
            "user_email": "email", 
            "user_role": "role",
            "team_id": "team"
        }
    }


class TestFlaskSecurityIntegration:
    """Integration tests for JWT authentication with Flask-Security mock"""
    
    @pytest.mark.asyncio
    async def test_flask_security_login_flow(self, mock_flask_server):
        """Test complete login flow with Flask-Security mock"""
        # Login to get JWT token
        async with httpx.AsyncClient() as client:
            login_response = await client.post(
                "http://localhost:5000/api/login",
                json={"email": "admin@example.com", "password": "password123"}
            )
            
        assert login_response.status_code == 200
        login_data = login_response.json()
        
        assert login_data["success"] is True
        assert "tokens" in login_data
        assert "access_token" in login_data["tokens"]
        assert "refresh_token" in login_data["tokens"]
        
        access_token = login_data["tokens"]["access_token"]
        
        # Test auth endpoint with token
        async with httpx.AsyncClient() as client:
            auth_response = await client.get(
                "http://localhost:5000/auth-test",
                headers={"Authorization": f"Bearer {access_token}"}
            )
        
        assert auth_response.status_code == 200
        auth_data = auth_response.json()
        
        assert auth_data["authenticated"] is True
        assert auth_data["user"]["email"] == "admin@example.com"
    
    @pytest.mark.asyncio
    async def test_jwt_auth_with_litellm(self, mock_flask_server, jwt_config):
        """Test JWT authentication with LiteLLM proxy using Flask-Security token"""
        # Get token from Flask-Security mock
        async with httpx.AsyncClient() as client:
            login_response = await client.post(
                "http://localhost:5000/api/login",
                json={"email": "user@example.com", "password": "password123"}
            )
        
        access_token = login_response.json()["tokens"]["access_token"]
        
        # Mock FastAPI request with JWT token
        from fastapi import Request
        
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"authorization": f"Bearer {access_token}"}
        
        # Patch the general_settings to include our JWT config
        with patch('litellm.proxy.proxy_server.general_settings', {"jwt_settings": jwt_config}):
            # Test LiteLLM JWT authentication
            user_auth = await jwt_auth(request=mock_request, api_key=access_token)
            
        assert isinstance(user_auth, UserAPIKeyAuth)
        assert user_auth.user_id == "user456"
        assert user_auth.user_email == "user@example.com"
        assert user_auth.team_id == "product"
        assert "jwt_claims" in user_auth.metadata
    
    @pytest.mark.asyncio
    async def test_role_mapping_integration(self, mock_flask_server, jwt_config):
        """Test role mapping from Flask-Security to LiteLLM roles"""
        test_cases = [
            ("admin@example.com", "PROXY_ADMIN"),
            ("user@example.com", "INTERNAL_USER"), 
            ("viewer@example.com", "INTERNAL_USER_VIEW_ONLY")
        ]
        
        for email, expected_role in test_cases:
            # Login to get token
            async with httpx.AsyncClient() as client:
                login_response = await client.post(
                    "http://localhost:5000/api/login",
                    json={"email": email, "password": "password123"}
                )
            
            access_token = login_response.json()["tokens"]["access_token"]
            
            # Test with LiteLLM
            mock_request = MagicMock(spec=Request)
            mock_request.headers = {"authorization": f"Bearer {access_token}"}
            
            with patch('litellm.proxy.proxy_server.general_settings', {"jwt_settings": jwt_config}):
                user_auth = await jwt_auth(request=mock_request, api_key=access_token)
            
            assert user_auth.user_role.value == expected_role
    
    @pytest.mark.asyncio 
    async def test_token_refresh_flow(self, mock_flask_server):
        """Test JWT refresh token flow"""
        # Login to get tokens
        async with httpx.AsyncClient() as client:
            login_response = await client.post(
                "http://localhost:5000/api/login", 
                json={"email": "admin@example.com", "password": "password123"}
            )
        
        tokens = login_response.json()["tokens"]
        refresh_token = tokens["refresh_token"]
        
        # Use refresh token to get new access token
        async with httpx.AsyncClient() as client:
            refresh_response = await client.post(
                "http://localhost:5000/api/token/refresh",
                headers={"Authorization": f"Bearer {refresh_token}"}
            )
        
        assert refresh_response.status_code == 200
        new_token_data = refresh_response.json()
        assert "access_token" in new_token_data
        
        # Verify new access token works
        new_access_token = new_token_data["access_token"]
        async with httpx.AsyncClient() as client:
            auth_response = await client.get(
                "http://localhost:5000/auth-test",
                headers={"Authorization": f"Bearer {new_access_token}"}
            )
        
        assert auth_response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_logout_token_blacklisting(self, mock_flask_server):
        """Test token blacklisting on logout"""
        # Login to get token
        async with httpx.AsyncClient() as client:
            login_response = await client.post(
                "http://localhost:5000/api/login",
                json={"email": "admin@example.com", "password": "password123"}
            )
        
        access_token = login_response.json()["tokens"]["access_token"]
        
        # Verify token works initially
        async with httpx.AsyncClient() as client:
            auth_response = await client.get(
                "http://localhost:5000/auth-test",
                headers={"Authorization": f"Bearer {access_token}"}
            )
        assert auth_response.status_code == 200
        
        # Logout to blacklist token
        async with httpx.AsyncClient() as client:
            logout_response = await client.post(
                "http://localhost:5000/api/logout",
                headers={"Authorization": f"Bearer {access_token}"}
            )
        assert logout_response.status_code == 200
        
        # Verify token is blacklisted (in real app would need blacklist checking)
        assert len(mock_flask_server.blacklisted_tokens) > 0
    
    @pytest.mark.asyncio
    async def test_invalid_token_handling(self, mock_flask_server, jwt_config):
        """Test handling of invalid tokens"""
        invalid_tokens = [
            "invalid.token.format",
            "Bearer invalid-token",
            "",
            None
        ]
        
        for invalid_token in invalid_tokens:
            mock_request = MagicMock(spec=Request)
            mock_request.headers = {"authorization": f"Bearer {invalid_token}"} if invalid_token else {}
            
            with patch('litellm.proxy.proxy_server.general_settings', {"jwt_settings": jwt_config}):
                with pytest.raises(HTTPException) as exc_info:
                    await jwt_auth(request=mock_request, api_key=invalid_token)
                
                assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_expired_token_handling(self, mock_flask_server, jwt_config):
        """Test handling of expired tokens"""
        # Create expired token
        user_data = mock_flask_server.users["admin@example.com"]
        
        # Create token that's already expired
        now = datetime.utcnow()
        payload = {
            "sub": user_data["id"],
            "email": user_data["email"], 
            "role": user_data["roles"][0],
            "team": user_data.get("team"),
            "iss": "http://localhost:5000",
            "aud": "litellm-proxy",
            "iat": int((now - timedelta(hours=2)).timestamp()),
            "exp": int((now - timedelta(hours=1)).timestamp()),  # Expired 1 hour ago
        }
        
        private_key_pem = mock_flask_server.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        expired_token = jwt.encode(payload, private_key_pem, algorithm="RS256")
        
        # Test with expired token
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"authorization": f"Bearer {expired_token}"}
        
        with patch('litellm.proxy.proxy_server.general_settings', {"jwt_settings": jwt_config}):
            with pytest.raises(HTTPException) as exc_info:
                await jwt_auth(request=mock_request, api_key=expired_token)
            
            assert exc_info.value.status_code == 401
            assert "expired" in str(exc_info.value.detail).lower()


class TestLiteLLMProxyIntegration:
    """Integration tests with actual LiteLLM proxy functionality"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_chat_completion_with_jwt(self, mock_flask_server, jwt_config):
        """Test end-to-end chat completion with JWT authentication"""
        # This would require starting actual LiteLLM proxy server
        # For now, test the auth integration point
        
        # Get valid JWT token
        async with httpx.AsyncClient() as client:
            login_response = await client.post(
                "http://localhost:5000/api/login",
                json={"email": "admin@example.com", "password": "password123"}
            )
        
        access_token = login_response.json()["tokens"]["access_token"]
        
        # Mock the request that would come to LiteLLM proxy
        mock_request = MagicMock(spec=Request)
        mock_request.headers = {"authorization": f"Bearer {access_token}"}
        
        with patch('litellm.proxy.proxy_server.general_settings', {"jwt_settings": jwt_config}):
            user_auth = await jwt_auth(request=mock_request, api_key=access_token)
        
        # Verify user context is properly set for cost tracking
        assert user_auth.user_id == "user123"
        assert user_auth.user_email == "admin@example.com"
        assert user_auth.team_id == "engineering"
        assert user_auth.metadata["auth_method"] == "jwt"
        
        # This user context would be used by LiteLLM for:
        # - Cost tracking in database 
        # - Rate limiting per user/team
        # - Audit logging
        # - Role-based access control


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"]) 
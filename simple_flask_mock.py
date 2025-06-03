#!/usr/bin/env python3
"""
Standalone Flask-Security mock server for integration testing
This version doesn't import LiteLLM components to avoid dependency issues
"""
import json
import time
import base64
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import uvicorn


def base64url_encode(data):
    """Base64URL encode data"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


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
                "n": base64url_encode(n),
                "e": base64url_encode(e),
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


if __name__ == '__main__':
    print("🚀 Starting Flask-Security Mock Server...")
    print("📡 Server will be available at http://localhost:5000")
    print("🔍 Endpoints:")
    print("   POST /api/login")
    print("   GET  /auth-test") 
    print("   POST /api/token/refresh")
    print("   POST /api/logout")
    print("   GET  /.well-known/jwks.json")
    print("=" * 50)
    
    server = FlaskSecurityMockServer()
    uvicorn.run(
        server.app, 
        host='0.0.0.0', 
        port=5000,
        log_level="info"
    ) 
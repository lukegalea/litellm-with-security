"""
JWT Mock Generator for testing LiteLLM JWT authentication.

Provides utilities for generating mock JWT tokens, JWKS responses,
and simulating various JWT provider scenarios.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class MockJWTGenerator:
    """
    Mock JWT generator for testing JWT authentication scenarios.
    
    Provides methods to generate JWT tokens with configurable claims,
    create JWKS responses, and simulate various authentication scenarios.
    """
    
    def __init__(self, issuer: str = "https://mock-jwt-provider.test", audience: str = "litellm-proxy"):
        self.issuer = issuer
        self.audience = audience
        self.kid = "mock-key-1"
        
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Extract public key components for JWKS
        public_numbers = self.public_key.public_numbers()
        self.n = self._encode_bigint(public_numbers.n)
        self.e = self._encode_bigint(public_numbers.e)
    
    def _encode_bigint(self, value: int) -> str:
        """Encode large integer to base64url format for JWKS."""
        import base64
        byte_length = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_length, byteorder='big')
        return base64.urlsafe_b64encode(value_bytes).decode('ascii').rstrip('=')
    
    def generate_token(
        self,
        user_id: str = "test-user",
        email: str = "test@example.com",
        roles: list = None,
        team_id: str = None,
        custom_claims: Dict[str, Any] = None,
        expires_in: int = 3600,
        expired: bool = False
    ) -> str:
        """
        Generate a JWT token with specified claims.
        
        Args:
            user_id: User identifier (sub claim)
            email: User email address
            roles: List of user roles
            team_id: Team/organization identifier
            custom_claims: Additional claims to include
            expires_in: Token expiration time in seconds
            expired: If True, generate an already expired token
            
        Returns:
            JWT token string
        """
        if roles is None:
            roles = ["user"]
        
        now = datetime.now(timezone.utc)
        if expired:
            # Create token that expired 1 hour ago
            exp_time = now - timedelta(hours=1)
            iat_time = now - timedelta(hours=2)
        else:
            exp_time = now + timedelta(seconds=expires_in)
            iat_time = now
        
        payload = {
            "sub": user_id,
            "email": email,
            "role": roles[0] if roles else "user",  # Primary role
            "roles": roles,  # All roles
            "iss": self.issuer,
            "aud": self.audience,
            "iat": int(iat_time.timestamp()),
            "exp": int(exp_time.timestamp()),
            "jti": f"mock-jwt-{int(time.time())}"
        }
        
        if team_id:
            payload["team"] = team_id
        
        if custom_claims:
            payload.update(custom_claims)
        
        return jwt.encode(
            payload,
            self.private_key,
            algorithm="RS256",
            headers={"kid": self.kid}
        )
    
    def get_jwks(self) -> Dict[str, Any]:
        """
        Generate JWKS (JSON Web Key Set) response for public key distribution.
        
        Returns:
            JWKS dictionary with public key information
        """
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": self.kid,
                    "alg": "RS256",
                    "n": self.n,
                    "e": self.e
                }
            ]
        }
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for direct validation."""
        return self.public_key.public_key_pem().decode('utf-8')


class MockUserDatabase:
    """Mock user database for testing authentication scenarios."""
    
    def __init__(self):
        self.users = {
            "admin@example.com": {
                "id": "admin-user-123",
                "email": "admin@example.com",
                "roles": ["admin"],
                "team": "admin-team",
                "active": True
            },
            "user@example.com": {
                "id": "regular-user-456",
                "email": "user@example.com", 
                "roles": ["user"],
                "team": "user-team",
                "active": True
            },
            "viewer@example.com": {
                "id": "viewer-user-789",
                "email": "viewer@example.com",
                "roles": ["viewer"],
                "team": "viewer-team",
                "active": True
            },
            "inactive@example.com": {
                "id": "inactive-user-000",
                "email": "inactive@example.com",
                "roles": ["user"],
                "team": "inactive-team",
                "active": False
            }
        }
    
    def get_user(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user data by email."""
        return self.users.get(email)
    
    def authenticate(self, email: str, password: str) -> Optional[Dict[str, Any]]:
        """Mock authentication - accepts 'password123' for all users."""
        if password == "password123":
            return self.get_user(email)
        return None


# Pre-configured generators for common test scenarios
mock_jwt_generator = MockJWTGenerator()
mock_user_db = MockUserDatabase()


def create_admin_token(expires_in: int = 3600, expired: bool = False) -> str:
    """Create JWT token for admin user."""
    return mock_jwt_generator.generate_token(
        user_id="admin-user-123",
        email="admin@example.com",
        roles=["admin"],
        team_id="admin-team",
        expires_in=expires_in,
        expired=expired
    )


def create_user_token(expires_in: int = 3600, expired: bool = False) -> str:
    """Create JWT token for regular user."""
    return mock_jwt_generator.generate_token(
        user_id="regular-user-456",
        email="user@example.com",
        roles=["user"],
        team_id="user-team",
        expires_in=expires_in,
        expired=expired
    )


def create_viewer_token(expires_in: int = 3600, expired: bool = False) -> str:
    """Create JWT token for viewer user."""
    return mock_jwt_generator.generate_token(
        user_id="viewer-user-789",
        email="viewer@example.com",
        roles=["viewer"],
        team_id="viewer-team",
        expires_in=expires_in,
        expired=expired
    )


def get_mock_jwks() -> Dict[str, Any]:
    """Get mock JWKS response."""
    return mock_jwt_generator.get_jwks() 
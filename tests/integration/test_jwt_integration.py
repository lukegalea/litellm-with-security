"""
JWT Authentication Integration Tests

Tests for the custom JWT authentication module using mocked responses.
Follows LiteLLM's standard testing patterns without Docker dependencies.
"""

import pytest
import jwt
import json
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from unittest.mock import patch, Mock
import responses
import httpx

# Import LiteLLM proxy components
from litellm.proxy.custom_jwt_auth import jwt_auth, JWTConfig, map_jwt_claims_to_user_auth
from litellm.proxy._types import UserAPIKeyAuth


class JWTTestHelper:
    """Helper class for generating test JWT tokens and keys"""
    
    def __init__(self):
        # Generate RSA key pair for testing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        
        # Serialize keys
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        self.public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Create JWKS response
        self.jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "test-key-1",
                    "n": self._get_rsa_public_numbers()["n"],
                    "e": self._get_rsa_public_numbers()["e"]
                }
            ]
        }
    
    def _get_rsa_public_numbers(self):
        """Extract RSA public key numbers for JWKS"""
        numbers = self.public_key.public_numbers()
        
        def _int_to_base64url_uint(val):
            """Convert integer to base64url-encoded unsigned integer"""
            import base64
            val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
            return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip('=')
        
        return {
            "n": _int_to_base64url_uint(numbers.n),
            "e": _int_to_base64url_uint(numbers.e)
        }
    
    def generate_token(self, claims=None, expired=False, invalid_signature=False):
        """Generate a test JWT token"""
        if claims is None:
            claims = {
                "sub": "user123",
                "email": "test@example.com",
                "role": "admin", 
                "team": "engineering",
                "iss": "https://test-issuer.com",
                "aud": "litellm-proxy"
            }
        
        # Set expiration
        if expired:
            claims["exp"] = int(time.time()) - 3600  # Expired 1 hour ago
        else:
            claims["exp"] = int(time.time()) + 3600  # Valid for 1 hour
        
        # Set issued at time
        claims["iat"] = int(time.time())
        
        # Use wrong key for invalid signature test
        signing_key = "wrong-key" if invalid_signature else self.private_key
        
        try:
            token = jwt.encode(
                claims, 
                signing_key, 
                algorithm="RS256",
                headers={"kid": "test-key-1"}
            )
            return token
        except Exception:
            # For invalid signature test, return a malformed token
            return "invalid.jwt.token"


@pytest.fixture
def jwt_helper():
    """Pytest fixture providing JWT test helper"""
    return JWTTestHelper()


@pytest.fixture
def mock_jwt_config():
    """Pytest fixture providing mock JWT configuration"""
    return JWTConfig({
        "issuer": "https://test-issuer.com",
        "audience": "litellm-proxy", 
        "public_key_url": "https://test-issuer.com/.well-known/jwks.json",
        "user_claim_mappings": {
            "user_id": "sub",
            "user_email": "email", 
            "user_role": "role",
            "team_id": "team"
        },
        "role_mapping": {
            "admin": "PROXY_ADMIN",
            "user": "INTERNAL_USER",
            "viewer": "INTERNAL_USER_VIEW_ONLY"
        }
    })


class TestJWTValidation:
    """Test JWT token validation functionality"""
    
    @responses.activate
    def test_valid_admin_token(self, jwt_helper, mock_jwt_config):
        """Test valid admin JWT token authentication"""
        # Mock JWKS endpoint
        responses.add(
            responses.GET,
            "https://test-issuer.com/.well-known/jwks.json",
            json=jwt_helper.jwks,
            status=200
        )
        
        # Generate valid token
        token = jwt_helper.generate_token({
            "sub": "admin123",
            "email": "admin@example.com", 
            "role": "admin",
            "team": "admin-team",
            "iss": "https://test-issuer.com",
            "aud": "litellm-proxy"
        })
        
        # Test validation
        result = map_jwt_claims_to_user_auth(
            jwt.decode(token, jwt_helper.public_key, algorithms=["RS256"], audience="litellm-proxy"),
            mock_jwt_config
        )
        
        assert isinstance(result, UserAPIKeyAuth)
        assert result.user_id == "admin123"
        assert result.user_email == "admin@example.com"
        assert result.user_role == "PROXY_ADMIN"
        assert result.team_id == "admin-team"
        assert result.metadata["auth_method"] == "jwt"
    
    @responses.activate
    def test_valid_user_token(self, jwt_helper, mock_jwt_config):
        """Test valid regular user JWT token authentication"""
        # Mock JWKS endpoint
        responses.add(
            responses.GET,
            "https://test-issuer.com/.well-known/jwks.json",
            json=jwt_helper.jwks,
            status=200
        )
        
        # Generate valid token
        token = jwt_helper.generate_token({
            "sub": "user456",
            "email": "user@example.com",
            "role": "user", 
            "team": "development",
            "iss": "https://test-issuer.com",
            "aud": "litellm-proxy"
        })
        
        # Test validation
        result = map_jwt_claims_to_user_auth(
            jwt.decode(token, jwt_helper.public_key, algorithms=["RS256"], audience="litellm-proxy"),
            mock_jwt_config
        )
        
        assert result.user_id == "user456"
        assert result.user_email == "user@example.com"
        assert result.user_role == "INTERNAL_USER"
        assert result.team_id == "development"
    
    def test_expired_token_rejection(self, jwt_helper, mock_jwt_config):
        """Test that expired tokens are rejected"""
        # Generate expired token
        token = jwt_helper.generate_token(expired=True)
        
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(token, jwt_helper.public_key, algorithms=["RS256"], audience="litellm-proxy")
    
    def test_invalid_signature_rejection(self, jwt_helper, mock_jwt_config):
        """Test that tokens with invalid signatures are rejected"""
        # Generate token with invalid signature
        token = jwt_helper.generate_token(invalid_signature=True)
        
        with pytest.raises((jwt.DecodeError, jwt.InvalidSignatureError)):
            jwt.decode(token, jwt_helper.public_key, algorithms=["RS256"], audience="litellm-proxy")
    
    def test_missing_claims_validation(self, jwt_helper, mock_jwt_config):
        """Test validation of tokens with missing required claims"""
        # Generate token missing required claims
        token = jwt_helper.generate_token({
            "sub": "user123",
            # Missing email, role, team
            "iss": "https://test-issuer.com", 
            "aud": "litellm-proxy"
        })
        
        claims = jwt.decode(token, jwt_helper.public_key, algorithms=["RS256"], audience="litellm-proxy")
        result = map_jwt_claims_to_user_auth(claims, mock_jwt_config)
        
        # Should still work but with default values
        assert result.user_id == "user123"
        assert result.user_email is None
        assert result.user_role == "INTERNAL_USER"  # Default role
        assert result.team_id is None


class TestRoleMapping:
    """Test JWT role mapping functionality"""
    
    def test_admin_role_mapping(self, jwt_helper, mock_jwt_config):
        """Test admin role maps to PROXY_ADMIN"""
        claims = {
            "sub": "admin123",
            "email": "admin@example.com",
            "role": "admin",
            "team": "admin-team"
        }
        
        result = map_jwt_claims_to_user_auth(claims, mock_jwt_config)
        assert result.user_role == "PROXY_ADMIN"
    
    def test_user_role_mapping(self, jwt_helper, mock_jwt_config):
        """Test user role maps to INTERNAL_USER"""
        claims = {
            "sub": "user456", 
            "email": "user@example.com",
            "role": "user",
            "team": "development"
        }
        
        result = map_jwt_claims_to_user_auth(claims, mock_jwt_config)
        assert result.user_role == "INTERNAL_USER"
    
    def test_viewer_role_mapping(self, jwt_helper, mock_jwt_config):
        """Test viewer role maps to INTERNAL_USER_VIEW_ONLY"""
        claims = {
            "sub": "viewer789",
            "email": "viewer@example.com", 
            "role": "viewer",
            "team": "analytics"
        }
        
        result = map_jwt_claims_to_user_auth(claims, mock_jwt_config)
        assert result.user_role == "INTERNAL_USER_VIEW_ONLY"
    
    def test_unknown_role_default(self, jwt_helper, mock_jwt_config):
        """Test unknown roles default to INTERNAL_USER"""
        claims = {
            "sub": "unknown123",
            "email": "unknown@example.com",
            "role": "unknown_role", 
            "team": "unknown"
        }
        
        result = map_jwt_claims_to_user_auth(claims, mock_jwt_config)
        assert result.user_role == "INTERNAL_USER"


class TestJWTAuthEndToEnd:
    """End-to-end JWT authentication tests"""
    
    @responses.activate
    @patch('litellm.proxy.custom_jwt_auth.get_jwt_config')
    async def test_jwt_auth_function_valid_token(self, mock_get_config, jwt_helper):
        """Test the main jwt_auth function with valid token"""
        # Setup mock configuration
        mock_get_config.return_value = JWTConfig({
            "issuer": "https://test-issuer.com",
            "audience": "litellm-proxy",
            "public_key_url": "https://test-issuer.com/.well-known/jwks.json",
            "user_claim_mappings": {
                "user_id": "sub",
                "user_email": "email",
                "user_role": "role", 
                "team_id": "team"
            },
            "role_mapping": {
                "admin": "PROXY_ADMIN",
                "user": "INTERNAL_USER",
                "viewer": "INTERNAL_USER_VIEW_ONLY"
            }
        })
        
        # Mock JWKS endpoint
        responses.add(
            responses.GET,
            "https://test-issuer.com/.well-known/jwks.json",
            json=jwt_helper.jwks,
            status=200
        )
        
        # Generate valid token
        token = jwt_helper.generate_token({
            "sub": "test123",
            "email": "test@example.com",
            "role": "admin",
            "team": "engineering", 
            "iss": "https://test-issuer.com",
            "aud": "litellm-proxy"
        })
        
        # Create mock request
        mock_request = Mock()
        mock_request.headers = {"authorization": f"Bearer {token}"}
        
        # Test jwt_auth function
        result = await jwt_auth(request=mock_request, api_key=token)
        
        assert isinstance(result, dict)
        assert result["user_id"] == "test123" 
        assert result["user_email"] == "test@example.com"
        assert result["user_role"] == "PROXY_ADMIN"
        assert result["team_id"] == "engineering"
    
    @responses.activate  
    @patch('litellm.proxy.custom_jwt_auth.get_jwt_config')
    async def test_jwt_auth_function_invalid_token(self, mock_get_config, jwt_helper):
        """Test the main jwt_auth function with invalid token"""
        # Setup mock configuration
        mock_get_config.return_value = JWTConfig({
            "issuer": "https://test-issuer.com", 
            "audience": "litellm-proxy",
            "public_key_url": "https://test-issuer.com/.well-known/jwks.json"
        })
        
        # Create mock request with invalid token
        mock_request = Mock()
        mock_request.headers = {"authorization": "Bearer invalid.jwt.token"}
        
        # Test jwt_auth function - should raise exception
        with pytest.raises(Exception):
            await jwt_auth(request=mock_request, api_key="invalid.jwt.token")


class TestJWKSCaching:
    """Test JWKS public key caching functionality"""
    
    @responses.activate
    @patch('litellm.proxy.custom_jwt_auth._jwks_cache', {})
    def test_jwks_caching(self, jwt_helper):
        """Test that JWKS responses are properly cached"""
        from litellm.proxy.custom_jwt_auth import fetch_jwks_keys
        
        jwks_url = "https://test-issuer.com/.well-known/jwks.json"
        
        # Mock JWKS endpoint
        responses.add(
            responses.GET,
            jwks_url,
            json=jwt_helper.jwks,
            status=200
        )
        
        # First call should fetch from endpoint
        keys1 = fetch_jwks_keys(jwks_url)
        assert len(responses.calls) == 1
        
        # Second call should use cache
        keys2 = fetch_jwks_keys(jwks_url)
        assert len(responses.calls) == 1  # No additional HTTP calls
        assert keys1 == keys2


if __name__ == "__main__":
    # Allow running tests directly with python
    pytest.main([__file__, "-v"]) 
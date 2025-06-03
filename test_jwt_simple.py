#!/usr/bin/env python3
"""
Simple JWT Integration Test Runner

This script provides a quick way to test JWT authentication functionality
without requiring Docker or complex container setup. Perfect for CI/CD.
"""

import sys
import traceback
from typing import Dict, Any

def test_jwt_imports():
    """Test that all JWT-related modules can be imported successfully."""
    print("🔍 Testing JWT module imports...")
    
    try:
        from litellm.proxy.custom_jwt_auth import (
            jwt_auth, 
            JWTConfig, 
            map_jwt_claims_to_user_auth,
            fetch_jwks_keys
        )
        from litellm.proxy._types import UserAPIKeyAuth
        import jwt
        import responses
        print("✅ All JWT modules imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_jwt_config_creation():
    """Test JWT configuration creation."""
    print("\n🔍 Testing JWT configuration creation...")
    
    try:
        from litellm.proxy.custom_jwt_auth import JWTConfig
        
        config = JWTConfig({
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
        
        assert config.issuer == "https://test-issuer.com"
        assert config.audience == "litellm-proxy"
        assert config.role_mapping["admin"] == "PROXY_ADMIN"
        
        print("✅ JWT configuration created successfully")
        return True
    except Exception as e:
        print(f"❌ JWT configuration error: {e}")
        traceback.print_exc()
        return False

def test_jwt_token_generation():
    """Test JWT token generation and validation."""
    print("\n🔍 Testing JWT token generation...")
    
    try:
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import time
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Create test claims
        claims = {
            "sub": "test-user-123",
            "email": "test@example.com",
            "role": "admin",
            "team": "engineering",
            "iss": "https://test-issuer.com",
            "aud": "litellm-proxy",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time())
        }
        
        # Generate token
        token = jwt.encode(claims, private_key, algorithm="RS256")
        
        # Validate token
        decoded = jwt.decode(
            token, 
            public_key, 
            algorithms=["RS256"], 
            audience="litellm-proxy",
            issuer="https://test-issuer.com"
        )
        
        assert decoded["sub"] == "test-user-123"
        assert decoded["email"] == "test@example.com"
        assert decoded["role"] == "admin"
        
        print("✅ JWT token generation and validation successful")
        return True
    except Exception as e:
        print(f"❌ JWT token generation error: {e}")
        traceback.print_exc()
        return False

def test_user_auth_mapping():
    """Test mapping JWT claims to UserAPIKeyAuth objects."""
    print("\n🔍 Testing user authentication mapping...")
    
    try:
        from litellm.proxy.custom_jwt_auth import map_jwt_claims_to_user_auth, JWTConfig
        from litellm.proxy._types import UserAPIKeyAuth
        
        # Mock JWT claims
        claims = {
            "sub": "admin-user-456",
            "email": "admin@example.com",
            "role": "admin",
            "team": "admin-team"
        }
        
        # Create config
        config = JWTConfig({
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
        
        # Map claims to user auth
        user_auth = map_jwt_claims_to_user_auth(claims, config)
        
        assert isinstance(user_auth, UserAPIKeyAuth)
        assert user_auth.user_id == "admin-user-456"
        assert user_auth.user_email == "admin@example.com"
        assert user_auth.user_role == "PROXY_ADMIN"
        assert user_auth.team_id == "admin-team"
        assert user_auth.metadata["auth_method"] == "jwt"
        
        print("✅ User authentication mapping successful")
        return True
    except Exception as e:
        print(f"❌ User authentication mapping error: {e}")
        traceback.print_exc()
        return False

def test_role_mapping():
    """Test role mapping functionality."""
    print("\n🔍 Testing role mapping...")
    
    try:
        from litellm.proxy.custom_jwt_auth import map_jwt_claims_to_user_auth, JWTConfig
        
        config = JWTConfig({
            "issuer": "https://test-issuer.com",
            "audience": "litellm-proxy",
            "public_key_url": "https://test-issuer.com/.well-known/jwks.json",
            "role_mapping": {
                "admin": "PROXY_ADMIN",
                "user": "INTERNAL_USER",
                "viewer": "INTERNAL_USER_VIEW_ONLY"
            }
        })
        
        # Test different role mappings
        test_cases = [
            ("admin", "PROXY_ADMIN"),
            ("user", "INTERNAL_USER"),
            ("viewer", "INTERNAL_USER_VIEW_ONLY"),
            ("unknown", "INTERNAL_USER")  # Default
        ]
        
        for jwt_role, expected_litellm_role in test_cases:
            claims = {"sub": "test", "role": jwt_role}
            user_auth = map_jwt_claims_to_user_auth(claims, config)
            assert user_auth.user_role == expected_litellm_role, \
                f"Role {jwt_role} should map to {expected_litellm_role}, got {user_auth.user_role}"
        
        print("✅ Role mapping tests passed")
        return True
    except Exception as e:
        print(f"❌ Role mapping error: {e}")
        traceback.print_exc()
        return False

def run_all_tests():
    """Run all JWT integration tests."""
    print("🚀 Starting JWT Integration Tests")
    print("=" * 50)
    
    tests = [
        test_jwt_imports,
        test_jwt_config_creation,
        test_jwt_token_generation,
        test_user_auth_mapping,
        test_role_mapping
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! JWT integration is working correctly.")
        return True
    else:
        print(f"⚠️  {failed} test(s) failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1) 
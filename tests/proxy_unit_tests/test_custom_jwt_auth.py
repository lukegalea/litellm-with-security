"""
Unit tests for custom JWT authentication with automatic user creation
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import Request, HTTPException

from litellm.proxy.custom_jwt_auth import (
    jwt_auth,
    JWTConfig,
    _ensure_user_exists,
    map_jwt_claims_to_user_auth,
)
from litellm.proxy._types import UserAPIKeyAuth, LitellmUserRoles


class TestCustomJWTAuth:
    """Test custom JWT authentication functionality"""

    def test_jwt_config_with_auto_create_users(self):
        """Test that JWTConfig properly handles auto_create_users setting"""
        jwt_settings = {
            "issuer": "https://test.com",
            "public_key_url": "https://test.com/.well-known/jwks.json",
            "auto_create_users": True,
            "audience_validation": {
                "mode": "single",
                "audiences": ["test-audience"]
            },
            "user_claim_mappings": {
                "user_id": "sub",
                "user_email": "email",
                "user_role": "role"
            }
        }
        
        config = JWTConfig(jwt_settings)
        assert config.auto_create_users is True
        
        # Test default value
        jwt_settings_no_auto = jwt_settings.copy()
        del jwt_settings_no_auto["auto_create_users"]
        config_default = JWTConfig(jwt_settings_no_auto)
        assert config_default.auto_create_users is True  # Should default to True

    def test_map_jwt_claims_to_user_auth(self):
        """Test mapping JWT claims to UserAPIKeyAuth object"""
        jwt_settings = {
            "issuer": "https://test.com",
            "public_key_url": "https://test.com/.well-known/jwks.json",
            "audience_validation": {
                "mode": "single",
                "audiences": ["test-audience"]
            },
            "user_claim_mappings": {
                "user_id": "sub",
                "user_email": "email",
                "user_role": "role"
            }
        }
        config = JWTConfig(jwt_settings)
        
        claims = {
            "sub": "test-user-123",
            "email": "test@example.com",
            "role": "user",
            "iss": "https://test.com",
            "aud": "test-audience"
        }
        
        user_auth = map_jwt_claims_to_user_auth(claims, config)
        
        assert user_auth.user_id == "test-user-123"
        assert user_auth.user_email == "test@example.com"
        assert user_auth.user_role == LitellmUserRoles.INTERNAL_USER
        assert user_auth.metadata["auth_method"] == "jwt"
        assert user_auth.metadata["jwt_claims"] == claims

    @pytest.mark.asyncio
    async def test_ensure_user_exists_disabled(self):
        """Test that user creation is skipped when auto_create_users is False"""
        jwt_settings = {
            "issuer": "https://test.com",
            "public_key_url": "https://test.com/.well-known/jwks.json",
            "auto_create_users": False,
            "audience_validation": {
                "mode": "single", 
                "audiences": ["test-audience"]
            },
            "user_claim_mappings": {}
        }
        config = JWTConfig(jwt_settings)
        
        user_auth = UserAPIKeyAuth(
            user_id="test-user",
            user_email="test@example.com",
            user_role=LitellmUserRoles.INTERNAL_USER
        )
        
        # Should return early without calling any database functions
        await _ensure_user_exists(user_auth, config)
        # If we get here without errors, the function correctly skipped user creation

    @pytest.mark.asyncio
    async def test_ensure_user_exists_enabled(self):
        """Test that user creation is attempted when auto_create_users is True"""
        jwt_settings = {
            "issuer": "https://test.com",
            "public_key_url": "https://test.com/.well-known/jwks.json",
            "auto_create_users": True,
            "audience_validation": {
                "mode": "single",
                "audiences": ["test-audience"]
            },
            "user_claim_mappings": {}
        }
        config = JWTConfig(jwt_settings)
        
        user_auth = UserAPIKeyAuth(
            user_id="test-user",
            user_email="test@example.com",
            user_role=LitellmUserRoles.INTERNAL_USER
        )
        
        # Mock the database components where they're imported from
        mock_prisma_client = MagicMock()
        mock_user_api_key_cache = MagicMock()
        mock_proxy_logging_obj = MagicMock()
        mock_user_object = MagicMock()
        
        with patch('litellm.proxy.proxy_server.prisma_client', mock_prisma_client), \
             patch('litellm.proxy.proxy_server.user_api_key_cache', mock_user_api_key_cache), \
             patch('litellm.proxy.proxy_server.proxy_logging_obj', mock_proxy_logging_obj), \
             patch('litellm.proxy.auth.auth_checks.get_user_object', new_callable=AsyncMock) as mock_get_user:
            
            # Configure the mock to return a user object
            mock_get_user.return_value = mock_user_object
            
            # Call the function
            await _ensure_user_exists(user_auth, config)
            
            # Verify get_user_object was called with correct parameters
            mock_get_user.assert_called_once()
            call_kwargs = mock_get_user.call_args.kwargs
            assert call_kwargs["user_id"] == "test-user"
            assert call_kwargs["user_email"] == "test@example.com"
            assert call_kwargs["sso_user_id"] == "test-user"
            assert call_kwargs["user_id_upsert"] is True

    @pytest.mark.asyncio
    async def test_ensure_user_exists_no_user_id(self):
        """Test that user creation is skipped when no user_id is provided"""
        jwt_settings = {
            "issuer": "https://test.com",
            "public_key_url": "https://test.com/.well-known/jwks.json",
            "auto_create_users": True,
            "audience_validation": {
                "mode": "single",
                "audiences": ["test-audience"]
            },
            "user_claim_mappings": {}
        }
        config = JWTConfig(jwt_settings)
        
        user_auth = UserAPIKeyAuth(
            user_id=None,  # No user ID
            user_email="test@example.com", 
            user_role=LitellmUserRoles.INTERNAL_USER
        )
        
        # Should return early without calling any database functions
        await _ensure_user_exists(user_auth, config)
        # If we get here without errors, the function correctly skipped user creation

    @pytest.mark.asyncio
    async def test_ensure_user_exists_graceful_failure(self):
        """Test that authentication continues even if user creation fails"""
        jwt_settings = {
            "issuer": "https://test.com",
            "public_key_url": "https://test.com/.well-known/jwks.json", 
            "auto_create_users": True,
            "audience_validation": {
                "mode": "single",
                "audiences": ["test-audience"]
            },
            "user_claim_mappings": {}
        }
        config = JWTConfig(jwt_settings)
        
        user_auth = UserAPIKeyAuth(
            user_id="test-user",
            user_email="test@example.com",
            user_role=LitellmUserRoles.INTERNAL_USER
        )
        
        # Mock database failure
        mock_prisma_client = MagicMock()
        
        with patch('litellm.proxy.proxy_server.prisma_client', mock_prisma_client), \
             patch('litellm.proxy.auth.auth_checks.get_user_object', new_callable=AsyncMock) as mock_get_user:
            
            # Configure the mock to raise an exception
            mock_get_user.side_effect = Exception("Database connection failed")
            
            # Should not raise an exception - should handle gracefully
            await _ensure_user_exists(user_auth, config)
            
            # Function should have attempted to call get_user_object
            mock_get_user.assert_called_once()

if __name__ == "__main__":
    pytest.main([__file__]) 
"""
HTTP Mocking utilities for JWT provider endpoints.

Provides fixtures and utilities for mocking HTTP calls to JWT providers,
including JWKS endpoints, authentication APIs, and token validation.
"""

import json
from typing import Dict, Any, Optional
from unittest.mock import patch

import pytest
import responses
from responses import RequestsMock

from .jwt_generator import mock_jwt_generator, get_mock_jwks


class JWTMockServer:
    """
    Mock JWT server for testing authentication flows.
    
    Provides mock implementations of common JWT provider endpoints
    including JWKS, token validation, and user authentication.
    """
    
    def __init__(self, base_url: str = "https://mock-jwt-provider.test"):
        self.base_url = base_url.rstrip('/')
        self.jwks_url = f"{self.base_url}/.well-known/jwks.json"
        self.auth_url = f"{self.base_url}/api/login"
        self.token_refresh_url = f"{self.base_url}/api/token/refresh"
        self.user_info_url = f"{self.base_url}/auth-test"
        
    def setup_responses(self, rsps: RequestsMock, 
                       jwks_status: int = 200,
                       auth_status: int = 200,
                       simulate_network_error: bool = False) -> None:
        """
        Set up mock responses for JWT provider endpoints.
        
        Args:
            rsps: responses.RequestsMock instance
            jwks_status: HTTP status code for JWKS endpoint
            auth_status: HTTP status code for auth endpoints
            simulate_network_error: If True, simulate network connectivity issues
        """
        if simulate_network_error:
            # Simulate network timeout/connection error
            rsps.add(
                responses.GET,
                self.jwks_url,
                body=responses.ConnectionError("Network timeout")
            )
            return
        
        # Mock JWKS endpoint
        if jwks_status == 200:
            rsps.add(
                responses.GET,
                self.jwks_url,
                json=get_mock_jwks(),
                status=jwks_status,
                headers={"Content-Type": "application/json"}
            )
        else:
            rsps.add(
                responses.GET,
                self.jwks_url,
                json={"error": "JWKS unavailable"},
                status=jwks_status
            )
        
        # Mock authentication endpoint
        def auth_callback(request):
            if auth_status != 200:
                return (auth_status, {}, json.dumps({"error": "Authentication failed"}))
            
            try:
                data = json.loads(request.body)
                email = data.get("email")
                password = data.get("password")
                
                if password == "password123" and email in ["admin@example.com", "user@example.com", "viewer@example.com"]:
                    # Generate token based on user type
                    if email == "admin@example.com":
                        token = mock_jwt_generator.generate_token(
                            user_id="admin-user-123",
                            email=email,
                            roles=["admin"],
                            team_id="admin-team"
                        )
                    elif email == "user@example.com":
                        token = mock_jwt_generator.generate_token(
                            user_id="regular-user-456",
                            email=email,
                            roles=["user"], 
                            team_id="user-team"
                        )
                    else:  # viewer@example.com
                        token = mock_jwt_generator.generate_token(
                            user_id="viewer-user-789",
                            email=email,
                            roles=["viewer"],
                            team_id="viewer-team"
                        )
                    
                    return (200, {}, json.dumps({
                        "access_token": token,
                        "token_type": "Bearer",
                        "user": {
                            "email": email,
                            "roles": ["admin"] if "admin" in email else ["user"] if "user" in email else ["viewer"]
                        }
                    }))
                else:
                    return (401, {}, json.dumps({"error": "Invalid credentials"}))
            except Exception:
                return (400, {}, json.dumps({"error": "Invalid request"}))
        
        rsps.add_callback(
            responses.POST,
            self.auth_url,
            callback=auth_callback,
            content_type="application/json"
        )
        
        # Mock user info endpoint (for testing authenticated requests)
        def user_info_callback(request):
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                try:
                    # For mock purposes, just validate the token format
                    if token and len(token) > 10:  # Basic token format check
                        return (200, {}, json.dumps({
                            "authenticated": True,
                            "message": "User authenticated",
                            "user": {
                                "id": "test-user-123",
                                "email": "test@example.com",
                                "roles": ["user"]
                            }
                        }))
                except Exception:
                    pass
            
            return (401, {}, json.dumps({"error": "Unauthorized"}))
        
        rsps.add_callback(
            responses.GET,
            self.user_info_url,
            callback=user_info_callback,
            content_type="application/json"
        )


# Pytest fixtures for HTTP mocking

@pytest.fixture
def jwt_mock_server():
    """Fixture providing JWTMockServer instance."""
    return JWTMockServer()


@pytest.fixture
def mock_jwt_responses():
    """Fixture providing responses.RequestsMock for JWT endpoints."""
    with responses.RequestsMock() as rsps:
        mock_server = JWTMockServer()
        mock_server.setup_responses(rsps)
        yield rsps


@pytest.fixture
def mock_jwt_responses_with_errors():
    """Fixture providing responses.RequestsMock with simulated errors."""
    with responses.RequestsMock() as rsps:
        mock_server = JWTMockServer()
        mock_server.setup_responses(rsps, jwks_status=500, auth_status=500)
        yield rsps


@pytest.fixture
def mock_jwt_responses_network_error():
    """Fixture simulating network connectivity issues."""
    with responses.RequestsMock() as rsps:
        mock_server = JWTMockServer()
        mock_server.setup_responses(rsps, simulate_network_error=True)
        yield rsps


@pytest.fixture
def mock_jwt_provider_config():
    """Fixture providing mock JWT provider configuration."""
    return {
        "issuer": "https://mock-jwt-provider.test",
        "audience": "litellm-proxy",
        "public_key_url": "https://mock-jwt-provider.test/.well-known/jwks.json",
        "user_claim_mappings": {
            "user_id": "sub",
            "user_email": "email",
            "user_role": "role",
            "team_id": "team"
        }
    }


# Context managers for patching HTTP requests

class MockJWTProviderContext:
    """Context manager for mocking JWT provider HTTP calls."""
    
    def __init__(self, 
                 jwks_status: int = 200,
                 auth_status: int = 200,
                 simulate_network_error: bool = False):
        self.jwks_status = jwks_status
        self.auth_status = auth_status
        self.simulate_network_error = simulate_network_error
        self.rsps = None
        
    def __enter__(self):
        self.rsps = responses.RequestsMock(assert_all_requests_are_fired=False)
        self.rsps.start()
        
        mock_server = JWTMockServer()
        mock_server.setup_responses(
            self.rsps,
            jwks_status=self.jwks_status,
            auth_status=self.auth_status,
            simulate_network_error=self.simulate_network_error
        )
        
        return self.rsps
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.rsps:
            self.rsps.stop()
            self.rsps.reset()


# Convenience functions for common mocking scenarios

def mock_successful_jwt_provider():
    """Context manager for successful JWT provider responses."""
    return MockJWTProviderContext()


def mock_failing_jwt_provider():
    """Context manager for failing JWT provider responses."""
    return MockJWTProviderContext(jwks_status=500, auth_status=500)


def mock_network_error_jwt_provider():
    """Context manager for network error simulation."""
    return MockJWTProviderContext(simulate_network_error=True)


# Patch helpers for direct mocking

def patch_httpx_get_jwks(jwks_data: Optional[Dict[str, Any]] = None):
    """Patch httpx.AsyncClient.get for JWKS endpoint calls."""
    if jwks_data is None:
        jwks_data = get_mock_jwks()
    
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        
        def json(self):
            return self.json_data
    
    return patch('httpx.AsyncClient.get', return_value=MockResponse(jwks_data))


def patch_httpx_post_auth(auth_response: Optional[Dict[str, Any]] = None):
    """Patch httpx.AsyncClient.post for authentication endpoint calls."""
    if auth_response is None:
        auth_response = {
            "access_token": mock_jwt_generator.generate_token(),
            "token_type": "Bearer"
        }
    
    class MockResponse:
        def __init__(self, json_data, status_code=200):
            self.json_data = json_data
            self.status_code = status_code
        
        def json(self):
            return self.json_data
    
    return patch('httpx.AsyncClient.post', return_value=MockResponse(auth_response)) 
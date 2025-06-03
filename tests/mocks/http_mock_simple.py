"""
Simplified HTTP Mocking utilities for JWT provider endpoints.
This version doesn't require pytest for basic testing.
"""

import json
from typing import Dict, Any, Optional
from unittest.mock import patch

try:
    import responses
    from responses import RequestsMock
    RESPONSES_AVAILABLE = True
except ImportError:
    RESPONSES_AVAILABLE = False

from .jwt_generator import mock_jwt_generator, get_mock_jwks


class JWTMockServer:
    """
    Mock JWT server for testing authentication flows.
    Simplified version without pytest dependencies.
    """
    
    def __init__(self, base_url: str = "https://mock-jwt-provider.test"):
        self.base_url = base_url.rstrip('/')
        self.jwks_url = f"{self.base_url}/.well-known/jwks.json"
        self.auth_url = f"{self.base_url}/api/login"
        self.token_refresh_url = f"{self.base_url}/api/token/refresh"
        self.user_info_url = f"{self.base_url}/auth-test"
        
    def setup_responses(self, rsps, 
                       jwks_status: int = 200,
                       auth_status: int = 200,
                       simulate_network_error: bool = False) -> None:
        """Set up mock responses for JWT provider endpoints."""
        if not RESPONSES_AVAILABLE:
            return
            
        if simulate_network_error:
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
        if not RESPONSES_AVAILABLE:
            return None
            
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


def mock_successful_jwt_provider():
    """Context manager for successful JWT provider responses."""
    return MockJWTProviderContext()


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
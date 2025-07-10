"""
Custom JWT Authentication for LiteLLM Proxy

This module provides JWT validation for external authentication providers
(like Flask-Security) while maintaining compatibility with LiteLLM's 
cost tracking and logging features.

Features:
- JWT signature validation using JWKS
- Flexible audience validation (single, multiple, domain patterns)
- User claim mapping to LiteLLM context
- Automatic user creation for cost tracking (configurable)

Usage:
    Configure in config.yaml:
    general_settings:
      custom_auth: custom_jwt_auth.jwt_auth
      jwt_settings:
        issuer: "https://your-auth-provider.com"
        public_key_url: "https://your-auth-provider.com/.well-known/jwks.json"
        algorithm: "RS256"
        leeway: 30
        auto_create_users: true  # Enable automatic user creation for cost tracking
        audience_validation:
          mode: "flexible"
          audiences: ["litellm-proxy", "your-app"]
        user_claim_mappings:
          user_id: "sub"
          user_email: "email"
          user_role: "role"
          team_id: "team"
"""

import time
import re
import fnmatch
from typing import Dict, Optional, Any, Union, List

import jwt
import httpx
from fastapi import Request, HTTPException
from cryptography.hazmat.primitives.asymmetric import rsa

from litellm._logging import verbose_proxy_logger
from litellm.proxy._types import UserAPIKeyAuth, LitellmUserRoles


class JWTConfig:
    """Configuration for JWT authentication with enhanced multi-domain audience support"""
    
    def __init__(self, jwt_settings: Dict[str, Any]):
        # Get required settings with validation
        issuer = jwt_settings.get("issuer")
        public_key_url = jwt_settings.get("public_key_url")
        
        if not issuer:
            raise ValueError("JWT issuer is required")
        if not public_key_url:
            raise ValueError("JWT public_key_url is required")
            
        # Now assign with proper types
        self.issuer: str = issuer
        self.public_key_url: str = public_key_url
        self.user_claim_mappings: Dict[str, str] = jwt_settings.get("user_claim_mappings", {})
        self.algorithm: str = jwt_settings.get("algorithm", "RS256")
        self.leeway: int = jwt_settings.get("leeway", 0)
        self.auto_create_users: bool = jwt_settings.get("auto_create_users", True)
        
        # Audience configuration attributes (set by _parse_audience_config)
        self.audience_mode: str
        self.audiences: List[str]
        self.allowed_domains: List[str]
        self.domain_patterns: List[str]
        self.require_exact_match: bool
        
        # Enhanced audience configuration
        self._parse_audience_config(jwt_settings)
    
    def _parse_audience_config(self, jwt_settings: Dict[str, Any]):
        """Parse and validate audience configuration"""
        # Support multiple configuration formats for backward compatibility
        audience_config = jwt_settings.get("audience_validation", {})
        
        # Backward compatibility: if 'audience' is specified directly
        if "audience" in jwt_settings and not audience_config:
            audience_config = {
                "mode": "single",
                "audiences": [jwt_settings["audience"]]
            }
        
        # Default configuration if not specified
        if not audience_config:
            raise ValueError("JWT audience validation configuration is required")
        
        self.audience_mode = audience_config.get("mode", "single")
        self.audiences = audience_config.get("audiences", [])
        self.allowed_domains = audience_config.get("allowed_domains", [])
        self.domain_patterns = audience_config.get("domain_patterns", [])
        self.require_exact_match = audience_config.get("require_exact_match", True)
        
        # Validate configuration
        if self.audience_mode not in ["single", "multiple", "domain_patterns", "flexible"]:
            raise ValueError(f"Invalid audience mode: {self.audience_mode}")
        
        if self.audience_mode in ["single", "multiple"] and not self.audiences:
            raise ValueError(f"audiences list is required for mode: {self.audience_mode}")
        
        if self.audience_mode == "domain_patterns" and not self.domain_patterns:
            raise ValueError("domain_patterns list is required for domain_patterns mode")
    
    def validate_audience(self, token_audiences: Union[str, List[str]]) -> bool:
        """
        Validate JWT audience claims against configured validation rules
        
        Args:
            token_audiences: Audience claim(s) from JWT token
            
        Returns:
            bool: True if audience validation passes
        """
        # Normalize token audiences to list
        if isinstance(token_audiences, str):
            token_audiences = [token_audiences]
        
        verbose_proxy_logger.debug(f"Validating audiences: {token_audiences} against mode: {self.audience_mode}")
        
        if self.audience_mode == "single":
            return self._validate_single_audience(token_audiences)
        elif self.audience_mode == "multiple":
            return self._validate_multiple_audiences(token_audiences)
        elif self.audience_mode == "domain_patterns":
            return self._validate_domain_patterns(token_audiences)
        elif self.audience_mode == "flexible":
            return self._validate_flexible(token_audiences)
        
        return False
    
    def _validate_single_audience(self, token_audiences: List[str]) -> bool:
        """Validate against a single expected audience"""
        if len(self.audiences) != 1:
            verbose_proxy_logger.error("Single audience mode requires exactly one configured audience")
            return False
        
        expected_audience = self.audiences[0]
        return expected_audience in token_audiences
    
    def _validate_multiple_audiences(self, token_audiences: List[str]) -> bool:
        """Validate against multiple allowed audiences (JWT spec compliant)"""
        # Check if any token audience matches any configured audience
        for token_aud in token_audiences:
            if token_aud in self.audiences:
                verbose_proxy_logger.debug(f"Audience match found: {token_aud}")
                return True
        
        verbose_proxy_logger.warning(f"No audience match found. Token: {token_audiences}, Configured: {self.audiences}")
        return False
    
    def _validate_domain_patterns(self, token_audiences: List[str]) -> bool:
        """Validate against domain patterns (supports wildcards)"""
        for token_aud in token_audiences:
            for pattern in self.domain_patterns:
                # Support both fnmatch-style wildcards and regex patterns
                if self._matches_pattern(token_aud, pattern):
                    verbose_proxy_logger.debug(f"Audience {token_aud} matches pattern {pattern}")
                    return True
        
        verbose_proxy_logger.warning(f"No pattern match found. Token: {token_audiences}, Patterns: {self.domain_patterns}")
        return False
    
    def _validate_flexible(self, token_audiences: List[str]) -> bool:
        """Flexible validation combining multiple strategies"""
        # Try exact matches first
        if self.audiences and self._validate_multiple_audiences(token_audiences):
            return True
        
        # Try domain patterns
        if self.domain_patterns and self._validate_domain_patterns(token_audiences):
            return True
        
        # Try allowed domains
        if self.allowed_domains:
            for token_aud in token_audiences:
                domain = self._extract_domain(token_aud)
                if domain:
                    for allowed_domain in self.allowed_domains:
                        # Check exact match or if domain is a subdomain of allowed domain
                        if domain == allowed_domain or domain.endswith('.' + allowed_domain):
                            verbose_proxy_logger.debug(f"Audience domain {domain} matches allowed domain {allowed_domain}")
                            return True
        
        return False
    
    def _matches_pattern(self, audience: str, pattern: str) -> bool:
        """Check if audience matches a pattern (supports wildcards and regex)"""
        try:
            # Try fnmatch first (supports *.example.com style patterns)
            if fnmatch.fnmatch(audience, pattern):
                return True
            
            # Try as regex pattern if fnmatch fails
            if re.match(pattern, audience):
                return True
                
        except re.error:
            # If regex is invalid, fall back to exact string match
            verbose_proxy_logger.warning(f"Invalid regex pattern: {pattern}, falling back to exact match")
            return audience == pattern
        
        return False
    
    def _extract_domain(self, audience: str) -> Optional[str]:
        """Extract domain from audience (handles URLs and plain domains)"""
        try:
            # Handle URLs
            if audience.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(audience)
                return parsed.netloc
            
            # Handle plain domain names - validate they are proper domains
            if ('.' in audience and 
                not audience.startswith('.') and 
                not audience.endswith('.') and
                '..' not in audience):  # No consecutive dots
                return audience
                
        except Exception as e:
            verbose_proxy_logger.warning(f"Failed to extract domain from {audience}: {e}")
        
        return None


class JWKSCache:
    """Simple cache for JWKS public keys with TTL"""
    
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._cache_time: Dict[str, float] = {}
    
    def get(self, url: str) -> Optional[Dict[str, Any]]:
        """Get cached JWKS if not expired"""
        if url in self._cache:
            if time.time() - self._cache_time[url] < self.ttl_seconds:
                return self._cache[url]
            else:
                # Expired, remove from cache
                del self._cache[url]
                del self._cache_time[url]
        return None
    
    def set(self, url: str, jwks: Dict[str, Any]) -> None:
        """Cache JWKS with timestamp"""
        self._cache[url] = jwks
        self._cache_time[url] = time.time()


# Global JWKS cache instance
_jwks_cache = JWKSCache()


async def fetch_jwks(url: str) -> Dict[str, Any]:
    """Fetch JWKS from the given URL with caching"""
    # Check cache first
    cached_jwks = _jwks_cache.get(url)
    if cached_jwks:
        verbose_proxy_logger.debug(f"Using cached JWKS from {url}")
        return cached_jwks
    
    # Fetch from URL
    verbose_proxy_logger.debug(f"Fetching JWKS from {url}")
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(url)
            response.raise_for_status()
            jwks = response.json()
            
            # Cache the result
            _jwks_cache.set(url, jwks)
            return jwks
            
        except httpx.RequestError as e:
            verbose_proxy_logger.error(f"Failed to fetch JWKS from {url}: {e}")
            raise HTTPException(status_code=503, detail=f"Unable to fetch JWT public keys: {e}")
        except httpx.HTTPStatusError as e:
            verbose_proxy_logger.error(f"JWKS endpoint returned error {e.response.status_code}: {e}")
            raise HTTPException(status_code=503, detail=f"JWT public key endpoint error: {e.response.status_code}")


def jwk_to_public_key(jwk: Dict[str, Any]) -> Any:
    """Convert JWK to cryptography public key object"""
    if jwk.get("kty") != "RSA":
        raise ValueError(f"Unsupported key type: {jwk.get('kty')}")
    
    try:
        # Decode base64url-encoded values
        n = jwt.utils.base64url_decode(jwk["n"])
        e = jwt.utils.base64url_decode(jwk["e"])
        
        # Convert to integers
        n_int = int.from_bytes(n, byteorder="big")
        e_int = int.from_bytes(e, byteorder="big")
        
        # Create RSA public key
        public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
        public_key = public_numbers.public_key()
        
        return public_key
        
    except (KeyError, ValueError) as e:
        verbose_proxy_logger.error(f"Failed to convert JWK to public key: {e}")
        raise ValueError(f"Invalid JWK format: {e}")


async def get_public_key(token_header: Dict[str, Any], config: JWTConfig) -> Any:
    """Get the public key for JWT validation"""
    kid = token_header.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="JWT token missing 'kid' in header")
    
    # Fetch JWKS
    jwks = await fetch_jwks(config.public_key_url)
    
    # Find the matching key
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return jwk_to_public_key(key)
    
    raise HTTPException(status_code=401, detail=f"Unable to find public key with kid: {kid}")


def map_jwt_claims_to_user_auth(claims: Dict[str, Any], config: JWTConfig) -> UserAPIKeyAuth:
    """Map JWT claims to UserAPIKeyAuth object"""
    mappings = config.user_claim_mappings
    
    # Extract user information from claims
    user_id = claims.get(mappings.get("user_id", "sub"))
    user_email = claims.get(mappings.get("user_email", "email"))
    team_id = claims.get(mappings.get("team_id", "team"))
    
    # Map role to LiteLLM user role
    role_claim = claims.get(mappings.get("user_role", "role"))
    user_role = map_role_to_litellm_role(role_claim)
    
    # Create UserAPIKeyAuth object
    auth_obj = UserAPIKeyAuth(
        user_id=user_id,
        user_email=user_email,
        user_role=user_role,
        team_id=team_id,
        # Add any additional metadata
        metadata={
            "jwt_claims": claims,
            "auth_method": "jwt"
        }
    )
    
    verbose_proxy_logger.debug(f"Mapped JWT claims to user auth: user_id={user_id}, role={user_role}, team_id={team_id}")
    return auth_obj


def map_role_to_litellm_role(role_claim: Optional[str]) -> LitellmUserRoles:
    """Map external role claim to LiteLLM user role"""
    if not role_claim:
        return LitellmUserRoles.INTERNAL_USER
    
    # Role mapping - customize this based on your external provider
    role_mappings = {
        "admin": LitellmUserRoles.PROXY_ADMIN,
        "proxy_admin": LitellmUserRoles.PROXY_ADMIN,
        "user": LitellmUserRoles.INTERNAL_USER,
        "internal_user": LitellmUserRoles.INTERNAL_USER,
        "viewer": LitellmUserRoles.INTERNAL_USER_VIEW_ONLY,
        "internal_user_viewer": LitellmUserRoles.INTERNAL_USER_VIEW_ONLY,
        "team": LitellmUserRoles.TEAM,
        "customer": LitellmUserRoles.CUSTOMER,
    }
    
    return role_mappings.get(role_claim.lower(), LitellmUserRoles.INTERNAL_USER)


async def validate_jwt_token(token: str, config: JWTConfig) -> Dict[str, Any]:
    """Validate JWT token and return claims"""
    try:
        # Decode header to get key ID
        unverified_header = jwt.get_unverified_header(token)
        
        # Get public key
        public_key = await get_public_key(unverified_header, config)
        
        # Validate token WITHOUT audience validation (we'll do custom validation)
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[config.algorithm],
            issuer=config.issuer,
            # Don't use PyJWT's audience validation - we have custom logic
            options={"verify_aud": False},
            leeway=config.leeway
        )
        
        # Custom audience validation
        token_audience = claims.get("aud")
        if not token_audience:
            verbose_proxy_logger.warning("JWT token missing audience claim")
            raise HTTPException(status_code=401, detail="JWT token missing audience claim")
        
        if not config.validate_audience(token_audience):
            verbose_proxy_logger.warning(f"JWT audience validation failed for: {token_audience}")
            raise HTTPException(status_code=401, detail="JWT audience validation failed")
        
        verbose_proxy_logger.debug(f"Successfully validated JWT for user: {claims.get('sub')}")
        return claims
        
    except jwt.ExpiredSignatureError:
        verbose_proxy_logger.warning("JWT token has expired")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        verbose_proxy_logger.warning(f"Invalid JWT token: {e}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    except HTTPException:
        # Re-raise HTTPException as-is (these are our custom validation errors)
        raise
    except Exception as e:
        verbose_proxy_logger.error(f"JWT validation error: {e}")
        raise HTTPException(status_code=401, detail="Token validation failed")


async def _ensure_user_exists(user_auth: UserAPIKeyAuth, config: JWTConfig) -> None:
    """
    Ensure that a user exists in the database for cost tracking.
    If the user doesn't exist, create them automatically (if enabled).
    """
    if not user_auth.user_id:
        verbose_proxy_logger.debug("No user_id provided, skipping user creation")
        return
    
    if not config.auto_create_users:
        verbose_proxy_logger.debug("Auto user creation disabled, skipping user creation")
        return
    
    try:
        # Import required modules for user management
        from litellm.proxy.proxy_server import prisma_client, user_api_key_cache, proxy_logging_obj
        from litellm.proxy.auth.auth_checks import get_user_object
        
        if not prisma_client:
            verbose_proxy_logger.warning("Database not connected, cannot create user for cost tracking")
            return
        
        # Try to get or create the user
        user_object = await get_user_object(
            user_id=user_auth.user_id,
            prisma_client=prisma_client,
            user_api_key_cache=user_api_key_cache,
            user_id_upsert=True,  # This enables automatic user creation
            proxy_logging_obj=proxy_logging_obj,
            user_email=user_auth.user_email,
            sso_user_id=user_auth.user_id,
        )
        
        if user_object:
            verbose_proxy_logger.info(f"User {user_auth.user_id} ready for cost tracking")
        else:
            verbose_proxy_logger.warning(f"Failed to create/retrieve user {user_auth.user_id}")
            
    except Exception as e:
        # Don't fail authentication if user creation fails
        verbose_proxy_logger.warning(f"Failed to ensure user exists for {user_auth.user_id}: {e}")
        verbose_proxy_logger.debug("JWT authentication will continue without user creation")


async def jwt_auth(request: Request, api_key: str) -> Optional[UserAPIKeyAuth]:
    """
    Main JWT authentication function for LiteLLM custom auth
    
    This function is called by LiteLLM's custom auth mechanism when
    a request comes in with a JWT token in the Authorization header.
    
    Args:
        request: FastAPI request object
        api_key: The JWT token from Authorization header (without 'Bearer ' prefix)
        
    Returns:
        UserAPIKeyAuth: Object containing user authentication information
        
    Raises:
        HTTPException: If token validation fails
    """
    # Get JWT configuration from proxy settings
    from litellm.proxy.proxy_server import general_settings
    
    jwt_settings = general_settings.get("jwt_settings")
    if not jwt_settings:
        verbose_proxy_logger.error("JWT settings not configured")
        raise HTTPException(status_code=500, detail="JWT authentication not properly configured")
    
    try:
        config = JWTConfig(jwt_settings)
    except ValueError as e:
        verbose_proxy_logger.error(f"Invalid JWT configuration: {e}")
        raise HTTPException(status_code=500, detail=f"JWT configuration error: {e}")
    
    # Check if the token looks like a JWT (has 3 parts separated by dots)
    if not api_key or api_key.count('.') != 2:
        verbose_proxy_logger.debug("Received non-JWT token in JWT auth handler, falling back to standard auth")
        # This is not a JWT token, return None to signal fallback to standard authentication
        # When custom auth returns None, LiteLLM continues with standard auth (master key, DB lookup, etc.)
        return None
    
    # Validate the JWT token
    claims = await validate_jwt_token(api_key, config)
    
    # Map claims to UserAPIKeyAuth object
    user_auth = map_jwt_claims_to_user_auth(claims, config)
    
    # Automatically create internal user if JWT authentication succeeds
    await _ensure_user_exists(user_auth, config)
    
    verbose_proxy_logger.info(f"Successfully authenticated user {user_auth.user_id} via JWT")
    return user_auth


async def hybrid_jwt_auth(request: Request, api_key: str) -> UserAPIKeyAuth:
    """
    Hybrid authentication function that tries JWT auth first and falls back to standard auth.
    
    This mimics the enterprise "auto" mode behavior where custom auth failures 
    allow fallback to standard authentication.
    
    Args:
        request: FastAPI request object
        api_key: The API key or JWT token from Authorization header
        
    Returns:
        UserAPIKeyAuth: Object containing user authentication information
        
    Raises:
        Exception: If neither JWT nor standard auth succeeds
    """
    # First try JWT authentication for JWT tokens
    try:
        # Only attempt JWT auth if the token looks like a JWT
        if api_key and api_key.count('.') == 2:
            verbose_proxy_logger.debug("Attempting JWT authentication")
            return await jwt_auth(request, api_key)
    except Exception as e:
        verbose_proxy_logger.debug(f"JWT authentication failed, falling back to standard auth: {e}")
        # Fall through to standard auth below
    
    # If not a JWT or JWT auth failed, use standard LiteLLM authentication
    verbose_proxy_logger.debug("Using standard LiteLLM authentication")
    
    # Import necessary modules for standard auth
    from litellm.proxy.proxy_server import (
        master_key, 
        prisma_client, 
        user_api_key_cache,
        proxy_logging_obj,
        litellm_proxy_admin_name
    )
    from litellm.proxy.auth.user_api_key_auth import _user_api_key_auth_builder
    from litellm.proxy._types import LitellmUserRoles
    import secrets
    
    # Check if it's the master key first (most common for UI access)
    if master_key and secrets.compare_digest(api_key, master_key):
        verbose_proxy_logger.debug("Authenticated using master key")
        return UserAPIKeyAuth(
            api_key=api_key,
            user_role=LitellmUserRoles.PROXY_ADMIN,
            user_id=litellm_proxy_admin_name,
        )
    
    # If not master key, raise an exception to let the standard auth system handle it
    # This ensures that database lookups and other standard auth mechanisms still work
    raise Exception("Not a JWT or master key - defer to standard authentication") 
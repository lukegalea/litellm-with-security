# JWT Authentication Integration Testing - Container-Based Approach

## Overview

This document describes the container-based integration testing approach for JWT authentication in LiteLLM. This approach eliminates the need for separate mock services by using HTTP mocking within the test container, providing better test isolation, faster execution, and simplified infrastructure.

## Architecture

### Before: Multi-Container Approach (Problematic)
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Test Runner   │───▶│ Flask-Mock       │───▶│   LiteLLM       │
│   Container     │    │ Container        │    │   Container     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### After: Single-Container with Mocking (Improved)
```
┌─────────────────────────────────────────────┐    ┌─────────────────┐
│           Test Container                    │───▶│   LiteLLM       │
│  ┌─────────────────┐ ┌─────────────────┐   │    │   Container     │
│  │  Test Runner    │ │  Mocked JWT     │   │    │                 │
│  │                 │ │  Endpoints      │   │    │                 │
│  └─────────────────┘ └─────────────────┘   │    │                 │
└─────────────────────────────────────────────┘    └─────────────────┘
```

## Test Infrastructure Components

### 1. Mock JWT Generator (`tests/mocks/jwt_generator.py`)

The `MockJWTGenerator` class provides:
- RSA key pair generation for JWT signing
- Configurable JWT token creation with custom claims
- JWKS (JSON Web Key Set) response generation
- Pre-configured token generators for common scenarios

#### Key Features:
```python
# Generate tokens for different user types
admin_token = create_admin_token()
user_token = create_user_token()
viewer_token = create_viewer_token()

# Generate JWKS for public key distribution
jwks = get_mock_jwks()

# Create tokens with custom claims
custom_token = mock_jwt_generator.generate_token(
    user_id="custom-user",
    email="custom@example.com",
    roles=["custom-role"],
    team_id="custom-team",
    expires_in=7200,  # 2 hours
    expired=False
)
```

### 2. HTTP Mocking (`tests/mocks/http_mock.py`, `tests/mocks/http_mock_simple.py`)

Provides HTTP endpoint mocking for JWT provider interactions:
- JWKS endpoint responses
- Authentication API simulation
- Token validation endpoints
- Error condition simulation

#### Usage Example:
```python
from tests.mocks.http_mock_simple import mock_successful_jwt_provider

with mock_successful_jwt_provider():
    # Your test code here - all HTTP calls to JWT provider will be mocked
    token = create_admin_token()
    # Test JWT validation logic
```

### 3. Integration Tests (`tests/integration/test_jwt_integration.py`)

Comprehensive test suite covering:
- JWT token validation scenarios
- Role mapping verification
- User context extraction
- Error handling for malformed tokens
- JWKS endpoint failure simulation

## Running Tests

### Container-Based Test Execution

All tests run within the Docker container environment to ensure consistency and eliminate local environment dependencies.

#### Basic Test Commands

```bash
# Start test container with dependencies installed
docker compose --profile test up -d litellm-test

# Run test setup validation
docker compose --profile test exec litellm-test python validate_test_setup.py

# Run integration tests with pytest (after dependencies are installed)
docker compose --profile test exec litellm-test python -m pytest tests/integration/ -v

# Run all tests
docker compose --profile test exec litellm-test python -m pytest tests/ -v

# Clean up test container
docker compose --profile test down
```

#### Alternative: One-off Test Commands

```bash
# Run validation in a one-off container (installs dependencies automatically)
docker compose --profile test run --rm litellm-test python validate_test_setup.py

# Run specific tests after dependency installation
docker compose --profile test run --rm litellm-test bash -c "
  pip install -r requirements-test.txt && 
  python -m pytest tests/integration/test_jwt_integration.py::TestJWTValidation -v
"
```

#### Test Configuration

Tests use the `config_jwt_test.yaml` configuration file:
```yaml
general_settings:
  custom_auth: custom_jwt_auth.jwt_auth
  jwt_settings:
    issuer: "https://mock-jwt-provider.test"
    audience: "litellm-proxy"
    public_key_url: "https://mock-jwt-provider.test/.well-known/jwks.json"
    user_claim_mappings:
      user_id: "sub"
      user_email: "email"
      user_role: "role"
      team_id: "team"
    role_mapping:
      admin: "PROXY_ADMIN"
      user: "INTERNAL_USER"
      viewer: "INTERNAL_USER_VIEW_ONLY"
```

## Test Scenarios Covered

### 1. JWT Validation Tests
- ✅ Valid token authentication for all user types
- ✅ Expired token rejection
- ✅ Invalid signature detection
- ✅ Malformed token handling
- ✅ Missing claims validation

### 2. Role Mapping Tests
- ✅ Admin role → `PROXY_ADMIN`
- ✅ User role → `INTERNAL_USER`
- ✅ Viewer role → `INTERNAL_USER_VIEW_ONLY`
- ✅ Unknown role → Default handling

### 3. User Context Extraction
- ✅ User ID from `sub` claim
- ✅ Email from `email` claim
- ✅ Team ID from `team` claim
- ✅ Role array from `roles` claim

### 4. Error Handling
- ✅ JWKS endpoint failures
- ✅ Network connectivity issues
- ✅ Invalid issuer/audience
- ✅ Token format validation

## Mock User Database

The test infrastructure includes a mock user database with predefined users:

```python
users = {
    "admin@example.com": {
        "id": "admin-user-123",
        "roles": ["admin"],
        "team": "admin-team"
    },
    "user@example.com": {
        "id": "regular-user-456", 
        "roles": ["user"],
        "team": "user-team"
    },
    "viewer@example.com": {
        "id": "viewer-user-789",
        "roles": ["viewer"],
        "team": "viewer-team"
    }
}
```

## Benefits of Container-Based Testing

### Performance Improvements
- **Faster Execution**: No container startup overhead for mock services
- **Parallel Testing**: Tests can run in parallel without container conflicts
- **Resource Efficiency**: Single test container instead of multiple services

### Maintainability Benefits
- **Simplified Infrastructure**: Fewer containers to manage and debug
- **Better Test Isolation**: Each test controls its own mocked responses
- **Easier Debugging**: All test logic in single container environment

### Development Experience
- **Faster Iteration**: Quick test feedback without container coordination
- **Reliable Tests**: No network dependencies between containers
- **Comprehensive Coverage**: Easy testing of edge cases and error conditions

## Troubleshooting Guide

### Common Issues and Solutions

#### 1. Container Permission Issues
**Problem**: `permission denied` errors when running containers
**Solution**: Use explicit entrypoint override:
```bash
docker compose --profile test run --rm --entrypoint "" litellm-test bash -c "command"
```

#### 2. Missing Dependencies
**Problem**: `No module named 'pytest'` or similar import errors
**Solution**: Install dependencies in container or use simplified test scripts:
```bash
docker compose --profile test run --rm --entrypoint "" litellm-test \
  bash -c "pip install pytest responses && python -m pytest tests/"
```

#### 3. JWT Signature Verification Failures
**Problem**: JWT tokens fail signature verification in tests
**Solution**: Use the same key pair for token generation and validation:
```python
# In tests, use mock_jwt_generator consistently
token = mock_jwt_generator.generate_token(...)
public_key = mock_jwt_generator.public_key
```

#### 4. JWKS Endpoint Mocking Issues
**Problem**: JWKS endpoint calls not being intercepted
**Solution**: Ensure proper context manager usage:
```python
with mock_successful_jwt_provider():
    # All HTTP calls within this block are mocked
    test_jwt_validation()
```

#### 5. Test Configuration Loading
**Problem**: JWT settings not loading correctly in tests
**Solution**: Verify configuration file path and format:
```bash
# Check config file is properly mounted
docker compose --profile test run --rm --entrypoint "" litellm-test \
  bash -c "cat /app/config_jwt_test.yaml"
```

### Debugging Test Failures

#### Enable Verbose Logging
```bash
docker compose --profile test run --rm --entrypoint "" litellm-test \
  bash -c "cd /app && python -m pytest tests/integration/ -v -s --tb=long"
```

#### Test Individual Components
```bash
# Test just the mock utilities
docker compose --profile test run --rm --entrypoint "" litellm-test \
  bash -c "cd /app && python test_mocks_simple.py"

# Test specific test class
docker compose --profile test run --rm --entrypoint "" litellm-test \
  bash -c "cd /app && python -m pytest tests/integration/test_jwt_integration.py::TestJWTValidation -v"
```

#### Check Container Environment
```bash
# Verify Python path and imports
docker compose --profile test run --rm --entrypoint "" litellm-test \
  bash -c "python -c 'import sys; print(sys.path)'"

# Check available modules
docker compose --profile test run --rm --entrypoint "" litellm-test \
  bash -c "pip list | grep -E '(jwt|crypto|httpx)'"
```

## Continuous Integration

### CI/CD Pipeline Integration

```yaml
# Example GitHub Actions workflow
name: JWT Integration Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run JWT Integration Tests
        run: |
          docker compose --profile test run --rm --entrypoint "" litellm-test \
            bash -c "cd /app && python test_mocks_simple.py"
```

### Performance Benchmarks

Target performance metrics for CI/CD:
- **Mock utility tests**: < 10 seconds
- **Integration test suite**: < 2 minutes
- **Full test coverage**: > 95% for JWT authentication module

## Migration from Previous Approach

### What Changed
1. **Removed**: `flask-security-mock` service from docker-compose.yml
2. **Removed**: `Dockerfile.flask-mock` file
3. **Added**: HTTP mocking utilities with responses library
4. **Added**: Container-based test execution framework

### Migration Steps
1. ✅ Remove mock service infrastructure
2. ✅ Implement HTTP mocking utilities
3. ✅ Create comprehensive test suite
4. ✅ Validate test execution in containers
5. ✅ Update documentation

## Future Enhancements

### Planned Improvements
- [ ] Add performance benchmarking for JWT validation
- [ ] Implement test coverage reporting
- [ ] Add automated security scanning for JWT implementation
- [ ] Create visual test reporting dashboard

### Extension Points
- **Custom Claims Testing**: Add support for application-specific JWT claims
- **Provider Integration**: Test with real JWT providers (Auth0, Okta, etc.)
- **Load Testing**: Validate performance under high token validation load
- **Security Testing**: Automated vulnerability scanning and penetration testing

This container-based testing approach provides a robust, maintainable foundation for validating JWT authentication integration while eliminating infrastructure complexity and improving developer experience. 
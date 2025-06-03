#!/usr/bin/env python3
"""
Standalone Flask-Security mock server for integration testing
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the mock server class
sys.path.append('/app')
from tests.test_flask_security_integration import FlaskSecurityMockServer
import uvicorn

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
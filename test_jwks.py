#!/usr/bin/env python3
import httpx
import json

def test_jwks_endpoint(url):
    """Test if JWKS endpoint is accessible and valid"""
    try:
        response = httpx.get(url, timeout=10)
        response.raise_for_status()
        
        jwks = response.json()
        
        print(f"✅ JWKS endpoint accessible: {url}")
        print(f"📋 Response status: {response.status_code}")
        print(f"🔑 Number of keys: {len(jwks.get('keys', []))}")
        
        if 'keys' in jwks and len(jwks['keys']) > 0:
            key = jwks['keys'][0]
            print(f"🔧 First key type: {key.get('kty', 'unknown')}")
            print(f"🔧 Algorithm: {key.get('alg', 'unknown')}")
            print(f"🔧 Key ID: {key.get('kid', 'unknown')}")
            return True
        else:
            print("❌ No keys found in JWKS response")
            return False
            
    except Exception as e:
        print(f"❌ JWKS endpoint test failed: {e}")
        return False

if __name__ == "__main__":
    # Test with a sample URL - replace with your actual JWKS URL
    test_url = input("Enter your JWKS URL: ").strip()
    if test_url:
        test_jwks_endpoint(test_url)
    else:
        print("Please provide a JWKS URL to test")

#!/usr/bin/env python3
import urllib.request
import urllib.error
import json

def test_jwks_endpoint(url):
    """Test if JWKS endpoint is accessible and valid"""
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            if response.status == 200:
                jwks = json.loads(response.read().decode())
                
                print(f"✅ JWKS endpoint accessible: {url}")
                print(f"📋 Response status: {response.status}")
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
            else:
                print(f"❌ HTTP {response.status} error")
                return False
                
    except urllib.error.URLError as e:
        print(f"❌ Network error: {e}")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON response: {e}")
        return False
    except Exception as e:
        print(f"❌ JWKS endpoint test failed: {e}")
        return False

if __name__ == "__main__":
    print("JWKS Endpoint Tester")
    print("===================")
    test_url = input("Enter your JWKS URL (or press Enter to skip): ").strip()
    if test_url:
        test_jwks_endpoint(test_url)
    else:
        print("\n🔗 Common JWKS URL patterns:")
        print("  - https://your-domain.com/.well-known/jwks.json")
        print("  - https://your-domain.com/.well-known/openid-configuration/jwks")
        print("  - For Auth0: https://YOUR_DOMAIN.auth0.com/.well-known/jwks.json")
        print("  - For Keycloak: https://YOUR_KEYCLOAK/realms/YOUR_REALM/protocol/openid-connect/certs")

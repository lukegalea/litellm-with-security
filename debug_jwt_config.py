#!/usr/bin/env python3
import os
import sys
import yaml
import json

def check_config_file():
    """Check if there's a config.yaml file and analyze JWT settings"""
    config_files = [
        "config.yaml",
        "/app/config/config.yaml", 
        "proxy_server_config.yaml",
        "litellm_config.yaml"
    ]
    
    found_config = False
    for config_file in config_files:
        if os.path.exists(config_file):
            print(f"📁 Found config file: {config_file}")
            found_config = True
            
            try:
                with open(config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    
                print(f"✅ Config file loaded successfully")
                
                # Check general settings
                general_settings = config.get('general_settings', {})
                
                # Check JWT configuration
                print("\n🔐 JWT Configuration Analysis:")
                print("=" * 40)
                
                # Enterprise JWT
                if general_settings.get('enable_jwt_auth'):
                    print("🏢 Enterprise JWT Auth ENABLED")
                    
                    # Check environment variables
                    jwt_public_key_url = os.environ.get('JWT_PUBLIC_KEY_URL')
                    jwt_audience = os.environ.get('JWT_AUDIENCE')
                    
                    print(f"📍 JWT_PUBLIC_KEY_URL: {jwt_public_key_url or '❌ NOT SET'}")
                    print(f"📍 JWT_AUDIENCE: {jwt_audience or '❌ NOT SET'}")
                    
                    # Check litellm_jwtauth settings
                    jwtauth = general_settings.get('litellm_jwtauth', {})
                    if jwtauth:
                        print("⚙️  LiteLLM JWT Auth settings found:")
                        for key, value in jwtauth.items():
                            print(f"   {key}: {value}")
                    else:
                        print("⚠️  No litellm_jwtauth configuration found")
                
                # Custom JWT
                elif general_settings.get('custom_auth'):
                    print("🔧 Custom JWT Auth ENABLED")
                    print(f"📍 custom_auth: {general_settings.get('custom_auth')}")
                    
                    jwt_settings = general_settings.get('jwt_settings', {})
                    if jwt_settings:
                        print("⚙️  JWT Settings found:")
                        for key, value in jwt_settings.items():
                            if key == 'public_key_url':
                                print(f"   {key}: {value}")
                            else:
                                print(f"   {key}: {value}")
                    else:
                        print("⚠️  No jwt_settings configuration found")
                
                else:
                    print("❌ NO JWT Authentication configured")
                    print("   Neither 'enable_jwt_auth' nor 'custom_auth' found")
                
                # Check model list
                model_list = config.get('model_list', [])
                print(f"\n📝 Models configured: {len(model_list)}")
                for model in model_list[:3]:  # Show first 3 models
                    print(f"   - {model.get('model_name', 'unnamed')}")
                if len(model_list) > 3:
                    print(f"   ... and {len(model_list) - 3} more")
                    
            except yaml.YAMLError as e:
                print(f"❌ YAML parsing error: {e}")
            except Exception as e:
                print(f"❌ Error reading config: {e}")
    
    if not found_config:
        print("❌ No config.yaml file found in common locations")
        print("🔍 Searched locations:")
        for config_file in config_files:
            print(f"   - {config_file}")

def check_environment():
    """Check relevant environment variables"""
    print("\n🌍 Environment Variables:")
    print("=" * 25)
    
    jwt_vars = [
        'JWT_PUBLIC_KEY_URL',
        'JWT_AUDIENCE', 
        'ANTHROPIC_API_KEY',
        'OPENAI_API_KEY'
    ]
    
    for var in jwt_vars:
        value = os.environ.get(var)
        if value:
            if 'KEY' in var:
                print(f"✅ {var}: ***{value[-4:]} (hidden)")
            else:
                print(f"✅ {var}: {value}")
        else:
            print(f"❌ {var}: NOT SET")

if __name__ == "__main__":
    print("LiteLLM JWT Configuration Debugger")
    print("=" * 40)
    
    check_config_file()
    check_environment()
    
    print("\n📋 Next Steps:")
    print("1. Ensure JWKS endpoint is accessible (run: python3 test_jwks_simple.py)")
    print("2. Choose either custom_auth or enable_jwt_auth (not both)")
    print("3. Configure jwt_settings for custom auth OR environment variables for enterprise")
    print("4. Test with a simple curl request")

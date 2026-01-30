#!/usr/bin/env python3
"""
DestroyGPT v10.0 - API Key Setup Helper
Fixes API key issues and helps with migration
"""

import os
from pathlib import Path

# Configuration
HOME = Path.home()
OLD_KEY_FILE = HOME / ".destroygpt_api_key"
NEW_CONFIG_DIR = HOME / ".destroygpt"
NEW_KEY_FILE = NEW_CONFIG_DIR / "api_key"

def setup_api_key():
    """Setup or migrate API key"""
    
    print("=" * 60)
    print("DestroyGPT v10.0 - API Key Setup")
    print("=" * 60)
    print()
    
    # Create config directory if needed
    NEW_CONFIG_DIR.mkdir(exist_ok=True)
    
    # Check for existing keys
    api_key = None
    
    # 1. Check environment variable
    if os.getenv("OPENROUTER_API_KEY"):
        api_key = os.getenv("OPENROUTER_API_KEY").strip()
        print("✓ Found API key in environment variable")
    
    # 2. Check old location (v9.0)
    elif OLD_KEY_FILE.exists():
        try:
            api_key = OLD_KEY_FILE.read_text().strip()
            print(f"✓ Found API key in old location: {OLD_KEY_FILE}")
            print(f"  Migrating to new location: {NEW_KEY_FILE}")
        except Exception as e:
            print(f"⚠️  Could not read old key file: {e}")
    
    # 3. Check new location
    elif NEW_KEY_FILE.exists():
        try:
            api_key = NEW_KEY_FILE.read_text().strip()
            print(f"✓ Found API key in: {NEW_KEY_FILE}")
        except Exception as e:
            print(f"⚠️  Could not read key file: {e}")
    
    # 4. Prompt for new key
    if not api_key:
        print("\n❌ No API key found!")
        print("\nTo get a FREE API key:")
        print("1. Visit: https://openrouter.ai/keys")
        print("2. Sign up (it's free!)")
        print("3. Generate an API key")
        print("4. Copy it (starts with 'sk-or-v1-')")
        print()
        
        api_key = input("Paste your API key here (or press Enter to exit): ").strip()
        
        if not api_key:
            print("\n❌ No API key provided. Exiting.")
            return None
    
    # Validate key format
    if not api_key.startswith("sk-or-v1-"):
        print("\n⚠️  Warning: API key doesn't start with 'sk-or-v1-'")
        print("   OpenRouter keys should start with 'sk-or-v1-'")
        confirm = input("   Continue anyway? [y/N]: ").strip().lower()
        if confirm != 'y':
            print("❌ Setup cancelled.")
            return None
    
    # Save to new location
    try:
        NEW_KEY_FILE.write_text(api_key)
        NEW_KEY_FILE.chmod(0o600)  # Secure permissions
        print(f"\n✓ API key saved to: {NEW_KEY_FILE}")
        print(f"✓ Permissions set to 600 (secure)")
        
        # Test the key
        print("\nTesting API key...")
        test_result = test_api_key(api_key)
        
        if test_result:
            print("✓ API key is valid!")
            print("\n" + "=" * 60)
            print("Setup complete! You can now run DestroyGPT:")
            print("  python3 destroygpt_enhanced.py")
            print("=" * 60)
            return api_key
        else:
            print("⚠️  Could not verify API key (might be network issue)")
            print("   Saved anyway. Try running DestroyGPT to test.")
            return api_key
            
    except Exception as e:
        print(f"\n❌ Could not save API key: {e}")
        print(f"   Try manually creating: {NEW_KEY_FILE}")
        print(f"   Command: echo 'your-key-here' > {NEW_KEY_FILE}")
        return None

def test_api_key(api_key):
    """Test if API key works"""
    try:
        import requests
        response = requests.get(
            "https://openrouter.ai/api/v1/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        print(f"   Test error: {e}")
        return False

if __name__ == "__main__":
    try:
        setup_api_key()
    except KeyboardInterrupt:
        print("\n\n❌ Setup interrupted.")
    except Exception as e:
        print(f"\n❌ Error: {e}")

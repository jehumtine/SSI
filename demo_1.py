import json

from cryptography.fernet import Fernet

from identity_registry import IdentityRegistry, RegistryVerifier


def verify_from_json_file(json_path: str, registry_path: str = "./identity_register") -> dict:
    """
    Loads and verifies an identity package from JSON file
    """
    try:
        # 1. Load the JSON file
        with open(json_path) as f:
            data = json.load(f)

        # 2. Convert back to original formats
        key = data['key'].encode('ascii')
        encrypted_pkg = data['encrypted_package'].encode('latin-1')

        # 3. Decrypt
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_pkg)
        user_package = json.loads(decrypted.decode('utf-8'))

        # 4. Verify against registry
        registry = IdentityRegistry(registry_path)
        return RegistryVerifier.verify_user_package(registry, user_package)

    except Exception as e:
        return {
            "valid": False,
            "error": f"{type(e).__name__}: {str(e)}",
            "debug": {
                "json_keys": list(data.keys()) if 'data' in locals() else None,
                "key_length": len(data.get('key', '')) if 'data' in locals() else 0,
                "package_length": len(data.get('encrypted_package', '')) if 'data' in locals() else 0
            }
        }


# Usage:
result = verify_from_json_file("user_identity_jane.json")
print(json.dumps(result, indent=2))
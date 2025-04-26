from pathlib import Path

from identity_registry import IdentityRegistry, RegistryVerifier
from zk_merkle_identity import ZKMerkleIdentity

# Example usage with multiple identities
if __name__ == "__main__":
    def decrypt_package(encrypted_package: bytes, key: bytes) -> dict:
        """
        Decrypt the identity package using the provided key
        Returns the original user data dictionary
        """
        cipher = Fernet(key)
        try:
            decrypted = cipher.decrypt(encrypted_package)
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            raise ValueError("Decryption failed - invalid key or corrupted package") from e


    def save_encrypted_package(output_path: str,
                               encrypted_package: bytes,
                               key: str) -> None:
        """
        Saves encrypted package and key to a JSON file
        """
        data = {
            "key": key.decode('ascii'),  # Convert bytes to string
            "encrypted_package": encrypted_package.decode('latin-1')
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)


    # Initialize the registry
    registry = IdentityRegistry("identity_register")
    registry.list_identities()
    # Define some sample identities
    documents = [
        {
            "id": "passport",
            "name": "Jane Mungole",
            "passport_number": "AB123456",
            "dob": "1990-01-15",
            "nationality": "US",
            "issue_date": "2020-03-10",
            "expiry_date": "2030-03-09"
        },
        {
            "id": "driver_license",
            "name": "Jane Mungole",
            "license_number": "DL987654",
            "dob": "1990-01-15",
            "address": "123 Privacy St, Cryptoville",
            "issue_date": "2022-05-20",
            "expiry_date": "2026-05-19"
        },
        {
            "id": "health_insurance",
            "name": "Jane Mungole",
            "policy_number": "HI567890",
            "plan_type": "Premium",
            "coverage_details": "Full coverage including dental and vision",
            "start_date": "2023-01-01"
        }
    ]
    selective_attributes = {
        "passport": ["name", "nationality", "dob"],
        "driver_license": ["name", "license_number", "dob"],
        "health_insurance": ["name", "policy_number"]
    }
    identity = ZKMerkleIdentity()
    identity_data=identity.create_identity(documents,selective_attributes)
    user_package = identity.generate_user_package(identity_data)

    # Serialize and encrypt for user download
    import json
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_package = cipher.encrypt(json.dumps(user_package).encode())
    save_encrypted_package(
        output_path="user_identity_jane.json",
        encrypted_package=encrypted_package,  # From cipher.encrypt()
        key=key  # Your Fernet key
    )
    # Provide to user
    print(f"User must securely store:\n- Encryption Key: {key.decode()}\n- Identity Package: {encrypted_package}")

    package = decrypt_package(encrypted_package, key)


    registry.register_identity("jane_mungole", identity, {
        "type": "individual",
        "country": "US"
    })
    doc_proof = identity.generate_disclosure_proof(documents[2], ["name", "policy_number"])
    registry_proof = registry.generate_registry_proof("jane_mungole")
    is_valid_doc = identity.verify_disclosure(doc_proof, identity.get_merkle_root())
    is_valid_registry = registry.verify_identity_in_registry(
        identity.get_merkle_root(),
        registry_proof
    )

    verification_result = RegistryVerifier.verify_user_package(registry, package)
    if verification_result['valid']:
        print("Verification Result is Valid")

    print(f"Document valid: {is_valid_doc}")


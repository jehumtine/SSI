#!/usr/bin/env python3
"""
ZKMerkleIdentity Registry Demo Program

This program demonstrates:
1. Creating multiple identities with documents
2. Registering them in an identity registry
3. Saving the registry to disk
4. Loading the registry from disk
5. Verifying the identities against the loaded registry

Run this file directly to execute the demonstration.
"""

import os
import shutil
from pathlib import Path
import json

# Assuming the original code is in a file named zk_merkle_identity.py
from main import ZKMerkleIdentity, IdentityRegistry


def print_separator(title):
    """Print a section separator with title"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def main():
    # Create a directory for our registry demo
    registry_dir = Path("./demo_registry")

    # Clean up any previous demo
    if registry_dir.exists():
        shutil.rmtree(registry_dir)
    registry_dir.mkdir(parents=True)

    print_separator("CREATING IDENTITIES AND REGISTRY")

    # Initialize the registry
    registry = IdentityRegistry(str(registry_dir))
    print(f"Created new registry in {registry_dir}")

    # Create identity for person 1: Jane Smith
    print("\nCreating identity for Jane Smith...")
    jane_docs = [
        {
            "id": "passport",
            "name": "Jane Smith",
            "passport_number": "CD789012",
            "dob": "1985-07-22",
            "nationality": "Canada",
            "issue_date": "2019-11-05",
            "expiry_date": "2029-11-04"
        },
        {
            "id": "driver_license",
            "name": "Jane Smith",
            "license_number": "DL456789",
            "dob": "1985-07-22",
            "address": "456 Secure Ave, Privacytown",
            "issue_date": "2021-08-15",
            "expiry_date": "2025-08-14"
        }
    ]

    jane_selective = {
        "passport": ["name", "nationality", "dob"],
        "driver_license": ["name", "license_number"]
    }

    jane_identity = ZKMerkleIdentity()
    jane_identity_data = jane_identity.create_identity(jane_docs, jane_selective)
    jane_root = jane_identity.get_merkle_root()
    print(f"Created Jane's identity with root: {jane_root[:8]}...")

    # Create identity for person 2: Bob Johnson
    print("\nCreating identity for Bob Johnson...")
    bob_docs = [
        {
            "id": "school_id",
            "name": "Bob Johnson",
            "student_id": "S12345",
            "dob": "2000-03-15",
            "program": "Computer Science",
            "valid_until": "2025-06-30"
        },
        {
            "id": "health_card",
            "name": "Bob Johnson",
            "card_number": "HC987654",
            "dob": "2000-03-15",
            "blood_type": "O+",
            "emergency_contact": "Mary Johnson, 555-123-4567",
            "issue_date": "2022-01-10"
        }
    ]

    bob_selective = {
        "school_id": ["name", "student_id", "program"],
        "health_card": ["name", "card_number", "blood_type"]
    }

    bob_identity = ZKMerkleIdentity()
    bob_identity_data = bob_identity.create_identity(bob_docs, bob_selective)
    bob_root = bob_identity.get_merkle_root()
    print(f"Created Bob's identity with root: {bob_root[:8]}...")

    # Register identities in the registry with metadata
    print("\nRegistering identities in the registry...")

    jane_path = registry.register_identity("jane_smith", jane_identity, {
        "type": "individual",
        "country": "Canada"
    })
    print(f"Jane's identity registered and saved to {jane_path}")

    bob_path = registry.register_identity("bob_johnson", bob_identity, {
        "type": "student",
        "country": "USA"
    })
    print(f"Bob's identity registered and saved to {bob_path}")

    # Get the registry root
    registry_root = registry.get_registry_root()
    print(f"\nRegistry root after registration: {registry_root[:16]}...")

    # Generate selective disclosure proofs
    print("\nGenerating selective disclosure proofs...")
    jane_passport_proof = jane_identity.generate_disclosure_proof(
        jane_docs[0], ["name", "nationality","dob"]
    )
    print(f"Jane's passport proof created, disclosing: {list(jane_passport_proof['disclosed_attributes'].keys())}")

    bob_school_proof = bob_identity.generate_disclosure_proof(
        bob_docs[0], ["name", "student_id", "program"]
    )
    print(f"Bob's school ID proof created, disclosing: {list(bob_school_proof['disclosed_attributes'].keys())}")

    # Generate registry proofs
    print("\nGenerating registry inclusion proofs...")
    jane_registry_proof = registry.generate_registry_proof("jane_smith")
    bob_registry_proof = registry.generate_registry_proof("bob_johnson")
    print("Registry proofs created for both identities")

    # Export identity info to JSON (optional)
    jane_json_path = registry_dir / "jane_identity.json"
    bob_json_path = registry_dir / "bob_identity.json"

    jane_identity.export_identity_json(str(jane_json_path))
    bob_identity.export_identity_json(str(bob_json_path))
    print(f"\nIdentities exported to JSON files for human readability")

    # Save the registry (this happens automatically, but we'll do it explicitly for clarity)
    registry._save_registry()
    print("\nRegistry explicitly saved to disk")

    # Simulate shutdown and restart by creating a new registry instance
    print_separator("LOADING REGISTRY FROM DISK")
    loaded_registry = IdentityRegistry(str(registry_dir))
    loaded_root = loaded_registry.get_registry_root()

    print(f"Loaded registry from {registry_dir}")
    print(f"Loaded registry root: {loaded_root[:16]}...")
    print(f"Matches original root: {'Yes' if loaded_root == registry_root else 'No'}")

    # List all identities
    identities = loaded_registry.list_identities()
    print(f"\nFound {len(identities)} identities in the registry:")
    for idx, identity in enumerate(identities, 1):
        print(f"  {idx}. ID: {identity['id']}, Type: {identity['metadata'].get('type', 'Unknown')}")

    # Load identities from registry
    print("\nLoading identities from registry...")
    loaded_jane = loaded_registry.get_identity("jane_smith")
    loaded_bob = loaded_registry.get_identity("bob_johnson")

    print(f"Jane's loaded identity root: {loaded_jane.get_merkle_root()[:8]}...")
    print(f"Bob's loaded identity root: {loaded_bob.get_merkle_root()[:8]}...")

    # Verify the loaded identities match the original ones
    jane_roots_match = loaded_jane.get_merkle_root() == jane_root
    bob_roots_match = loaded_bob.get_merkle_root() == bob_root

    print(f"Jane's identity matches original: {'Yes' if jane_roots_match else 'No'}")
    print(f"Bob's identity matches original: {'Yes' if bob_roots_match else 'No'}")

    print_separator("VERIFYING IDENTITIES AND PROOFS")

    # Verify selective disclosure proofs
    print("\nVerifying selective disclosure proofs...")

    jane_disclosure_valid = loaded_jane.verify_disclosure(
        jane_passport_proof, loaded_jane.get_merkle_root()
    )
    print(f"Jane's passport proof verification: {'Valid' if jane_disclosure_valid else 'Invalid'}")

    if jane_disclosure_valid:
        print(f"  Disclosed attributes: {jane_passport_proof['disclosed_attributes']}")

    bob_disclosure_valid = loaded_bob.verify_disclosure(
        bob_school_proof, loaded_bob.get_merkle_root()
    )
    print(f"Bob's school ID proof verification: {'Valid' if bob_disclosure_valid else 'Invalid'}")

    if bob_disclosure_valid:
        print(f"  Disclosed attributes: {bob_school_proof['disclosed_attributes']}")

    # Verify registry inclusion proofs
    print("\nVerifying registry inclusion proofs...")

    jane_registry_valid = loaded_registry.verify_identity_in_registry(
        loaded_jane.get_merkle_root(), jane_registry_proof
    )
    print(f"Jane's registry inclusion verification: {'Valid' if jane_registry_valid else 'Invalid'}")

    bob_registry_valid = loaded_registry.verify_identity_in_registry(
        loaded_bob.get_merkle_root(), bob_registry_proof
    )
    print(f"Bob's registry inclusion verification: {'Valid' if bob_registry_valid else 'Invalid'}")

    # Final summary
    print_separator("SUMMARY")
    all_valid = (
            jane_disclosure_valid and
            bob_disclosure_valid and
            jane_registry_valid and
            bob_registry_valid
    )

    if all_valid:
        print("All identity operations completed successfully!")
        print("✓ Created multiple identities")
        print("✓ Registered identities in the registry")
        print("✓ Saved the registry to disk")
        print("✓ Loaded the registry from disk")
        print("✓ Verified selective disclosures")
        print("✓ Verified registry inclusion")
    else:
        print("⚠️ Some verifications failed!")

    print("\nRegistry files are available at:", registry_dir)


if __name__ == "__main__":
    main()
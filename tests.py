import unittest
import os
import shutil
from pathlib import Path
import tempfile
import json

# Assuming the code provided is in a file named zk_merkle_identity.py
from main import ZKMerkleIdentity, IdentityRegistry


class TestZKMerkleIdentityRegistry(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for the test registry
        self.test_dir = tempfile.mkdtemp()
        self.registry_dir = Path(self.test_dir) / "test_registry"

        # Sample data for testing
        self.sample_documents = [
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

        self.selective_attributes = {
            "passport": ["name", "nationality", "dob"],
            "driver_license": ["name", "license_number"]
        }

    def tearDown(self):
        # Clean up test directory
        shutil.rmtree(self.test_dir)

    def test_create_save_load_verify_identity(self):
        """Test the full lifecycle: create, save, load, and verify an identity"""
        # 1. Create a new registry
        registry = IdentityRegistry(str(self.registry_dir))

        # 2. Create and register an identity
        identity = ZKMerkleIdentity()
        identity_data = identity.create_identity(self.sample_documents, self.selective_attributes)

        # Capture the root for later verification
        original_root = identity.get_merkle_root()

        # Register with metadata
        registry.register_identity("jane_smith", identity, {
            "type": "individual",
            "country": "Canada"
        })

        # 3. Save the registry (implicit in register_identity)
        registry_root = registry.get_registry_root()
        self.assertTrue(registry_root, "Registry root should not be empty")

        # 4. Generate a proof for selective disclosure
        doc_proof = identity.generate_disclosure_proof(
            self.sample_documents[0],
            ["name", "nationality","dob"]
        )

        # 5. Generate a proof that the identity is in the registry
        registry_proof = registry.generate_registry_proof("jane_smith")

        # 6. Create a new registry instance (simulating restart)
        new_registry = IdentityRegistry(str(self.registry_dir))

        # 7. Verify the registry was properly loaded
        self.assertEqual(
            registry_root,
            new_registry.get_registry_root(),
            "Registry root should be the same after loading"
        )

        # 8. Load the identity from the registry
        loaded_identity = new_registry.get_identity("jane_smith")

        # 9. Verify the loaded identity has the same root
        self.assertEqual(
            original_root,
            loaded_identity.get_merkle_root(),
            "Identity root should be the same after loading"
        )

        # 10. Verify the document proof against the loaded identity
        is_valid_doc = loaded_identity.verify_disclosure(
            doc_proof,
            loaded_identity.get_merkle_root()
        )
        self.assertTrue(is_valid_doc, "Document proof should be valid")

        # 11. Verify the identity is in the registry
        is_valid_registry = new_registry.verify_identity_in_registry(
            loaded_identity.get_merkle_root(),
            registry_proof
        )
        self.assertTrue(is_valid_registry, "Identity should be verifiable in the registry")

    def test_multiple_identities(self):
        """Test creating and verifying multiple identities in the registry"""
        # Create a registry
        registry = IdentityRegistry(str(self.registry_dir))

        # Create two different identities
        identity1 = ZKMerkleIdentity()
        identity1.create_identity([self.sample_documents[0]], {"passport": ["name", "nationality"]})

        identity2_docs = [{
            "id": "school_id",
            "name": "Alex Johnson",
            "student_id": "S12345",
            "dob": "2000-03-15",
            "program": "Computer Science",
            "valid_until": "2025-06-30"
        }]
        identity2 = ZKMerkleIdentity()
        identity2.create_identity(identity2_docs, {"school_id": ["name", "student_id"]})

        # Register both identities
        registry.register_identity("jane_smith", identity1, {"type": "individual"})
        registry.register_identity("alex_johnson", identity2, {"type": "student"})

        # List identities
        identities = registry.list_identities()
        self.assertEqual(len(identities), 2, "Registry should have two identities")

        # Get proofs for both identities
        proof1 = registry.generate_registry_proof("jane_smith")
        proof2 = registry.generate_registry_proof("alex_johnson")

        # Verify both identities in registry
        is_valid1 = registry.verify_identity_in_registry(identity1.get_merkle_root(), proof1)
        is_valid2 = registry.verify_identity_in_registry(identity2.get_merkle_root(), proof2)

        self.assertTrue(is_valid1, "First identity should be valid")
        self.assertTrue(is_valid2, "Second identity should be valid")

    def test_identity_persistence(self):
        """Test that identities persist when registry is reloaded"""
        # First registry instance
        registry1 = IdentityRegistry(str(self.registry_dir))

        # Create identity
        identity = ZKMerkleIdentity()
        identity.create_identity(self.sample_documents, self.selective_attributes)
        registry1.register_identity("jane_smith", identity)

        # Save explicitly to be sure
        registry1._save_registry()

        # Second registry instance (simulating restart)
        registry2 = IdentityRegistry(str(self.registry_dir))

        # Check identities were loaded
        identities = registry2.list_identities()
        self.assertEqual(len(identities), 1, "Registry should have one identity after reload")
        self.assertEqual(identities[0]['id'], "jane_smith", "Identity ID should match")

        # Load and verify the identity
        loaded_identity = registry2.get_identity("jane_smith")
        self.assertEqual(
            loaded_identity.get_merkle_root(),
            identity.get_merkle_root(),
            "Identity root should be the same after reload"
        )

    def test_selective_disclosure(self):
        """Test creating and verifying selective disclosure proofs"""
        # Create registry and identity
        registry = IdentityRegistry(str(self.registry_dir))
        identity = ZKMerkleIdentity()
        identity.create_identity(self.sample_documents, self.selective_attributes)
        registry.register_identity("jane_smith", identity)

        # Generate proofs for different attribute combinations
        passport = self.sample_documents[0]

        # Prove only name
        name_proof = identity.generate_disclosure_proof(passport, ["name", "nationality", "dob"])
        self.assertTrue(
            identity.verify_disclosure(name_proof, identity.get_merkle_root()),
            "Name-only proof should be valid"
        )
        self.assertEqual(
            name_proof["disclosed_attributes"],
            {"name": "Jane Smith"},
            "Proof should only contain name"
        )

        # Prove name and nationality
        name_nat_proof = identity.generate_disclosure_proof(passport, ["name", "nationality"])
        self.assertTrue(
            identity.verify_disclosure(name_nat_proof, identity.get_merkle_root()),
            "Name and nationality proof should be valid"
        )
        self.assertEqual(
            name_nat_proof["disclosed_attributes"],
            {"name": "Jane Smith", "nationality": "Canada"},
            "Proof should contain name and nationality"
        )

        # Verify the proofs still work after registry reload
        new_registry = IdentityRegistry(str(self.registry_dir))
        loaded_identity = new_registry.get_identity("jane_smith")

        self.assertTrue(
            loaded_identity.verify_disclosure(name_proof, loaded_identity.get_merkle_root()),
            "Name proof should be valid after reload"
        )
        self.assertTrue(
            loaded_identity.verify_disclosure(name_nat_proof, loaded_identity.get_merkle_root()),
            "Name and nationality proof should be valid after reload"
        )

    def test_export_json(self):
        """Test exporting identity information to JSON"""
        # Create registry and identity
        registry = IdentityRegistry(str(self.registry_dir))
        identity = ZKMerkleIdentity()
        identity.create_identity(self.sample_documents, self.selective_attributes)
        registry.register_identity("jane_smith", identity)

        # Export to JSON
        json_path = Path(self.test_dir) / "identity_export.json"
        identity.export_identity_json(str(json_path))

        # Verify JSON file exists and contains expected data
        self.assertTrue(json_path.exists(), "Export file should exist")

        with open(json_path, 'r') as f:
            exported_data = json.load(f)

        self.assertEqual(
            exported_data["merkle_root"],
            identity.get_merkle_root(),
            "Exported JSON should contain correct Merkle root"
        )

        # Verify documents are included
        self.assertGreaterEqual(len(exported_data["documents"]), 2, "Should have at least 2 documents")


if __name__ == "__main__":
    unittest.main()
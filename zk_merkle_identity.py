import hashlib
import json
import os
from typing import List, Dict, Tuple
import secrets
import pickle
from merkle_tree import MerkleTree


class ZKMerkleIdentity:
    def __init__(self, leaves: List[bytes] = None):
        self.salt_cache = {}  # Store salts for commitments
        if leaves:
            self.merkle_tree = MerkleTree(leaves)
        else:
            self.merkle_tree = None

    def _generate_salt(self) -> bytes:
        """Generate a random salt for commitments"""
        return secrets.token_bytes(32)

    def _create_commitment(self, document: Dict, attributes: List[str] = None) -> Tuple[bytes, Dict]:
        """
        Create a commitment that hides the document content
        Returns the commitment hash and the salts used
        """
        salt = self._generate_salt()

        # If specific attributes are provided, only commit to those
        if attributes:
            filtered_doc = {k: document[k] for k in attributes if k in document}
        else:
            filtered_doc = document

        # Convert document to bytes and combine with salt
        doc_bytes = json.dumps(filtered_doc, sort_keys=True).encode('utf-8')
        commitment = hashlib.sha256(doc_bytes + salt).digest()

        # Store salt for this commitment
        commitment_hex = commitment.hex()
        self.salt_cache[commitment_hex] = {
            "salt": salt,
            "attributes": attributes if attributes else list(document.keys())
        }

        return commitment, {"salt": salt.hex(), "attributes": attributes if attributes else list(document.keys())}

    def create_identity(self, documents: List[Dict], selective_attributes: Dict = None) -> Dict:
        """
        Create an identity from a list of document dictionaries
        Optional selective_attributes allows specifying which attributes to include for each document
        Returns the identity with document commitments and Merkle root
        """
        commitments = []
        commitment_data = {}

        for i, doc in enumerate(documents):
            # Get attributes to commit to for this document
            doc_id = doc.get("id", str(i))
            attrs = None
            if selective_attributes and doc_id in selective_attributes:
                attrs = selective_attributes[doc_id]

            # Create commitment
            commitment, data = self._create_commitment(doc, attrs)
            commitments.append(commitment)
            commitment_data[commitment.hex()] = {
                "document_id": doc_id,
                "salt": data["salt"],
                "attributes": data["attributes"]
            }

        # Create Merkle tree with commitments
        self.merkle_tree = MerkleTree(commitments)
        for leaf in self.merkle_tree.leaves:
            proof = self.merkle_tree.get_proof(leaf)
            commitment_hex = leaf.hex()

            if commitment_hex in commitment_data:
                commitment_data[commitment_hex]["merkle_proof"] = {
                    "path_elements": [p["data"].hex() for p in proof],
                    "path_indices": [1 if p["position"] == "right" else 0 for p in proof],
                }

        return {
            "merkle_root": self.merkle_tree.get_root().hex(),
            "commitments": commitment_data,
            "documents": [doc.get("id", str(i)) for i, doc in enumerate(documents)],
        }

    def generate_disclosure_proof(self, document: Dict, attributes_to_disclose: List[str]) -> Dict:
        # Ensure we have a Merkle tree
        if not self.merkle_tree:
            raise ValueError("No identity has been created yet")

        # Filter document to only include requested attributes
        filtered_doc = {k: document[k] for k in attributes_to_disclose if k in document}

        # Find original commitment for this document
        doc_id = document.get("id", "unknown")
        original_commitment = None
        commitment_hex = None

        for hex_commit, data in self.salt_cache.items():
            commitment = bytes.fromhex(hex_commit)

            # Try to verify if this commitment matches the document
            test_doc_bytes = json.dumps(filtered_doc, sort_keys=True).encode('utf-8')

            # Only attempt to verify if we have the salt for this commitment
            if "salt" in data:
                test_commitment = hashlib.sha256(test_doc_bytes + data["salt"]).digest()

                if test_commitment.hex() == hex_commit:
                    original_commitment = commitment
                    commitment_hex = hex_commit
                    break

        if not original_commitment:
            raise ValueError(f"Document {doc_id} not found in the identity")

        # Get Merkle proof for this commitment
        merkle_proof = self.merkle_tree.get_proof(original_commitment)

        # Convert to ZK-friendly format
        path_elements = [step["data"].hex() for step in merkle_proof]
        path_indices = [1 if step["position"] == "right" else 0 for step in merkle_proof]

        # Create proof with only disclosed attributes
        return {
            "merkle_root": self.merkle_tree.get_root().hex(),
            "disclosed_attributes": filtered_doc,
            "commitment": commitment_hex,
            "path_elements": path_elements,
            "path_indices": path_indices,
            # Include a blinded version of the salt that can be used for verification
            # without revealing the actual salt
            "blinded_salt": hashlib.sha256(self.salt_cache[commitment_hex]["salt"]).digest().hex()
        }

    def generate_user_package(self, identity_data: Dict) -> Dict:
        """Package identity data for user storage"""
        return {
            "version": "1.0",
            "merkle_root": identity_data["merkle_root"],
            "documents": {
                doc_id: {
                    "salt": identity_data["commitments"][commit_hex]["salt"],
                    "merkle_proof": identity_data["commitments"][commit_hex]["merkle_proof"],
                    "committed_attributes": identity_data["commitments"][commit_hex]["attributes"]
                }
                for commit_hex, data in identity_data["commitments"].items()
                for doc_id in [data["document_id"]]
            }
        }

    def verify_disclosure(self, proof: Dict, expected_root: str) -> bool:
        # Check if the Merkle root matches
        if proof["merkle_root"] != expected_root:
            return False

        # Convert proof elements back to bytes format for verification
        commitment = bytes.fromhex(proof["commitment"])

        binary_proof = []
        for i, elem in enumerate(proof["path_elements"]):
            position = "right" if proof["path_indices"][i] == 1 else "left"
            binary_proof.append({
                "data": bytes.fromhex(elem),
                "position": position
            })

        # Reconstruct path to root
        current = commitment
        for step in binary_proof:
            sibling = step["data"]
            position = step["position"]

            if position == "left":
                current = hashlib.sha256(sibling + current).digest()
            else:
                current = hashlib.sha256(current + sibling).digest()

        # Check if we reached the expected root
        root_bytes = bytes.fromhex(expected_root)
        return current == root_bytes

    def save_identity(self, filepath: str) -> None:
        """
        Save the identity system to a file, including the Merkle tree and salt cache.

        Args:
            filepath: Path where to save the identity data
        """
        if not self.merkle_tree:
            raise ValueError("No identity has been created yet")

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)

        # Prepare data for serialization
        data = {
            "salt_cache": self.salt_cache,
            "merkle_tree": {
                "leaves": self.merkle_tree.leaves,
                "tree": self.merkle_tree.tree
            }
        }

        # Serialize and save
        with open(filepath, 'wb') as file:
            pickle.dump(data, file)

        print(f"Identity saved to {filepath}")

    def load_identity(self, filepath: str) -> None:
        """
        Load the identity system from a file.

        Args:
            filepath: Path to the saved identity data
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Identity file not found: {filepath}")

        # Load serialized data
        with open(filepath, 'rb') as file:
            data = pickle.load(file)

        # Restore state
        self.salt_cache = data["salt_cache"]

        # Reconstruct Merkle tree
        merkle_data = data["merkle_tree"]
        self.merkle_tree = MerkleTree(merkle_data["leaves"])

        # Verify the loaded tree matches the saved one
        for level_idx, level in enumerate(merkle_data["tree"]):
            for node_idx, node in enumerate(level):
                if level_idx < len(self.merkle_tree.tree) and node_idx < len(self.merkle_tree.tree[level_idx]):
                    assert node == self.merkle_tree.tree[level_idx][
                        node_idx], "Loaded tree doesn't match the expected structure"

        print(f"Identity loaded from {filepath}")

    def export_identity_json(self, filepath: str) -> None:
        """
        Export identity information to a JSON file (human-readable format)

        Args:
            filepath: Path where to save the JSON data
        """
        if not self.merkle_tree:
            raise ValueError("No identity has been created yet")

        # Prepare data for JSON serialization
        export_data = {
            "merkle_root": self.merkle_tree.get_root().hex(),
            "documents": {}
        }

        # Process each commitment
        for commitment_hex, data in self.salt_cache.items():
            doc_id = None

            # Try to find the document ID from the original tree creation
            for commit, info in self.salt_cache.items():
                if commit == commitment_hex and "document_id" in info:
                    doc_id = info["document_id"]
                    break

            if not doc_id:
                doc_id = f"document_{len(export_data['documents'])}"

            export_data["documents"][doc_id] = {
                "commitment": commitment_hex,
                "attributes": data.get("attributes", []),
                # Don't export actual salt values in JSON format for security
                "has_salt": "salt" in data
            }

        # Save as JSON
        with open(filepath, 'w') as file:
            json.dump(export_data, file, indent=2)

        print(f"Identity exported to {filepath}")

    def get_merkle_root(self) -> str:
        """Get the Merkle root as a hex string"""
        if not self.merkle_tree:
            raise ValueError("No identity has been created yet")
        return self.merkle_tree.get_root().hex()

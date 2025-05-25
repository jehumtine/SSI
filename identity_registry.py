import datetime
import hashlib
from typing import List, Dict
import secrets
import pickle
from pathlib import Path
from merkle_tree import MerkleTree
from zk_merkle_identity import ZKMerkleIdentity

class IdentityRegistry:
    """
    A registry that manages multiple identities in a Merkle tree structure,
    where each leaf node is an identity's Merkle root
    """

    def __init__(self, storage_dir: str = "./identity_register"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True, parents=True)

        # Registry's Merkle tree components
        self.identity_roots = []  # List of identity roots (bytes)
        self.registry_tree = None
        self.registry_salts = {}  # Salt for each identity commitment

        # Identity metadata storage
        self.registry_data = {}
        self.load_registry()

    def load_registry(self) -> None:
        """Load registry state from storage"""
        registry_file = self.storage_dir / "registry.pkl"

        if registry_file.exists():
            with open(registry_file, 'rb') as f:
                data = pickle.load(f)
                self.identity_roots = data['identity_roots']
                self.registry_data = data['registry_data']
                self.registry_salts = data.get('registry_salts', {})

            # Rebuild registry Merkle tree
            if self.identity_roots:
                self.registry_tree = MerkleTree(self.identity_roots)
            else:
                self.registry_tree = None
        else:
            self.identity_roots = []
            self.registry_data = {}
            self.registry_tree = None
            self.registry_salts = {}

    def _save_registry(self) -> None:
        """Save registry state to storage"""
        registry_file = self.storage_dir / "registry.pkl"

        data = {
            'identity_roots': self.identity_roots,
            'registry_data': self.registry_data,
            'registry_salts': self.registry_salts
        }

        with open(registry_file, 'wb') as f:
            pickle.dump(data, f)

    def register_identity(self, identity_id: str, identity: ZKMerkleIdentity,
                          metadata: Dict = None) -> str:
        """
        Register a new identity in the registry's Merkle tree
        Returns the file path where the identity is stored
        """
        # Save the identity separately
        identity_path = self.storage_dir / f"{identity_id}.pkl"
        identity.save_identity(str(identity_path))

        # Get identity's Merkle root
        identity_root_hex = identity.get_merkle_root()
        identity_root_bytes = bytes.fromhex(identity_root_hex)

        # Create commitment for the identity root
        salt = secrets.token_bytes(32)
        commitment = hashlib.sha256(identity_root_bytes + salt).digest()

        # Add to registry structures
        self.identity_roots.append(commitment)
        self.registry_salts[commitment.hex()] = salt
        self.registry_data[commitment.hex()] = {
            'identity_root': identity_root_hex,
            'identity_id': identity_id,
            'identity_path': str(identity_path),
            'metadata': metadata or {},
            'registered_at': datetime.datetime.now().isoformat(),
            'salt': salt.hex()
        }

        # Rebuild registry Merkle tree
        self.registry_tree = MerkleTree(self.identity_roots)

        # Save registry state
        self._save_registry()

        return self.registry_data[commitment.hex()]

    def get_registry_root(self) -> str:
        """Get the current registry Merkle root"""
        if not self.registry_tree:
            return ""
        return self.registry_tree.get_root().hex()

    def verify_identity_in_registry(self, identity_root: str, proof: Dict) -> bool:
        """
        Verify that an identity root is properly committed in the registry
        Proof should contain both the salt and Merkle proof components
        """
        # Reconstruct commitment
        try:
            salt = bytes.fromhex(proof['salt'])
            identity_root_bytes = bytes.fromhex(identity_root)
            commitment = hashlib.sha256(identity_root_bytes + salt).digest()
        except:
            return False

        # Verify Merkle proof
        if not self.registry_tree:
            return False

        merkle_proof = [
            {'data': bytes.fromhex(p), 'position': pos}
            for p, pos in zip(proof['path_elements'], proof['path_positions'])
        ]

        current = commitment
        for step in merkle_proof:
            sibling = step['data']
            if step['position'] == 'left':
                current = hashlib.sha256(sibling + current).digest()
            else:
                current = hashlib.sha256(current + sibling).digest()

        return current == self.registry_tree.get_root()

    def generate_registry_proof(self, identity_id: str) -> Dict:
        """Generate inclusion proof for an identity in the registry"""
        # Find the identity commitment
        identity_info = next(
            (v for v in self.registry_data.values() if v['identity_id'] == identity_id),
            None
        )
        if not identity_info:
            raise ValueError(f"Identity {identity_id} not found in registry")

        identity_root_bytes = bytes.fromhex(identity_info['identity_root'])
        salt_bytes = bytes.fromhex(identity_info['salt'])
        commitment = hashlib.sha256(
            identity_root_bytes + salt_bytes
        ).digest()

        # Generate Merkle proof
        merkle_proof = self.registry_tree.get_proof(commitment)

        return {
            'identity_root': identity_info['identity_root'],
            'salt': identity_info['salt'],
            'path_elements': [p['data'].hex() for p in merkle_proof],
            'path_positions': [p['position'] for p in merkle_proof],
            'registry_root': self.get_registry_root()
        }

    def get_identity(self, identity_id: str) -> ZKMerkleIdentity:
        """Load a registered identity"""
        identity_info = next(
            (v for v in self.registry_data.values() if v['identity_id'] == identity_id),
            None
        )
        if not identity_info:
            raise ValueError(f"Identity {identity_id} not found in registry")

        identity = ZKMerkleIdentity()
        identity.load_identity(identity_info['identity_path'])
        return identity

    def list_identities(self) -> List[Dict]:
        """List all registered identities with basic info"""
        return [
            {
                'id': data['identity_id'],
                'registered_at': data['registered_at'],
                'metadata': data['metadata'],
                'identity_root': data['identity_root']
            }
            for data in self.registry_data.values()
        ]


class RegistryVerifier:
    @staticmethod
    def verify_user_package(registry: IdentityRegistry, user_package: dict) -> dict:
        """
        Verify that a user package is properly registered in the registry
        Returns verification result and registry proof if valid
        """
        # 1. Extract the Merkle root from user package
        user_root = user_package.get('merkle_root')
        if not user_root:
            raise ValueError("Invalid user package: missing merkle_root")

        # 2. Check if this root exists in registry
        identity_info = next(
            (v for v in registry.registry_data.values()
             if v['identity_root'] == user_root),
            None
        )

        if not identity_info:
            return {
                'valid': False,
                'reason': 'Identity not found in registry'
            }

        # 3. Generate registry proof
        registry_proof = user_package["proof"]
        print("identity_info" + str(identity_info))
        print("registry_proof" + str(registry_proof))
        # 4. Verify against registry
        is_valid = registry.verify_identity_in_registry(
            identity_root=user_root,
            proof={
                'salt': registry_proof['salt'],
                'path_elements': registry_proof['path_elements'],
                'path_positions': registry_proof['path_positions']
            }
        )

        return {
            'valid': is_valid,
            'registry_proof': registry_proof if is_valid else None,
            'identity_id': identity_info['identity_id'],
            'metadata': identity_info['metadata']
        }

    @staticmethod
    def verify_document_disclosure(registry: IdentityRegistry,
                                   disclosure_proof: dict) -> dict:
        """
        Verify a document disclosure proof against the registry
        """
        # 1. Verify the document proof's Merkle root
        doc_root = disclosure_proof.get('merkle_root')
        if not doc_root:
            raise ValueError("Invalid disclosure proof: missing merkle_root")

        # 2. First verify the root is in registry
        root_verification = RegistryVerifier.verify_user_package(
            registry,
            {'merkle_root': doc_root}
        )

        if not root_verification['valid']:
            return {
                'valid': False,
                'reason': 'Identity root not valid in registry',
                'root_verification': root_verification
            }

        # 3. Verify the document proof itself
        identity = registry.get_identity(root_verification['identity_id'])
        doc_valid = identity.verify_disclosure(
            disclosure_proof,
            doc_root
        )

        return {
            'valid': doc_valid,
            'identity_id': root_verification['identity_id'],
            'disclosed_attributes': disclosure_proof.get('disclosed_attributes', {}),
            'registry_proof': root_verification['registry_proof']
        }

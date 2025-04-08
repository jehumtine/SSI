from pathlib import Path

from fontTools.misc.eexec import decrypt

from identity_registry import IdentityRegistry, RegistryVerifier
from models import IdentityPackage, UserPackage
from zk_merkle_identity import ZKMerkleIdentity
import json
from cryptography.fernet import Fernet
import random

registry = IdentityRegistry("identity_register")

def save_encrypted_package(output_path: str,
                           encrypted_package: bytes,
                           key: str) -> None:
    """
    Saves encrypted package and key to a JSON file
    """
    data = {
        "key": key.decode('ascii'),  # Convert bytes to string
        "package": encrypted_package.decode('latin-1')
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)


async def create_identity(identity_package: IdentityPackage):
    identity = ZKMerkleIdentity()
    response_data = []
    for doc in identity_package.documents:
        response_data.append(doc.model_dump_json())

    identity_data = identity.create_identity(response_data)
    id = random.randint(1, 1000)
    registry.register_identity(id, identity,{"type": "individual", "country": "ZM"})
    user_package = identity.generate_user_package(identity_data)
    key = Fernet.generate_key()
    cipher = Fernet(key)
    encrypted_package = cipher.encrypt(json.dumps(user_package).encode())
    data = {
        "key": key.decode('ascii'),
        "encrypted_package": encrypted_package.decode(),
    }
    return data


async def verify_identity(user_package: UserPackage):
    key = user_package.key.encode('ascii')
    encrypted_pkg = user_package.package
    cipher = Fernet(key)
    decrypted_pkg = cipher.decrypt(encrypted_pkg)
    package = json.loads(decrypted_pkg.decode('utf-8'))
    return RegistryVerifier.verify_user_package(registry, package)

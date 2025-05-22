import os
import json
import base64
import hashlib
import secrets
import struct
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from pathlib import Path
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import click
import yaml
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cpabe.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('CPABE_SDK')

# ==============================================
# Data Models and Configurations
# ==============================================

@dataclass
class SystemConfig:
    """System configuration parameters"""
    storage_backend: str = "file"
    encryption_algorithm: str = "AES-256-GCM"
    key_derivation: str = "PBKDF2"
    hash_algorithm: str = "SHA-256"
    chunk_size: int = 8192
    backup_enabled: bool = True
    audit_enabled: bool = True
    max_file_size: int = 1024 * 1024 * 1024  # 1GB
    session_timeout: int = 3600  # 1 hour

@dataclass
class AttributeAuthority:
    """Attribute Authority data model"""
    authority_id: str
    name: str
    description: str
    attributes: List[str]
    public_key: str
    private_key: str
    created_at: str
    updated_at: str
    status: str = "active"
    contact_info: Dict[str, str] = None

@dataclass
class UserKey:
    """User key data model"""
    user_id: str
    authority_id: str
    attributes: List[str]
    encrypted_key: str
    key_hash: str
    created_at: str
    expires_at: str
    revoked: bool = False
    metadata: Dict[str, Any] = None

@dataclass
class AccessPolicy:
    """Access policy data model"""
    policy_id: str
    name: str
    description: str
    policy_expression: str
    created_by: str
    created_at: str
    updated_at: str
    version: int = 1
    active: bool = True

@dataclass
class EncryptedFile:
    """Encrypted file metadata"""
    file_id: str
    original_name: str
    policy_id: str
    encrypted_path: str
    file_hash: str
    file_size: int
    encrypted_at: str
    encrypted_by: str
    access_count: int = 0
    last_accessed: str = None

# ==============================================
# Core CP-ABE Cryptographic Engine
# ==============================================

class CPABECrypto:
    """Core cryptographic operations for CP-ABE"""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_master_keys(self) -> Tuple[str, str]:
        """Generate master public and private keys"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return base64.b64encode(public_pem).decode(), base64.b64encode(private_pem).decode()
    
    def generate_attribute_key(self, attributes: List[str], master_private_key: str) -> str:
        """Generate attribute-based key for user"""
        # Create a deterministic key based on attributes
        attr_string = "|".join(sorted(attributes))
        salt = hashlib.sha256(attr_string.encode()).digest()
        
        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        key = kdf.derive(master_private_key.encode()[:32])
        return base64.b64encode(key).decode()
    
    def evaluate_policy(self, policy_expression: str, user_attributes: List[str]) -> bool:
        """Evaluate if user attributes satisfy the policy"""
        try:
            # Convert attributes to set for faster lookup
            user_attr_set = set(user_attributes)
            
            # Replace attribute names with True/False based on user attributes
            expression = policy_expression
            
            # Convert to lowercase and replace operators
            expression = expression.replace(" AND ", " and ")
            expression = expression.replace(" OR ", " or ")
            expression = expression.replace(" NOT ", " not ")
            
            # Find all unique attributes in the policy
            import re
            policy_attrs = re.findall(r'\b[a-zA-Z_]\w*\b', expression)
            policy_attrs = [attr for attr in policy_attrs if attr.lower() not in ['and', 'or', 'not', 'true', 'false']]
            
            for attr in policy_attrs:
                has_attr = attr in user_attr_set
                expression = expression.replace(attr, str(has_attr))
            
            # Evaluate the boolean expression
            return eval(expression)
            
        except Exception as e:
            logger.error(f"Policy evaluation error: {e}")
            return False
    
    def encrypt_data(self, data: bytes, policy_id: str) -> Tuple[bytes, str]:
        """Encrypt data with symmetric key"""
        # Generate random symmetric key
        key = secrets.token_bytes(32)  # 256-bit key
        iv = secrets.token_bytes(16)   # 128-bit IV
        
        # Encrypt data using AES-GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Combine IV, tag, and ciphertext
        encrypted_data = iv + encryptor.tag + ciphertext
        
        # Return encrypted data and base64 encoded key
        return encrypted_data, base64.b64encode(key).decode()
    
    def decrypt_data(self, encrypted_data: bytes, key_b64: str) -> bytes:
        """Decrypt data with symmetric key"""
        key = base64.b64decode(key_b64)
        
        # Extract IV, tag, and ciphertext
        iv = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        # Decrypt using AES-GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

# ==============================================
# Main CP-ABE System
# ==============================================

class ProductionCPABE:
    """Production-ready CP-ABE system with comprehensive features"""
    
    def __init__(self, config_path: str = "cpabe_config.yaml"):
        self.config = self._load_config(config_path)
        self.crypto = CPABECrypto()
        self.data_dir = Path("cpabe_data")
        self.data_dir.mkdir(exist_ok=True)
        
        # Storage files
        self.authorities_file = self.data_dir / "authorities.json"
        self.users_file = self.data_dir / "users.json"
        self.policies_file = self.data_dir / "policies.json"
        self.files_file = self.data_dir / "files.json"
        self.audit_file = self.data_dir / "audit.log"
        
        # In-memory storage (loaded from files)
        self.authorities: Dict[str, AttributeAuthority] = {}
        self.user_keys: Dict[str, UserKey] = {}
        self.policies: Dict[str, AccessPolicy] = {}
        self.encrypted_files: Dict[str, EncryptedFile] = {}
        
        # Load existing data
        self._load_data()
        
        # Master keys
        self.master_public_key = None
        self.master_private_key = None
        self._initialize_master_keys()
    
    def _load_config(self, config_path: str) -> SystemConfig:
        """Load system configuration"""
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
                return SystemConfig(**config_data)
        else:
            # Create default config
            config = SystemConfig()
            with open(config_path, 'w') as f:
                yaml.dump(asdict(config), f, default_flow_style=False)
            return config
    
    def _load_data(self):
        """Load all data from storage files"""
        try:
            if self.authorities_file.exists():
                with open(self.authorities_file, 'r') as f:
                    data = json.load(f)
                    self.authorities = {k: AttributeAuthority(**v) for k, v in data.items()}
            
            if self.users_file.exists():
                with open(self.users_file, 'r') as f:
                    data = json.load(f)
                    self.user_keys = {k: UserKey(**v) for k, v in data.items()}
            
            if self.policies_file.exists():
                with open(self.policies_file, 'r') as f:
                    data = json.load(f)
                    self.policies = {k: AccessPolicy(**v) for k, v in data.items()}
            
            if self.files_file.exists():
                with open(self.files_file, 'r') as f:
                    data = json.load(f)
                    self.encrypted_files = {k: EncryptedFile(**v) for k, v in data.items()}
                    
        except Exception as e:
            logger.error(f"Error loading data: {e}")
    
    def _save_data(self):
        """Save all data to storage files"""
        try:
            with open(self.authorities_file, 'w') as f:
                json.dump({k: asdict(v) for k, v in self.authorities.items()}, f, indent=2)
            
            with open(self.users_file, 'w') as f:
                json.dump({k: asdict(v) for k, v in self.user_keys.items()}, f, indent=2)
            
            with open(self.policies_file, 'w') as f:
                json.dump({k: asdict(v) for k, v in self.policies.items()}, f, indent=2)
            
            with open(self.files_file, 'w') as f:
                json.dump({k: asdict(v) for k, v in self.encrypted_files.items()}, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving data: {e}")
            raise
    
    def _initialize_master_keys(self):
        """Initialize or load master keys"""
        master_keys_file = self.data_dir / "master_keys.json"
        
        if master_keys_file.exists():
            with open(master_keys_file, 'r') as f:
                keys = json.load(f)
                self.master_public_key = keys['public_key']
                self.master_private_key = keys['private_key']
        else:
            # Generate new master keys
            pub_key, priv_key = self.crypto.generate_master_keys()
            self.master_public_key = pub_key
            self.master_private_key = priv_key
            
            with open(master_keys_file, 'w') as f:
                json.dump({
                    'public_key': pub_key,
                    'private_key': priv_key,
                    'created_at': datetime.now().isoformat()
                }, f, indent=2)
    
    def _audit_log(self, action: str, user_id: str, details: Dict[str, Any]):
        """Log audit events"""
        if not self.config.audit_enabled:
            return
        
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'user_id': user_id,
            'details': details
        }
        
        with open(self.audit_file, 'a') as f:
            f.write(json.dumps(audit_entry) + '\n')
    
    # ==============================================
    # Authority Management
    # ==============================================
    
    def create_authority(self, authority_id: str, name: str, description: str, 
                        attributes: List[str], contact_info: Dict[str, str] = None) -> AttributeAuthority:
        """Create a new Attribute Authority"""
        if authority_id in self.authorities:
            raise ValueError(f"Authority '{authority_id}' already exists")
        
        # Generate authority keys
        pub_key, priv_key = self.crypto.generate_master_keys()
        
        authority = AttributeAuthority(
            authority_id=authority_id,
            name=name,
            description=description,
            attributes=attributes,
            public_key=pub_key,
            private_key=priv_key,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            contact_info=contact_info or {}
        )
        
        self.authorities[authority_id] = authority
        self._save_data()
        
        self._audit_log("CREATE_AUTHORITY", "system", {
            "authority_id": authority_id,
            "attributes": attributes
        })
        
        return authority
    
    def update_authority(self, authority_id: str, **kwargs) -> AttributeAuthority:
        """Update an existing authority"""
        if authority_id not in self.authorities:
            raise ValueError(f"Authority '{authority_id}' not found")
        
        authority = self.authorities[authority_id]
        
        for key, value in kwargs.items():
            if hasattr(authority, key):
                setattr(authority, key, value)
        
        authority.updated_at = datetime.now().isoformat()
        self._save_data()
        
        self._audit_log("UPDATE_AUTHORITY", "system", {
            "authority_id": authority_id,
            "changes": kwargs
        })
        
        return authority
    
    def list_authorities(self, status: str = None) -> List[AttributeAuthority]:
        """List all authorities with optional status filter"""
        authorities = list(self.authorities.values())
        if status:
            authorities = [a for a in authorities if a.status == status]
        return authorities
    
    def get_authority(self, authority_id: str) -> AttributeAuthority:
        """Get specific authority details"""
        if authority_id not in self.authorities:
            raise ValueError(f"Authority '{authority_id}' not found")
        return self.authorities[authority_id]
    
    # ==============================================
    # User Key Management
    # ==============================================
    
    def generate_user_key(self, user_id: str, authority_id: str, attributes: List[str],
                         expires_in_days: int = 365, metadata: Dict[str, Any] = None) -> UserKey:
        """Generate a user key with specified attributes"""
        if authority_id not in self.authorities:
            raise ValueError(f"Authority '{authority_id}' not found")
        
        authority = self.authorities[authority_id]
        
        # Validate attributes
        invalid_attrs = set(attributes) - set(authority.attributes)
        if invalid_attrs:
            raise ValueError(f"Invalid attributes for authority '{authority_id}': {invalid_attrs}")
        
        # Generate the key
        encrypted_key = self.crypto.generate_attribute_key(attributes, authority.private_key)
        key_hash = hashlib.sha256(encrypted_key.encode()).hexdigest()
        
        expires_at = (datetime.now() + timedelta(days=expires_in_days)).isoformat()
        
        user_key = UserKey(
            user_id=user_id,
            authority_id=authority_id,
            attributes=attributes,
            encrypted_key=encrypted_key,
            key_hash=key_hash,
            created_at=datetime.now().isoformat(),
            expires_at=expires_at,
            metadata=metadata or {}
        )
        
        self.user_keys[user_id] = user_key
        self._save_data()
        
        self._audit_log("GENERATE_USER_KEY", user_id, {
            "authority_id": authority_id,
            "attributes": attributes
        })
        
        return user_key
    
    def revoke_user_key(self, user_id: str, reason: str = "Not specified") -> bool:
        """Revoke a user's key"""
        if user_id not in self.user_keys:
            raise ValueError(f"User key for '{user_id}' not found")
        
        self.user_keys[user_id].revoked = True
        self._save_data()
        
        self._audit_log("REVOKE_USER_KEY", user_id, {"reason": reason})
        
        return True
    
    def list_user_keys(self, authority_id: str = None, status: str = None) -> List[UserKey]:
        """List user keys with optional filters"""
        keys = list(self.user_keys.values())
        
        if authority_id:
            keys = [k for k in keys if k.authority_id == authority_id]
        
        if status == "active":
            keys = [k for k in keys if not k.revoked and datetime.fromisoformat(k.expires_at) > datetime.now()]
        elif status == "expired":
            keys = [k for k in keys if datetime.fromisoformat(k.expires_at) <= datetime.now()]
        elif status == "revoked":
            keys = [k for k in keys if k.revoked]
        
        return keys
    
    # ==============================================
    # Policy Management
    # ==============================================
    
    def create_policy(self, policy_id: str, name: str, description: str, 
                     policy_expression: str, created_by: str) -> AccessPolicy:
        """Create a new access policy"""
        if policy_id in self.policies:
            raise ValueError(f"Policy '{policy_id}' already exists")
        
        # Validate policy expression (basic syntax check)
        try:
            # Test with dummy attributes
            test_attrs = ["attr1", "attr2", "attr3"]
            self.crypto.evaluate_policy(policy_expression, test_attrs)
        except Exception as e:
            raise ValueError(f"Invalid policy expression: {e}")
        
        policy = AccessPolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            policy_expression=policy_expression,
            created_by=created_by,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat()
        )
        
        self.policies[policy_id] = policy
        self._save_data()
        
        self._audit_log("CREATE_POLICY", created_by, {
            "policy_id": policy_id,
            "expression": policy_expression
        })
        
        return policy
    
    def update_policy(self, policy_id: str, **kwargs) -> AccessPolicy:
        """Update an existing policy"""
        if policy_id not in self.policies:
            raise ValueError(f"Policy '{policy_id}' not found")
        
        policy = self.policies[policy_id]
        old_version = policy.version
        
        for key, value in kwargs.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        
        policy.version = old_version + 1
        policy.updated_at = datetime.now().isoformat()
        self._save_data()
        
        self._audit_log("UPDATE_POLICY", "system", {
            "policy_id": policy_id,
            "changes": kwargs,
            "new_version": policy.version
        })
        
        return policy
    
    def list_policies(self, active_only: bool = True) -> List[AccessPolicy]:
        """List all policies"""
        policies = list(self.policies.values())
        if active_only:
            policies = [p for p in policies if p.active]
        return policies
    
    def get_policy(self, policy_id: str) -> AccessPolicy:
        """Get specific policy details"""
        if policy_id not in self.policies:
            raise ValueError(f"Policy '{policy_id}' not found")
        return self.policies[policy_id]
    
    # ==============================================
    # File Encryption/Decryption
    # ==============================================
    
    def encrypt_file(self, file_path: str, policy_id: str, encrypted_by: str,
                    output_path: str = None, chunk_size: int = None) -> EncryptedFile:
        """Encrypt a file with CP-ABE policy"""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File '{file_path}' not found")
        
        if policy_id not in self.policies:
            raise ValueError(f"Policy '{policy_id}' not found")
        
        # Check file size limit
        file_size = file_path.stat().st_size
        if file_size > self.config.max_file_size:
            raise ValueError(f"File size exceeds limit ({self.config.max_file_size} bytes)")
        
        chunk_size = chunk_size or self.config.chunk_size
        output_path = output_path or str(file_path) + ".cpabe"
        
        # Generate file ID and calculate hash
        file_id = hashlib.sha256(f"{file_path.name}{time.time()}".encode()).hexdigest()[:16]
        
        file_hash = hashlib.sha256()
        encrypted_chunks = []
        
        try:
            with open(file_path, 'rb') as infile:
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="Encrypting") as pbar:
                    while True:
                        chunk = infile.read(chunk_size)
                        if not chunk:
                            break
                        
                        file_hash.update(chunk)
                        encrypted_chunk, key = self.crypto.encrypt_data(chunk, policy_id)
                        encrypted_chunks.append((encrypted_chunk, key))
                        pbar.update(len(chunk))
            
            # Save encrypted file
            with open(output_path, 'wb') as outfile:
                # Write header
                header = {
                    'version': '2.0',
                    'policy_id': policy_id,
                    'chunk_count': len(encrypted_chunks),
                    'original_size': file_size
                }
                header_bytes = json.dumps(header).encode()
                outfile.write(struct.pack('!I', len(header_bytes)))
                outfile.write(header_bytes)
                
                # Write encrypted chunks
                for encrypted_chunk, key in encrypted_chunks:
                    outfile.write(struct.pack('!I', len(key)))
                    outfile.write(key.encode())
                    outfile.write(struct.pack('!I', len(encrypted_chunk)))
                    outfile.write(encrypted_chunk)
            
            # Create file metadata
            encrypted_file = EncryptedFile(
                file_id=file_id,
                original_name=file_path.name,
                policy_id=policy_id,
                encrypted_path=output_path,
                file_hash=file_hash.hexdigest(),
                file_size=file_size,
                encrypted_at=datetime.now().isoformat(),
                encrypted_by=encrypted_by
            )
            
            self.encrypted_files[file_id] = encrypted_file
            self._save_data()
            
            self._audit_log("ENCRYPT_FILE", encrypted_by, {
                "file_id": file_id,
                "original_name": file_path.name,
                "policy_id": policy_id,
                "file_size": file_size
            })
            
            return encrypted_file
            
        except Exception as e:
            # Cleanup on failure
            if os.path.exists(output_path):
                os.remove(output_path)
            raise
    
    def decrypt_file(self, file_id: str, user_id: str, output_path: str = None) -> Dict[str, Any]:
        """Decrypt a file if user has access"""
        if file_id not in self.encrypted_files:
            raise ValueError(f"Encrypted file '{file_id}' not found")
        
        if user_id not in self.user_keys:
            raise ValueError(f"User key for '{user_id}' not found")
        
        encrypted_file = self.encrypted_files[file_id]
        user_key = self.user_keys[user_id]
        policy = self.policies[encrypted_file.policy_id]
        
        # Check if user key is valid
        if user_key.revoked:
            raise PermissionError("User key has been revoked")
        
        if datetime.fromisoformat(user_key.expires_at) <= datetime.now():
            raise PermissionError("User key has expired")
        
        # Check if user attributes satisfy policy
        if not self.crypto.evaluate_policy(policy.policy_expression, user_key.attributes):
            raise PermissionError("User attributes do not satisfy the access policy")
        
        # Decrypt the file
        encrypted_path = encrypted_file.encrypted_path
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError(f"Encrypted file not found: {encrypted_path}")
        
        output_path = output_path or f"decrypted_{encrypted_file.original_name}"
        
        try:
            with open(encrypted_path, 'rb') as infile:
                # Read header
                header_size = struct.unpack('!I', infile.read(4))[0]
                header_bytes = infile.read(header_size)
                header = json.loads(header_bytes.decode())
                
                decrypted_data = b""
                
                with tqdm(total=header['chunk_count'], desc="Decrypting") as pbar:
                    for _ in range(header['chunk_count']):
                        # Read key
                        key_size = struct.unpack('!I', infile.read(4))[0]
                        key = infile.read(key_size).decode()
                        
                        # Read encrypted chunk
                        chunk_size = struct.unpack('!I', infile.read(4))[0]
                        encrypted_chunk = infile.read(chunk_size)
                        
                        # Decrypt chunk
                        decrypted_chunk = self.crypto.decrypt_data(encrypted_chunk, key)
                        decrypted_data += decrypted_chunk
                        pbar.update(1)
            
            # Write decrypted file
            os.makedirs(os.path.dirname(output_path), exist_ok=True) if os.path.dirname(output_path) else None
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
            
            # Update access count
            encrypted_file.access_count += 1
            encrypted_file.last_accessed = datetime.now().isoformat()
            self._save_data()
            
            self._audit_log("DECRYPT_FILE", user_id, {
                "file_id": file_id,
                "original_name": encrypted_file.original_name,
                "output_path": output_path
            })
            
            return {
                "status": "success",
                "file_id": file_id,
                "decrypted_path": output_path,
                "original_name": encrypted_file.original_name
            }
            
        except Exception as e:
            self._audit_log("DECRYPT_FILE_FAILED", user_id, {
                "file_id": file_id,
                "error": str(e)
            })
            raise
    
    def list_encrypted_files(self, encrypted_by: str = None) -> List[EncryptedFile]:
        """List encrypted files with optional filter"""
        files = list(self.encrypted_files.values())
        if encrypted_by:
            files = [f for f in files if f.encrypted_by == encrypted_by]
        return files
    
    def get_file_info(self, file_id: str) -> EncryptedFile:
        """Get encrypted file information"""
        if file_id not in self.encrypted_files:
            raise ValueError(f"Encrypted file '{file_id}' not found")
        return self.encrypted_files[file_id]
    
    # ==============================================
    # System Management
    # ==============================================
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status and statistics"""
        return {
            "authorities": len(self.authorities),
            "active_authorities": len([a for a in self.authorities.values() if a.status == "active"]),
            "users": len(self.user_keys),
            "active_users": len([u for u in self.user_keys.values() if not u.revoked]),
            "policies": len(self.policies),
            "active_policies": len([p for p in self.policies.values() if p.active]),
            "encrypted_files": len(self.encrypted_files),
            "total_file_size": sum(f.file_size for f in self.encrypted_files.values()),
            "config": asdict(self.config)
        }
    
    def backup_system(self, backup_path: str = None) -> str:
        """Create system backup"""
        backup_path = backup_path or f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
        
        import tarfile
        
        with tarfile.open(backup_path, 'w:gz') as tar:
            tar.add(self.data_dir, arcname='cpabe_data')
        
        logger.info(f"System backup created: {backup_path}")
        return backup_path
    
    def restore_system(self, backup_path: str):
        """Restore system from backup"""
        import tarfile
        import shutil
        
        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
        
        # Backup current data
        current_backup = self.backup_system(f"pre_restore_backup_{int(time.time())}.tar.gz")
        
        try:
            # Remove current data
            if self.data_dir.exists():
                shutil.rmtree(self.data_dir)
            
            # Extract backup
            with tarfile.open(backup_path, 'r:gz') as tar:
                tar.extractall()
            
            # Reload data
            self._load_data()
            self._initialize_master_keys()
            
            logger.info(f"System restored from: {backup_path}")
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            # Attempt to restore from current backup
            try:
                with tarfile.open(current_backup, 'r:gz') as tar:
                    tar.extractall()
                self._load_data()
            except:
                pass
            raise

# ==============================================
# CLI Interface with Click
# ==============================================

# Global CPABE instance
cpabe = None

def get_cpabe():
    """Get or initialize CPABE instance"""
    global cpabe
    if cpabe is None:
        cpabe = ProductionCPABE()
    return cpabe

@click.group()
@click.option('--config', default='cpabe_config.yaml', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def cli(config, verbose):
    """Production-Ready CP-ABE SDK - Secure Attribute-Based Encryption System"""
    global cpabe
    
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        cpabe = ProductionCPABE(config)
        click.secho("✅ CP-ABE system initialized successfully!", fg="green")
    except Exception as e:
        click.secho(f"❌ Failed to initialize system: {e}", fg="red")
        raise click.Abort()

# ==============================================
# Authority Management Commands
# ==============================================

@cli.group()
def authority():
    """Manage Attribute Authorities"""
    pass

@authority.command('create')
@click.argument('authority_id')
@click.option('--name', required=True, help='Authority display name')
@click.option('--description', default='', help='Authority description')
@click.option('--attributes', required=True, help='Comma-separated list of attributes')
@click.option('--contact-email', help='Contact email address')
@click.option('--contact-phone', help='Contact phone number')
@click.option('--contact-org', help='Contact organization')
def create_authority(authority_id, name, description, attributes, contact_email, contact_phone, contact_org):
    """Create a new Attribute Authority"""
    try:
        attrs = [attr.strip() for attr in attributes.split(',')]
        contact_info = {}
        if contact_email:
            contact_info['email'] = contact_email
        if contact_phone:
            contact_info['phone'] = contact_phone
        if contact_org:
            contact_info['organization'] = contact_org
        
        authority = get_cpabe().create_authority(
            authority_id=authority_id,
            name=name,
            description=description,
            attributes=attrs,
            contact_info=contact_info
        )
        
        click.secho(f"✅ Authority '{authority_id}' created successfully!", fg="green")
        click.echo(f"Name: {authority.name}")
        click.echo(f"Attributes: {', '.join(authority.attributes)}")
        click.echo(f"Created: {authority.created_at}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@authority.command('list')
@click.option('--status', type=click.Choice(['active', 'inactive']), help='Filter by status')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table', help='Output format')
def list_authorities(status, output_format):
    """List all Attribute Authorities"""
    try:
        authorities = get_cpabe().list_authorities(status=status)
        
        if output_format == 'json':
            click.echo(json.dumps([asdict(auth) for auth in authorities], indent=2))
        else:
            if not authorities:
                click.echo("No authorities found.")
                return
            
            click.echo("\n📋 Attribute Authorities:")
            click.echo("=" * 80)
            for auth in authorities:
                click.echo(f"ID: {auth.authority_id}")
                click.echo(f"Name: {auth.name}")
                click.echo(f"Status: {auth.status}")
                click.echo(f"Attributes: {', '.join(auth.attributes)}")
                click.echo(f"Created: {auth.created_at}")
                click.echo("-" * 40)
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@authority.command('update')
@click.argument('authority_id')
@click.option('--name', help='Update authority name')
@click.option('--description', help='Update description')
@click.option('--status', type=click.Choice(['active', 'inactive']), help='Update status')
@click.option('--add-attributes', help='Comma-separated attributes to add')
@click.option('--remove-attributes', help='Comma-separated attributes to remove')
def update_authority(authority_id, name, description, status, add_attributes, remove_attributes):
    try:
        updates = {}
        if name:
            updates['name'] = name
        if description:
            updates['description'] = description
        if status:
            updates['status'] = status
        
        # Handle attribute updates
        if add_attributes or remove_attributes:
            authority = get_cpabe().get_authority(authority_id)
            current_attrs = set(authority.attributes)
            
            if add_attributes:
                new_attrs = {attr.strip() for attr in add_attributes.split(',')}
                current_attrs.update(new_attrs)
            
            if remove_attributes:
                remove_attrs = {attr.strip() for attr in remove_attributes.split(',')}
                current_attrs -= remove_attrs
            
            updates['attributes'] = list(current_attrs)
        
        authority = get_cpabe().update_authority(authority_id, **updates)
        
        click.secho(f"✅ Authority '{authority_id}' updated successfully!", fg="green")
        click.echo(f"Name: {authority.name}")
        click.echo(f"Status: {authority.status}")
        click.echo(f"Attributes: {', '.join(authority.attributes)}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@authority.command('info')
@click.argument('authority_id')
@click.option('--format', 'output_format', type=click.Choice(['detailed', 'json']), default='detailed')
def authority_info(authority_id, output_format):
    """Get detailed information about an Authority"""
    try:
        authority = get_cpabe().get_authority(authority_id)
        
        if output_format == 'json':
            click.echo(json.dumps(asdict(authority), indent=2))
        else:
            click.echo(f"\n🏢 Authority Details: {authority_id}")
            click.echo("=" * 50)
            click.echo(f"Name: {authority.name}")
            click.echo(f"Description: {authority.description}")
            click.echo(f"Status: {authority.status}")
            click.echo(f"Attributes: {', '.join(authority.attributes)}")
            click.echo(f"Created: {authority.created_at}")
            click.echo(f"Updated: {authority.updated_at}")
            if authority.contact_info:
                click.echo("Contact Info:")
                for key, value in authority.contact_info.items():
                    click.echo(f"  {key.title()}: {value}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

# ==============================================
# User Key Management Commands
# ==============================================

@cli.group()
def user():
    """Manage User Keys and Attributes"""
    pass

@user.command('create-key')
@click.argument('user_id')
@click.argument('authority_id')
@click.option('--attributes', required=True, help='Comma-separated user attributes')
@click.option('--expires-days', default=365, help='Key expiration in days')
@click.option('--email', help='User email address')
@click.option('--department', help='User department')
@click.option('--role', help='User role')
def create_user_key(user_id, authority_id, attributes, expires_days, email, department, role):
    """Generate a user key with specified attributes"""
    try:
        attrs = [attr.strip() for attr in attributes.split(',')]
        metadata = {}
        if email:
            metadata['email'] = email
        if department:
            metadata['department'] = department
        if role:
            metadata['role'] = role
        
        user_key = get_cpabe().generate_user_key(
            user_id=user_id,
            authority_id=authority_id,
            attributes=attrs,
            expires_in_days=expires_days,
            metadata=metadata
        )
        
        click.secho(f"✅ User key for '{user_id}' created successfully!", fg="green")
        click.echo(f"Authority: {user_key.authority_id}")
        click.echo(f"Attributes: {', '.join(user_key.attributes)}")
        click.echo(f"Expires: {user_key.expires_at}")
        click.echo(f"Key Hash: {user_key.key_hash[:16]}...")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@user.command('list')
@click.option('--authority', help='Filter by authority ID')
@click.option('--status', type=click.Choice(['active', 'expired', 'revoked', 'all']), default='active')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table')
def list_users(authority, status, output_format):
    """List user keys with optional filters"""
    try:
        user_keys = get_cpabe().list_user_keys(authority_id=authority, status=status)
        
        if output_format == 'json':
            click.echo(json.dumps([asdict(key) for key in user_keys], indent=2))
        else:
            if not user_keys:
                click.echo("No user keys found.")
                return
            
            click.echo(f"\n👥 User Keys ({status}):")
            click.echo("=" * 80)
            for key in user_keys:
                status_icon = "🔓" if not key.revoked and datetime.fromisoformat(key.expires_at) > datetime.now() else "🔒"
                click.echo(f"{status_icon} User: {key.user_id}")
                click.echo(f"   Authority: {key.authority_id}")
                click.echo(f"   Attributes: {', '.join(key.attributes)}")
                click.echo(f"   Created: {key.created_at}")
                click.echo(f"   Expires: {key.expires_at}")
                if key.revoked:
                    click.echo(f"   Status: REVOKED")
                click.echo("-" * 40)
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@user.command('revoke')
@click.argument('user_id')
@click.option('--reason', default='Not specified', help='Reason for revocation')
@click.confirmation_option(prompt='Are you sure you want to revoke this user key?')
def revoke_user(user_id, reason):
    """Revoke a user's key"""
    try:
        get_cpabe().revoke_user_key(user_id, reason)
        click.secho(f"✅ User key for '{user_id}' revoked successfully!", fg="yellow")
        click.echo(f"Reason: {reason}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@user.command('info')
@click.argument('user_id')
def user_info(user_id):
    """Get detailed user information"""
    try:
        if user_id not in get_cpabe().user_keys:
            raise ValueError(f"User '{user_id}' not found")
        
        user_key = get_cpabe().user_keys[user_id]
        
        click.echo(f"\n👤 User Details: {user_id}")
        click.echo("=" * 50)
        click.echo(f"Authority: {user_key.authority_id}")
        click.echo(f"Attributes: {', '.join(user_key.attributes)}")
        click.echo(f"Created: {user_key.created_at}")
        click.echo(f"Expires: {user_key.expires_at}")
        click.echo(f"Revoked: {'Yes' if user_key.revoked else 'No'}")
        click.echo(f"Key Hash: {user_key.key_hash}")
        
        if user_key.metadata:
            click.echo("Metadata:")
            for key, value in user_key.metadata.items():
                click.echo(f"  {key.title()}: {value}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

# ==============================================
# Policy Management Commands
# ==============================================

@cli.group()
def policy():
    """Manage Access Policies"""
    pass

@policy.command('create')
@click.argument('policy_id')
@click.option('--name', required=True, help='Policy display name')
@click.option('--description', default='', help='Policy description')
@click.option('--expression', required=True, help='Policy expression (e.g., "manager AND finance")')
@click.option('--created-by', required=True, help='Policy creator')
def create_policy(policy_id, name, description, expression, created_by):
    """Create a new access policy"""
    try:
        policy = get_cpabe().create_policy(
            policy_id=policy_id,
            name=name,
            description=description,
            policy_expression=expression,
            created_by=created_by
        )
        
        click.secho(f"✅ Policy '{policy_id}' created successfully!", fg="green")
        click.echo(f"Name: {policy.name}")
        click.echo(f"Expression: {policy.policy_expression}")
        click.echo(f"Created by: {policy.created_by}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@policy.command('list')
@click.option('--active-only', is_flag=True, default=True, help='Show only active policies')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table')
def list_policies(active_only, output_format):
    """List all access policies"""
    try:
        policies = get_cpabe().list_policies(active_only=active_only)
        
        if output_format == 'json':
            click.echo(json.dumps([asdict(policy) for policy in policies], indent=2))
        else:
            if not policies:
                click.echo("No policies found.")
                return
            
            click.echo("\n📜 Access Policies:")
            click.echo("=" * 80)
            for policy in policies:
                status_icon = "✅" if policy.active else "❌"
                click.echo(f"{status_icon} Policy: {policy.policy_id}")
                click.echo(f"   Name: {policy.name}")
                click.echo(f"   Expression: {policy.policy_expression}")
                click.echo(f"   Created by: {policy.created_by}")
                click.echo(f"   Version: {policy.version}")
                click.echo(f"   Created: {policy.created_at}")
                click.echo("-" * 40)
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@policy.command('test')
@click.argument('policy_id')
@click.option('--attributes', required=True, help='Comma-separated attributes to test')
def test_policy(policy_id, attributes):
    """Test if attributes satisfy a policy"""
    try:
        policy = get_cpabe().get_policy(policy_id)
        attrs = [attr.strip() for attr in attributes.split(',')]
        
        result = get_cpabe().crypto.evaluate_policy(policy.policy_expression, attrs)
        
        if result:
            click.secho(f"✅ Attributes SATISFY the policy '{policy_id}'", fg="green")
        else:
            click.secho(f"❌ Attributes DO NOT satisfy the policy '{policy_id}'", fg="red")
        
        click.echo(f"Policy Expression: {policy.policy_expression}")
        click.echo(f"Test Attributes: {', '.join(attrs)}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@policy.command('update')
@click.argument('policy_id')
@click.option('--name', help='Update policy name')
@click.option('--description', help='Update description')
@click.option('--expression', help='Update policy expression')
@click.option('--active', type=bool, help='Update active status')
def update_policy(policy_id, name, description, expression, active):
    """Update an existing policy"""
    try:
        updates = {}
        if name:
            updates['name'] = name
        if description:
            updates['description'] = description
        if expression:
            updates['policy_expression'] = expression
        if active is not None:
            updates['active'] = active
        
        policy = get_cpabe().update_policy(policy_id, **updates)
        
        click.secho(f"✅ Policy '{policy_id}' updated successfully!", fg="green")
        click.echo(f"New version: {policy.version}")
        click.echo(f"Updated: {policy.updated_at}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

# ==============================================
# File Encryption/Decryption Commands
# ==============================================

@cli.group()
def file():
    """Encrypt and decrypt files"""
    pass

@file.command('encrypt')
@click.argument('file_path')
@click.option('--policy-id', required=True, help='Policy ID for access control')
@click.option('--encrypted-by', required=True, help='User ID who is encrypting')
@click.option('--output', help='Output path for encrypted file')
@click.option('--chunk-size', default=8192, help='Encryption chunk size')
def encrypt_file(file_path, policy_id, encrypted_by, output, chunk_size):
    """Encrypt a file with CP-ABE policy"""
    try:
        encrypted_file = get_cpabe().encrypt_file(
            file_path=file_path,
            policy_id=policy_id,
            encrypted_by=encrypted_by,
            output_path=output,
            chunk_size=chunk_size
        )
        
        click.secho(f"✅ File encrypted successfully!", fg="green")
        click.echo(f"File ID: {encrypted_file.file_id}")
        click.echo(f"Original: {encrypted_file.original_name}")
        click.echo(f"Encrypted: {encrypted_file.encrypted_path}")
        click.echo(f"Policy: {encrypted_file.policy_id}")
        click.echo(f"Size: {encrypted_file.file_size:,} bytes")
        click.echo(f"Hash: {encrypted_file.file_hash}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@file.command('decrypt')
@click.argument('file_id')
@click.argument('user_id')
@click.option('--output', help='Output path for decrypted file')
def decrypt_file(file_id, user_id, output):
    """Decrypt a file if user has access"""
    try:
        result = get_cpabe().decrypt_file(
            file_id=file_id,
            user_id=user_id,
            output_path=output
        )
        
        click.secho(f"✅ File decrypted successfully!", fg="green")
        click.echo(f"File ID: {result['file_id']}")
        click.echo(f"Original: {result['original_name']}")
        click.echo(f"Decrypted: {result['decrypted_path']}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@file.command('list')
@click.option('--encrypted-by', help='Filter by user who encrypted')
@click.option('--format', 'output_format', type=click.Choice(['table', 'json']), default='table')
def list_files(encrypted_by, output_format):
    """List encrypted files"""
    try:
        files = get_cpabe().list_encrypted_files(encrypted_by=encrypted_by)
        
        if output_format == 'json':
            click.echo(json.dumps([asdict(f) for f in files], indent=2))
        else:
            if not files:
                click.echo("No encrypted files found.")
                return
            
            click.echo("\n📁 Encrypted Files:")
            click.echo("=" * 80)
            total_size = 0
            for file in files:
                click.echo(f"📄 File: {file.original_name}")
                click.echo(f"   ID: {file.file_id}")
                click.echo(f"   Policy: {file.policy_id}")
                click.echo(f"   Size: {file.file_size:,} bytes")
                click.echo(f"   Encrypted by: {file.encrypted_by}")
                click.echo(f"   Encrypted: {file.encrypted_at}")
                click.echo(f"   Access count: {file.access_count}")
                if file.last_accessed:
                    click.echo(f"   Last accessed: {file.last_accessed}")
                click.echo("-" * 40)
                total_size += file.file_size
            
            click.echo(f"\nTotal files: {len(files)}")
            click.echo(f"Total size: {total_size:,} bytes")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@file.command('info')
@click.argument('file_id')
def file_info(file_id):
    """Get detailed file information"""
    try:
        file = get_cpabe().get_file_info(file_id)
        policy = get_cpabe().get_policy(file.policy_id)
        
        click.echo(f"\n📄 File Details: {file.original_name}")
        click.echo("=" * 50)
        click.echo(f"File ID: {file.file_id}")
        click.echo(f"Original Name: {file.original_name}")
        click.echo(f"Encrypted Path: {file.encrypted_path}")
        click.echo(f"File Size: {file.file_size:,} bytes")
        click.echo(f"File Hash: {file.file_hash}")
        click.echo(f"Encrypted by: {file.encrypted_by}")
        click.echo(f"Encrypted: {file.encrypted_at}")
        click.echo(f"Access Count: {file.access_count}")
        if file.last_accessed:
            click.echo(f"Last Accessed: {file.last_accessed}")
        
        click.echo(f"\n📜 Access Policy:")
        click.echo(f"Policy ID: {policy.policy_id}")
        click.echo(f"Policy Name: {policy.name}")
        click.echo(f"Expression: {policy.policy_expression}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

# ==============================================
# System Management Commands
# ==============================================

@cli.group()
def system():
    """System management and utilities"""
    pass

@system.command('status')
def system_status():
    """Get system status and statistics"""
    try:
        status = get_cpabe().get_system_status()
        
        click.echo("\n🔧 System Status:")
        click.echo("=" * 50)
        click.echo(f"Authorities: {status['authorities']} (Active: {status['active_authorities']})")
        click.echo(f"Users: {status['users']} (Active: {status['active_users']})")
        click.echo(f"Policies: {status['policies']} (Active: {status['active_policies']})")
        click.echo(f"Encrypted Files: {status['encrypted_files']}")
        click.echo(f"Total File Size: {status['total_file_size']:,} bytes")
        
        click.echo(f"\n⚙️ Configuration:")
        for key, value in status['config'].items():
            click.echo(f"  {key}: {value}")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@system.command('backup')
@click.option('--output', help='Backup file path')
def backup_system(output):
    """Create system backup"""
    try:
        backup_path = get_cpabe().backup_system(output)
        click.secho(f"✅ System backup created: {backup_path}", fg="green")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@system.command('restore')
@click.argument('backup_path')
@click.confirmation_option(prompt='Are you sure you want to restore from backup? This will overwrite current data.')
def restore_system(backup_path):
    """Restore system from backup"""
    try:
        get_cpabe().restore_system(backup_path)
        click.secho(f"✅ System restored from: {backup_path}", fg="green")
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

@system.command('audit')
@click.option('--lines', default=50, help='Number of recent audit lines to show')
@click.option('--user', help='Filter by user ID')
@click.option('--action', help='Filter by action type')
def show_audit(lines, user, action):
    """Show audit log"""
    try:
        audit_file = get_cpabe().audit_file
        if not audit_file.exists():
            click.echo("No audit log found.")
            return
        
        click.echo(f"\n📊 Audit Log (Last {lines} entries):")
        click.echo("=" * 80)
        
        with open(audit_file, 'r') as f:
            log_lines = f.readlines()
        
        # Filter and show recent entries
        filtered_lines = []
        for line in reversed(log_lines[-lines:]):
            try:
                entry = json.loads(line.strip())
                if user and entry['user_id'] != user:
                    continue
                if action and entry['action'] != action:
                    continue
                filtered_lines.append(entry)
            except:
                continue
        
        for entry in filtered_lines:
            click.echo(f"⏰ {entry['timestamp']}")
            click.echo(f"👤 User: {entry['user_id']}")
            click.echo(f"🔄 Action: {entry['action']}")
            click.echo(f"📝 Details: {entry['details']}")
            click.echo("-" * 40)
        
    except Exception as e:
        click.secho(f"❌ Error: {e}", fg="red")

# ==============================================
# Main Entry Point
# ==============================================

if __name__ == '__main__':
    cli()
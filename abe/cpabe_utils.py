from cryptography.fernet import Fernet
import os
import base64
import pickle
import re
import random
import struct


class SimpleABE:
    def __init__(self):
        self.key_store = {}
        self.policy_store = {}
        os.makedirs('abe/keys', exist_ok=True)
        os.makedirs('decrypted', exist_ok=True)
        self._load_metadata()

    def setup(self):
        """Initialize the encryption system"""
        return True
    
    def _add_noise(self, data, noise_blocks=3):
        """Insert noise blocks randomly into the data"""
        original_len = len(data)
        positions = sorted(random.sample(range(noise_blocks + 1), noise_blocks))
        blocks = []
        cursor = 0

        for i in range(noise_blocks + 1):
            end = cursor + original_len // (noise_blocks + 1)
            real_block = data[cursor:end]
            cursor = end

            noise = os.urandom(len(real_block))  # random noise block
            if i in positions:
                blocks.append(noise + real_block)
            else:
                blocks.append(real_block + noise)

        noisy_data = b''.join(blocks)

        # Pack header: total_blocks + indices of real blocks
        header = struct.pack("B" + "B" * len(positions), len(blocks), *positions)
        return header + noisy_data

    def _remove_noise(self, noisy_data):
        """Remove noise blocks using header"""
        total_blocks = noisy_data[0]
        positions = list(noisy_data[1:1 + total_blocks - 1])
        body = noisy_data[1 + total_blocks - 1:]
        block_len = len(body) // total_blocks
        clean_data = b''

        for i in range(total_blocks):
            block = body[i * block_len: (i + 1) * block_len]
            if i in positions:
                clean_data += block[len(block) // 2:]
            else:
                clean_data += block[:len(block) // 2]
        return clean_data

    def encrypt_file(self, file_path, policy):
        """Encrypt a file with a Boolean attribute-based policy string"""
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)

        with open(file_path, 'rb') as f:
            file_data = f.read()

        encrypted_data = cipher_suite.encrypt(file_data)

        file_id = os.path.basename(file_path)
        self.key_store[file_id] = key
        self.policy_store[file_id] = policy

        encrypted_file_path = f"{file_path}.enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_data)

        self._save_metadata()
        return encrypted_file_path

    def decrypt_file(self, encrypted_file_path, user_attributes):
        """Decrypt file if user satisfies the Boolean attribute policy"""
        file_id = os.path.basename(encrypted_file_path).replace('.enc', '')

        if file_id not in self.key_store:
            raise Exception("File not found in key store")

        policy = self.policy_store[file_id]
        if not self._evaluate_policy(policy, user_attributes):
            raise Exception("User does not have required attributes for decryption")

        key = self.key_store[file_id]
        cipher_suite = Fernet(key)

        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = cipher_suite.decrypt(encrypted_data)

        decrypted_file_path = os.path.join('decrypted', file_id)
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)

        return decrypted_file_path

    def _evaluate_policy(self, policy_str, user_attributes):
        """Evaluate Boolean attribute policy"""
        def repl(match):
            attr = match.group(0)
            return str(attr in user_attributes)

        expr = re.sub(r'\b\w+\b', repl, policy_str)
        expr = expr.replace("AND", "and").replace("OR", "or")

        try:
            return eval(expr)
        except Exception as e:
            raise Exception(f"Invalid policy format: {policy_str}") from e

    def _save_metadata(self):
        metadata = {
            'key_store': {k: base64.b64encode(v).decode() for k, v in self.key_store.items()},
            'policy_store': self.policy_store
        }
        with open('abe/keys/metadata.pickle', 'wb') as f:
            pickle.dump(metadata, f)

    def _load_metadata(self):
        try:
            with open('abe/keys/metadata.pickle', 'rb') as f:
                metadata = pickle.load(f)
                self.key_store = {k: base64.b64decode(v) for k, v in metadata['key_store'].items()}
                self.policy_store = metadata['policy_store']
        except FileNotFoundError:
            pass

# Global instance
abe = SimpleABE()

def setup():
    return abe.setup()

def encrypt_file(file_path, policy):
    return abe.encrypt_file(file_path, policy)

def decrypt_file(encrypted_file_path, user_attributes):
    return abe.decrypt_file(encrypted_file_path, user_attributes)

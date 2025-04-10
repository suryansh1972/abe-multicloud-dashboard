from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject
import os
import pickle

group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)

def setup():
    """Initialize CP-ABE system and generate master key and public parameters"""
    (pk, msk) = cpabe.setup()
    
    # Save public key and master secret key
    os.makedirs('abe/keys', exist_ok=True)
    with open('abe/keys/pk.pickle', 'wb') as f:
        pickle.dump(pk, f)
    with open('abe/keys/msk.pickle', 'wb') as f:
        pickle.dump(msk, f)
    
    return pk, msk

def load_keys():
    """Load public key and master secret key from files"""
    with open('abe/keys/pk.pickle', 'rb') as f:
        pk = pickle.load(f)
    with open('abe/keys/msk.pickle', 'rb') as f:
        msk = pickle.load(f)
    return pk, msk

def keygen(attributes):
    """Generate a secret key for a set of attributes"""
    pk, msk = load_keys()
    sk = cpabe.keygen(pk, msk, attributes)
    return sk

def encrypt_file(file_path, policy):
    """Encrypt a file using CP-ABE with the given policy"""
    pk, _ = load_keys()
    
    # Read file content
    with open(file_path, 'rb') as f:
        file_content = f.read()
    
    # Convert policy to string if it's a list
    if isinstance(policy, list):
        policy = ' and '.join(policy)
    
    # Encrypt the file
    ciphertext = cpabe.encrypt(pk, file_content, policy)
    
    # Save encrypted file
    encrypted_file_path = f"{file_path}.enc"
    with open(encrypted_file_path, 'wb') as f:
        pickle.dump(ciphertext, f)
    
    return encrypted_file_path

def decrypt_file(encrypted_file_path, attributes):
    """Decrypt a file using CP-ABE with the given attributes"""
    # Load encrypted file
    with open(encrypted_file_path, 'rb') as f:
        ciphertext = pickle.load(f)
    
    # Generate secret key for attributes
    sk = keygen(attributes)
    
    # Decrypt the file
    try:
        decrypted_content = cpabe.decrypt(ciphertext, sk)
        
        # Save decrypted file
        decrypted_file_path = os.path.join('decrypted', os.path.basename(encrypted_file_path).replace('.enc', ''))
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_content)
        
        return decrypted_file_path
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

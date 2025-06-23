import os
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from dotenv import load_dotenv
from cryptography.hazmat.primitives import hashes, serialization


load_dotenv()

def decrypt_with_private_key(encrypted_data):
    """
    Decrypts data that was encrypted with PHP's openssl_public_encrypt using OPENSSL_PKCS1_OAEP_PADDING
    """
    try:
        # Get and validate private key
        private_key_pem = os.getenv("PRIVATE_KEY")
        if not private_key_pem:
            raise ValueError("Private key not found in environment variables")
            
        # Clean the private key - ensure proper formatting
        private_key_pem = private_key_pem.strip()
        if not private_key_pem.startswith('-----BEGIN PRIVATE KEY-----'):
            raise ValueError("Invalid private key format")
            
        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        
        # Clean and decode the encrypted data
        encrypted_data = encrypted_data.strip()
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Decrypt using OAEP padding with SHA-1 (to match PHP's default)
        decrypted_data = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),  # Changed to SHA1 to match PHP
                algorithm=hashes.SHA1(),                    # Changed to SHA1 to match PHP
                label=None
            )
        )
        
        return decrypted_data.decode('utf-8')
        
    except Exception as e:
        print(f"Decryption error details: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")
    
    
def encrypt_with_public_key(data):
    """
    Encrypts the given data using the public key stored in environment variables.
    Returns the encrypted data as a Base64-encoded string.
    """
    public_key_pem = os.getenv("PUBLIC_KEY")
    if not public_key_pem:
        raise ValueError("Public key not found in environment variables.")
    
    # Load the public key
    public_key = load_pem_public_key(public_key_pem.encode())
    
    # Encrypt the data
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),  # Changed to SHA1 to match PHP
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )
    # Encode encrypted data to Base64
    return base64.b64encode(encrypted_data).decode()

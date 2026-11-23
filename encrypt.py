import os
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key_from_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derive a Fernet key from the provided password using PBKDF2.
    
    Args:
        password: The custom password to derive the key from.
        salt: Optional salt; if None, a random salt is generated.
    
    Returns:
        Tuple of (derived_key, salt).
    """
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet key length
        salt=salt,
        iterations=100000,  # High iteration count for security
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key, salt

def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """
    Encrypt a file using the provided password and save the encrypted content (with salt) to output.
    
    Args:
        input_path: Path to the file to encrypt.
        output_path: Path to save the encrypted file.
        password: Custom password for encryption.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file '{input_path}' does not exist.")
    
    key, salt = derive_key_from_password(password)
    fernet = Fernet(key)
    
    with open(input_path, 'rb') as infile:
        plaintext = infile.read()
    
    encrypted_data = fernet.encrypt(plaintext)
    
    # Save salt followed by encrypted data for future decryption
    with open(output_path, 'wb') as outfile:
        outfile.write(salt + encrypted_data)
    
    print(f"Successfully encrypted '{input_path}' to '{output_path}' using password-derived key.")

def main() -> None:
    if len(sys.argv) != 4:
        print("Usage: python encrypt.py <input_file> <output_file> <password>")
        print("Example: python encrypt.py secret.txt encrypted_secret.bin mypassword")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    password = sys.argv[3]
    
    try:
        encrypt_file(input_file, output_file, password)
    except Exception as e:
        print(f"Encryption failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

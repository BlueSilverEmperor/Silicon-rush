import os
import sys
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(password, salt=None):
    """Derive a Fernet-compatible key from a password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_file(input_file, output_file, password):
    """Encrypt the input file using a password-derived key and save to output file."""
    key, salt = derive_key(password)
    fernet = Fernet(key)
    with open(input_file, 'rb') as f:
        data = f.read()
    encrypted = fernet.encrypt(data)
    # Prepend salt to encrypted data for decryption
    with open(output_file, 'wb') as f:
        f.write(salt + encrypted)
    print(f"File {input_file} encrypted successfully to {output_file}")

def main():
    if len(sys.argv) < 4:
        print("Usage: python encrypt.py <input_file> <output_file> <password>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    password = sys.argv[3]

    if not os.path.exists(input_file):
        print(f"Input file {input_file} does not exist.")
        sys.exit(1)

    encrypt_file(input_file, output_file, password)

if __name__ == "__main__":
    main()

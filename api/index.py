import os
import json
import base64
from http.server import BaseHTTPRequestHandler
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_SIZE = 32
DEFAULT_ITERATIONS = 100_000

def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_bytes(plaintext: bytes, password: str, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt, iterations)
    iv = os.urandom(BLOCK_SIZE)

    # PKCS7 padding
    pad_len = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    if pad_len == 0:
        pad_len = BLOCK_SIZE
    padded = plaintext + bytes([pad_len]) * pad_len

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return salt + iv + ciphertext

def decrypt_bytes(data: bytes, password: str, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    if len(data) < SALT_SIZE + BLOCK_SIZE + 1:
        raise ValueError("Data too short or corrupted.")

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
    ciphertext = data[SALT_SIZE + BLOCK_SIZE:]

    key = derive_key(password, salt, iterations)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    if not padded:
        raise ValueError("Decrypted buffer is empty.")

    pad_len = padded[-1]
    if not (1 <= pad_len <= BLOCK_SIZE):
        raise ValueError("Invalid padding: incorrect password or corrupted payload.")

    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Bad padding: incorrect password or corrupted payload.")

    return padded[:-pad_len]

class handler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self._send_cors_headers()
        self.end_headers()

        payload = {
            "status": "ok",
            "app": "AXION Security API",
            "version": "1.0.0",
            "cipher": "AES-256-CBC",
            "kdf": "PBKDF2-SHA256",
            "iterations": DEFAULT_ITERATIONS,
            "compatible_extension": ".docenc",
            "endpoints": [
                {"path": "/api/health", "method": "GET"},
                {"path": "/api/encrypt", "method": "POST", "body": {"data_base64": "...", "password": "..."}},
                {"path": "/api/decrypt", "method": "POST", "body": {"data_base64": "...", "password": "..."}}
            ]
        }
        self.wfile.write(json.dumps(payload).encode('utf-8'))

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length <= 0:
            self._send_error(400, "Empty request body")
            return

        body = self.rfile.read(content_length)
        try:
            req = json.loads(body.decode('utf-8'))
        except Exception:
            self._send_error(400, "Invalid JSON payload")
            return

        password = req.get('password')
        data_base64 = req.get('data_base64')
        iterations = req.get('iterations', DEFAULT_ITERATIONS)

        if not password or len(password) < 4:
            self._send_error(400, "Password must be at least 4 characters")
            return

        if not data_base64:
            self._send_error(400, "Missing data_base64")
            return

        try:
            raw_data = base64.b64decode(data_base64)
        except Exception:
            self._send_error(400, "Failed to decode base64 data")
            return

        path = self.path.split('?')[0]

        if path.endswith('/encrypt'):
            try:
                encrypted = encrypt_bytes(raw_data, password, iterations)
                res_b64 = base64.b64encode(encrypted).decode('ascii')
                self._send_json(200, {
                    "status": "success",
                    "operation": "encrypt",
                    "result_base64": res_b64,
                    "original_size": len(raw_data),
                    "encrypted_size": len(encrypted)
                })
            except Exception as e:
                self._send_error(500, f"Encryption error: {str(e)}")

        elif path.endswith('/decrypt'):
            try:
                decrypted = decrypt_bytes(raw_data, password, iterations)
                res_b64 = base64.b64encode(decrypted).decode('ascii')
                self._send_json(200, {
                    "status": "success",
                    "operation": "decrypt",
                    "result_base64": res_b64,
                    "original_size": len(raw_data),
                    "decrypted_size": len(decrypted)
                })
            except Exception as e:
                self._send_error(400, f"Decryption failed: {str(e)}")

        else:
            self._send_error(404, f"Endpoint not found: {path}")

    def _send_json(self, status_code: int, data: dict):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _send_error(self, status_code: int, message: str):
        self._send_json(status_code, {"status": "error", "message": message})

import sys
import os
import struct
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QLineEdit, QProgressBar, QFrame, QInputDialog, QMessageBox
)
from PyQt5.QtGui import QFont, QPainter, QBrush, QColor, QPixmap
from PyQt5.QtCore import Qt, QPoint

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asympad
from cryptography.hazmat.backends import default_backend

# Constants
AES_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
PBKDF2_SALT_SIZE = 16
PBKDF2_ITERATIONS = 200_000
RSA_KEY_SIZE = 3072  # strong RSA key
AXION_DIR = Path.home() / ".axion_keys"
PUBLIC_KEY_PATH = AXION_DIR / "public.pem"
PRIVATE_KEY_ENC_PATH = AXION_DIR / "private.enc"

MAGIC = b"AXION1"  # file magic header for .docenc files
KEYFILE_MAGIC = b"AXIONKEY"  # header for encrypted private key


def ensure_keys_dir():
    AXION_DIR.mkdir(parents=True, exist_ok=True)


def derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def generate_and_store_keypair(passphrase: str) -> str:
    """
    Generates RSA keypair. Stores:
      - public PEM at PUBLIC_KEY_PATH (PEM, public)
      - private key serialized then encrypted with AESGCM using key derived from passphrase
        stored at PRIVATE_KEY_ENC_PATH as: KEYFILE_MAGIC || salt(16) || nonce(12) || ciphertext
    """
    try:
        ensure_keys_dir()
        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize public key (PEM)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_pem)

        # Serialize private key (PEM, unencrypted) then encrypt with passphrase-derived key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        salt = os.urandom(PBKDF2_SALT_SIZE)
        key = derive_key_from_password(passphrase, salt, length=32)
        aesgcm = AESGCM(key)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, private_pem, associated_data=None)

        with open(PRIVATE_KEY_ENC_PATH, "wb") as f:
            f.write(KEYFILE_MAGIC + salt + nonce + ciphertext)

        return "Keypair generated and stored."
    except Exception as e:
        return f"Key generation failed: {e}"


def load_public_key():
    if not PUBLIC_KEY_PATH.exists():
        raise FileNotFoundError("Public key not found. Please run Setup Keys first.")
    with open(PUBLIC_KEY_PATH, "rb") as f:
        data = f.read()
    public_key = serialization.load_pem_public_key(data, backend=default_backend())
    return public_key


def load_private_key_from_encrypted(passphrase: str):
    """
    Reads PRIVATE_KEY_ENC_PATH, derives key from passphrase and decrypts via AESGCM.
    Returns a loaded private key object.
    """
    if not PRIVATE_KEY_ENC_PATH.exists():
        raise FileNotFoundError("Encrypted private key not found. Please run Setup Keys first.")
    with open(PRIVATE_KEY_ENC_PATH, "rb") as f:
        raw = f.read()

    if not raw.startswith(KEYFILE_MAGIC):
        raise ValueError("Invalid private key file format.")

    offset = len(KEYFILE_MAGIC)
    salt = raw[offset:offset + PBKDF2_SALT_SIZE]
    offset += PBKDF2_SALT_SIZE
    nonce = raw[offset:offset + AES_GCM_NONCE_SIZE]
    offset += AES_GCM_NONCE_SIZE
    ciphertext = raw[offset:]

    key = derive_key_from_password(passphrase, salt, length=32)
    aesgcm = AESGCM(key)
    try:
        private_pem = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        raise ValueError("Incorrect passphrase or corrupted private key.") from e

    private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
    return private_key


def encrypt_file_with_hybrid(public_key, input_path: str) -> str:
    """
    Hybrid encryption:
      - Generate random AES key
      - Encrypt file content with AESGCM
      - Encrypt AES key with RSA-OAEP using public_key
      - Write out: MAGIC || enc_key_len(4) || enc_key || nonce(12) || ciphertext
    """
    try:
        with open(input_path, "rb") as f:
            plaintext = f.read()

        # AES-GCM encrypt
        aes_key = os.urandom(AES_KEY_SIZE)
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

        # RSA encrypt AES key
        enc_key = public_key.encrypt(
            aes_key,
            asympad.OAEP(
                mgf=asympad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # build file
        enc_key_len = len(enc_key)
        header = MAGIC + struct.pack(">I", enc_key_len)
        output_path = input_path + ".docenc"
        with open(output_path, "wb") as f:
            f.write(header + enc_key + nonce + ciphertext)

        return f"Encrypted:\n{output_path}"
    except Exception as e:
        return f"Encryption failed: {e}"


def decrypt_file_with_hybrid(private_key, input_path: str, output_ext: str) -> str:
    """
    Read file format and decrypt:
      - Read MAGIC, enc_key_len, enc_key, nonce, ciphertext
      - Decrypt enc_key with RSA private key -> aes_key
      - AESGCM decrypt ciphertext with nonce -> plaintext
    """
    try:
        with open(input_path, "rb") as f:
            data = f.read()

        if not data.startswith(MAGIC):
            return "Invalid encrypted file format."

        offset = len(MAGIC)
        enc_key_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        enc_key = data[offset:offset + enc_key_len]
        offset += enc_key_len
        nonce = data[offset:offset + AES_GCM_NONCE_SIZE]
        offset += AES_GCM_NONCE_SIZE
        ciphertext = data[offset:]

        # RSA decrypt AES key
        aes_key = private_key.decrypt(
            enc_key,
            asympad.OAEP(
                mgf=asympad.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

        output_path = input_path.replace('.docenc', f'.decrypted{output_ext}')
        with open(output_path, "wb") as f:
            f.write(plaintext)

        return f"Decrypted:\n{output_path}"
    except Exception as e:
        return f"Decryption failed: {e}"


# ---------- UI classes (modified/extended) ----------

class BaseLockerWindow(QWidget):
    def __init__(self, file_type, ext, output_ext):
        super().__init__()
        self.file_type = file_type
        self.ext = ext
        self.output_ext = output_ext
        self.logo_path = r"C:\Users\sridh\Desktop\Silicon rush\logo2.png"
        self.setWindowTitle(f"{file_type} Locker")
        self.setGeometry(300, 200, 600, 350)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("""
            QWidget { background-color: #1e1e1e; color: white; border-radius: 12px; font-family: Arial; }
            QLabel { font-size: 14px; }
            QLineEdit { background-color: #2c2c2c; padding: 6px; border: 1px solid #444; border-radius: 5px; color: white; }
            QPushButton { background-color: #4aa3ff; color: black; padding: 6px 10px; border-radius: 6px; font-weight: bold; }
            QPushButton:hover { background-color: #74bdff; }
            QProgressBar { background-color: #2e2e2e; border: 1px solid #3f3f3f; border-radius: 5px; height: 16px; }
            QProgressBar::chunk { background-color: #4aa3ff; }
        """)
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        title_bar = QHBoxLayout()
        logo_label = QLabel()
        try:
            pix = QPixmap(self.logo_path).scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_label.setPixmap(pix)
        except Exception:
            pass
        title_bar.addWidget(logo_label)
        title = QLabel(f"  AXION - {file_type}")
        title.setFont(QFont("Arial", 14))
        title_bar.addWidget(title)
        title_bar.addStretch(1)
        minimize_btn = QPushButton("-")
        minimize_btn.setFixedSize(30, 22)
        minimize_btn.clicked.connect(self.showMinimized)
        minimize_btn.setStyleSheet("background-color: #333; color: white; border-radius: 4px;")
        close_btn = QPushButton("x")
        close_btn.setFixedSize(30, 22)
        close_btn.clicked.connect(self.close)
        close_btn.setStyleSheet("background-color: #aa0000; color: white; border-radius: 4px;")
        title_bar.addWidget(minimize_btn)
        title_bar.addWidget(close_btn)
        layout.addLayout(title_bar)
        layout.addSpacing(10)
        file_row = QHBoxLayout()
        file_label = QLabel(f"  Select {ext.upper()} File  ")
        file_label.setStyleSheet("background-color: #4aa3ff; color: black; padding: 6px; border-radius: 5px;")
        file_row.addWidget(file_label)
        self.file_display = QLineEdit()
        self.file_display.setReadOnly(True)
        file_row.addWidget(self.file_display)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)
        layout.addSpacing(20)
        pwd_row = QHBoxLayout()
        pwd_label = QLabel("  Enter Passphrase (for decryption)  ")
        pwd_label.setStyleSheet("background-color: #4aa3ff; color: black; padding: 6px; border-radius: 5px;")
        pwd_row.addWidget(pwd_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        pwd_row.addWidget(self.password_input)
        layout.addLayout(pwd_row)
        layout.addSpacing(20)
        btn_row = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt")
        decrypt_btn = QPushButton("Decrypt")
        encrypt_btn.clicked.connect(self.run_encrypt)
        decrypt_btn.clicked.connect(self.run_decrypt)
        btn_row.addWidget(encrypt_btn)
        btn_row.addWidget(decrypt_btn)
        layout.addLayout(btn_row)
        layout.addSpacing(15)
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        self.setLayout(layout)
        self.old_pos = None

    def run_encrypt(self):
        path = self.file_display.text()
        if not path:
            self.progress.setValue(0)
            self.progress.setFormat("Missing file")
            return
        try:
            public_key = load_public_key()
        except Exception as e:
            self.progress.setValue(0)
            self.progress.setFormat("Public key missing. Run Setup Keys.")
            return
        result = encrypt_file_with_hybrid(public_key, path)
        if result.startswith("Encrypted"):
            self.progress.setValue(100)
        else:
            self.progress.setValue(0)
        self.progress.setFormat(result)

    def run_decrypt(self):
        path = self.file_display.text()
        password = self.password_input.text()
        if not path or not password:
            self.progress.setValue(0)
            self.progress.setFormat("Missing file or passphrase")
            return
        try:
            private_key = load_private_key_from_encrypted(password)
        except Exception as e:
            self.progress.setValue(0)
            self.progress.setFormat("Failed to load private key: " + str(e))
            return
        result = decrypt_file_with_hybrid(private_key, path, self.output_ext)
        if result.startswith("Decrypted"):
            self.progress.setValue(100)
        else:
            self.progress.setValue(0)
        self.progress.setFormat(result)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Select {self.ext.upper()} File", "",
            f"{self.ext.upper()} Files (*{self.ext});;Encrypted Files (*.docenc)"
        )
        if file_path:
            self.file_display.setText(file_path)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.old_pos = event.globalPos()

    def mouseMoveEvent(self, event):
        if self.old_pos:
            delta = QPoint(event.globalPos() - self.old_pos)
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPos()

    def mouseReleaseEvent(self, event):
        self.old_pos = None

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QBrush(QColor(30, 30, 30)))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 12, 12)


class TextLockerWindow(BaseLockerWindow):
    def __init__(self):
        super().__init__(file_type="Text", ext=".txt", output_ext=".txt")


class DocxLockerWindow(BaseLockerWindow):
    def __init__(self):
        super().__init__(file_type="DOCX", ext=".docx", output_ext=".docx")


class PptLockerWindow(BaseLockerWindow):
    def __init__(self):
        super().__init__(file_type="PPTX", ext=".pptx", output_ext=".pptx")


class PdfLockerWindow(BaseLockerWindow):
    def __init__(self):
        super().__init__(file_type="PDF", ext=".pdf", output_ext=".pdf")


class AxionFileWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.logo_path = r"C:\Users\sridh\Desktop\Silicon rush\logo2.png"
        self.setWindowTitle("AXION")
        self.setGeometry(300, 200, 650, 420)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: white;
                border-radius: 12px;
                font-family: Arial;
            }
            QPushButton {
                background-color: #4aa3ff;
                color: black;
                padding: 8px 22px;
                border-radius: 6px;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #74bdff;
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)

        title_bar = QHBoxLayout()
        logo_small = QLabel()
        try:
            pix = QPixmap(self.logo_path).scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            logo_small.setPixmap(pix)
        except Exception:
            pass
        title_bar.addWidget(logo_small)

        title = QLabel("  AXION")
        title.setFont(QFont("Arial", 14))
        title_bar.addWidget(title)
        title_bar.addStretch(1)

        minimize_btn = QPushButton("-")
        minimize_btn.setFixedSize(30, 22)
        minimize_btn.clicked.connect(self.showMinimized)
        minimize_btn.setStyleSheet("background-color: #333; color: white; border-radius: 4px;")

        close_btn = QPushButton("x")
        close_btn.setFixedSize(30, 22)
        close_btn.clicked.connect(self.close)
        close_btn.setStyleSheet("background-color: #aa0000; color: white; border-radius: 4px;")

        title_bar.addWidget(minimize_btn)
        title_bar.addWidget(close_btn)

        main_layout.addLayout(title_bar)
        main_layout.addSpacing(15)

        btn_row = QHBoxLayout()

        text_btn = QPushButton("Text")
        text_btn.clicked.connect(self.open_text_locker)

        doc_btn = QPushButton("DOC")
        doc_btn.clicked.connect(self.open_docx_locker)

        ppt_btn = QPushButton("PPT")
        ppt_btn.clicked.connect(self.open_ppt_locker)

        pdf_btn = QPushButton("PDF")
        pdf_btn.clicked.connect(self.open_pdf_locker)

        setup_btn = QPushButton("Setup Keys")
        setup_btn.clicked.connect(self.setup_keys_dialog)

        btn_row.addWidget(text_btn)
        btn_row.addWidget(doc_btn)
        btn_row.addWidget(ppt_btn)
        btn_row.addWidget(pdf_btn)
        btn_row.addWidget(setup_btn)

        main_layout.addLayout(btn_row)
        main_layout.addSpacing(10)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #444; background-color: #444; max-height: 2px;")
        main_layout.addWidget(line)
        main_layout.addSpacing(20)

        center_logo = QLabel()
        try:
            big_pix = QPixmap(self.logo_path).scaled(270, 270, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            center_logo.setPixmap(big_pix)
        except Exception:
            pass
        center_logo.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(center_logo)

        self.setLayout(main_layout)
        self.old_pos = None

    def open_text_locker(self):
        self.text_window = TextLockerWindow()
        self.text_window.show()

    def open_docx_locker(self):
        self.docx_window = DocxLockerWindow()
        self.docx_window.show()

    def open_ppt_locker(self):
        self.ppt_window = PptLockerWindow()
        self.ppt_window.show()

    def open_pdf_locker(self):
        self.pdf_window = PdfLockerWindow()
        self.pdf_window.show()

    def setup_keys_dialog(self):
        # ask for passphrase twice
        pass1, ok1 = QInputDialog.getText(self, "Setup Keys", "Enter passphrase to protect your private key:", QLineEdit.Password)
        if not ok1 or not pass1:
            return
        pass2, ok2 = QInputDialog.getText(self, "Setup Keys", "Confirm passphrase:", QLineEdit.Password)
        if not ok2 or not pass2:
            return
        if pass1 != pass2:
            QMessageBox.warning(self, "Mismatch", "Passphrases do not match.")
            return
        result = generate_and_store_keypair(pass1)
        QMessageBox.information(self, "Setup Keys", result)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.old_pos = event.globalPos()

    def mouseMoveEvent(self, event):
        if self.old_pos:
            delta = event.globalPos() - self.old_pos
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPos()

    def mouseReleaseEvent(self, event):
        self.old_pos = None

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QBrush(QColor(30, 30, 30)))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 12, 12)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AxionFileWindow()
    window.show()
    sys.exit(app.exec_())

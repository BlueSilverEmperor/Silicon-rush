import sys
import os
import tempfile
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QLineEdit, QProgressBar, QFrame,
    QMessageBox
)
from PyQt5.QtGui import QFont, QPainter, QBrush, QColor, QPixmap
from PyQt5.QtCore import Qt, QPoint
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---- Configurable constants ----
BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100_000
MIN_PASSWORD_LENGTH = 4          # minimal acceptable password length
LARGE_FILE_WARNING_BYTES = 100 * 1024 * 1024  # 100 MB

# ---- Utility functions ----
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def _write_atomic(path: str, data: bytes):
    """
    Write bytes to path atomically: write to temp file then replace.
    """
    dirn = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dirn, prefix=".tmp_axion_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        # atomic replace
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise

def _safe_output_path(input_path: str, suffix: str):
    """
    Create an output path that does not clobber existing files.
    If file exists, append numeric suffix.
    """
    base = input_path + suffix
    if not os.path.exists(base):
        return base
    # add incremental suffix
    i = 1
    while True:
        candidate = f"{input_path}{suffix}.{i}"
        if not os.path.exists(candidate):
            return candidate
        i += 1

# ---- Crypto functions (symmetric, with PBKDF2 + AES-CBC) ----
def encrypt_file(input_path: str, password: str, expected_ext: str):
    # Basic validation
    if not input_path or not os.path.isfile(input_path):
        return False, "Input file not found."
    if not input_path.lower().endswith(expected_ext):
        return False, f"Only {expected_ext} files are supported for encryption."

    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

    try:
        file_size = os.path.getsize(input_path)
        if file_size >= LARGE_FILE_WARNING_BYTES:
            # warn caller (UI will show message) but continue
            warn = f"Warning: file is large ({file_size//1024//1024} MB). Operation may take time."
        else:
            warn = None

        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        iv = os.urandom(BLOCK_SIZE)

        # Read file (medium safety: we read all at once to keep logic simple)
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # PKCS7-like padding (simple)
        padding_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
        if padding_length == 0:
            padding_length = BLOCK_SIZE
        plaintext += bytes([padding_length]) * padding_length

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        output_path = _safe_output_path(input_path, '.docenc')
        # File layout: salt + iv + ciphertext
        out_bytes = salt + iv + ciphertext
        _write_atomic(output_path, out_bytes)
        msg = f"Encrypted: {output_path}"
        if warn:
            msg = warn + "\n" + msg
        return True, msg
    except Exception as e:
        return False, f"Encryption failed: {str(e)}"

def decrypt_file(input_path: str, password: str, expected_ext: str, output_ext: str):
    # validation
    if not input_path or not os.path.isfile(input_path):
        return False, "Input file not found."
    if not input_path.lower().endswith('.docenc'):
        return False, "Only .docenc files are supported for decryption."

    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

    try:
        with open(input_path, 'rb') as f:
            data = f.read()

        if len(data) < SALT_SIZE + BLOCK_SIZE + 1:
            return False, "File appears too small or corrupted."

        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
        ciphertext = data[SALT_SIZE + BLOCK_SIZE:]

        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Validate padding (safe)
        if not plaintext_padded:
            return False, "Decrypted data is empty (wrong key or corrupted)."

        padding_length = plaintext_padded[-1]
        if not (1 <= padding_length <= BLOCK_SIZE):
            # invalid padding value
            return False, "Decryption failed: invalid padding (wrong password or corrupted file)."

        # ensure last padding_length bytes all equal to padding_length
        if plaintext_padded[-padding_length:] != bytes([padding_length]) * padding_length:
            return False, "Decryption failed: bad padding (wrong password or corrupted file)."

        plaintext = plaintext_padded[:-padding_length]

        # Validate output filename and write atomically
        output_path = _safe_output_path(input_path.replace('.docenc', f'.decrypted{output_ext}'), '')
        _write_atomic(output_path, plaintext)
        return True, f"Decrypted: {output_path}"

    except ValueError as ve:
        # cryptography can raise ValueError for wrong key / finalize issues
        return False, f"Decryption failed: {str(ve)}"
    except Exception as e:
        return False, f"Decryption failed: {str(e)}"

# ---- GUI classes (medium-safety tweaks) ----
class BaseLockerWindow(QWidget):
    def __init__(self, file_type, ext, output_ext):
        super().__init__()
        self.file_type = file_type
        self.ext = ext
        self.output_ext = output_ext
        self.logo_path = r"C:\Users\sridh\Desktop\Silicon rush\logo2.png"
        self.setWindowTitle(f"{file_type} Locker")
        self.setGeometry(300, 200, 600, 370)
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

        # Title bar with logo
        title_bar = QHBoxLayout()
        logo_label = QLabel()
        try:
            if os.path.exists(self.logo_path):
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

        # File row
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
        layout.addSpacing(10)

        # Password row
        pwd_row = QHBoxLayout()
        pwd_label = QLabel("  Enter Password  ")
        pwd_label.setStyleSheet("background-color: #4aa3ff; color: black; padding: 6px; border-radius: 5px;")
        pwd_row.addWidget(pwd_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        pwd_row.addWidget(self.password_input)
        layout.addLayout(pwd_row)
        layout.addSpacing(12)

        # Buttons
        btn_row = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt")
        decrypt_btn = QPushButton("Decrypt")
        encrypt_btn.clicked.connect(self.run_encrypt)
        decrypt_btn.clicked.connect(self.run_decrypt)
        btn_row.addWidget(encrypt_btn)
        btn_row.addWidget(decrypt_btn)
        layout.addLayout(btn_row)
        layout.addSpacing(12)

        # Progress bar + status label
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.status_label = QLabel("")  # safer place for messages
        self.status_label.setStyleSheet("color: #cfcfcf; font-size: 13px;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)
        self.old_pos = None

    def set_status(self, text: str, percent: int = 100):
        # update progress & status label
        try:
            self.progress.setValue(percent)
        except Exception:
            pass
        self.status_label.setText(text)

    def run_encrypt(self):
        path = self.file_display.text().strip()
        password = self.password_input.text()
        if not path:
            self.set_status("Missing file.", 0)
            return
        if not password:
            self.set_status("Missing password.", 0)
            return
        # do encryption
        self.set_status("Encrypting...", 10)
        ok, msg = encrypt_file(path, password, self.ext)
        self.set_status(msg, 100 if ok else 0)
        if not ok:
            QMessageBox.warning(self, "Encrypt", msg)
        else:
            QMessageBox.information(self, "Encrypt", msg)

    def run_decrypt(self):
        path = self.file_display.text().strip()
        password = self.password_input.text()
        if not path:
            self.set_status("Missing file.", 0)
            return
        if not password:
            self.set_status("Missing password.", 0)
            return
        self.set_status("Decrypting...", 10)
        ok, msg = decrypt_file(path, password, self.ext, self.output_ext)
        self.set_status(msg, 100 if ok else 0)
        if not ok:
            QMessageBox.warning(self, "Decrypt", msg)
        else:
            QMessageBox.information(self, "Decrypt", msg)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Select {self.ext.upper()} File", "",
            f"{self.ext.upper()} Files (*{self.ext});;Encrypted Files (*.docenc);;All Files (*)"
        )
        if file_path:
            self.file_display.setText(file_path)

    # Drag & paint events preserved
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

# Specific file windows
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

# Main launcher
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
            if os.path.exists(self.logo_path):
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
        text_btn = QPushButton("Text"); text_btn.clicked.connect(self.open_text_locker)
        doc_btn = QPushButton("DOC"); doc_btn.clicked.connect(self.open_docx_locker)
        ppt_btn = QPushButton("PPT"); ppt_btn.clicked.connect(self.open_ppt_locker)
        pdf_btn = QPushButton("PDF"); pdf_btn.clicked.connect(self.open_pdf_locker)
        btn_row.addWidget(text_btn); btn_row.addWidget(doc_btn); btn_row.addWidget(ppt_btn); btn_row.addWidget(pdf_btn)
        main_layout.addLayout(btn_row)
        main_layout.addSpacing(10)
        line = QFrame(); line.setFrameShape(QFrame.HLine); line.setStyleSheet("color: #444; background-color: #444; max-height: 2px;")
        main_layout.addWidget(line); main_layout.addSpacing(20)
        center_logo = QLabel()
        try:
            if os.path.exists(self.logo_path):
                big_pix = QPixmap(self.logo_path).scaled(270, 270, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                center_logo.setPixmap(big_pix)
        except Exception:
            pass
        center_logo.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(center_logo)
        self.setLayout(main_layout)
        self.old_pos = None

    def open_text_locker(self): self.text_window = TextLockerWindow(); self.text_window.show()
    def open_docx_locker(self): self.docx_window = DocxLockerWindow(); self.docx_window.show()
    def open_ppt_locker(self): self.ppt_window = PptLockerWindow(); self.ppt_window.show()
    def open_pdf_locker(self): self.pdf_window = PdfLockerWindow(); self.pdf_window.show()

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
import sys
import os
import tempfile
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QLineEdit, QProgressBar, QFrame,
    QMessageBox
)
from PyQt5.QtGui import QFont, QPainter, QBrush, QColor, QPixmap
from PyQt5.QtCore import Qt, QPoint
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---- Configurable constants ----
BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100_000
MIN_PASSWORD_LENGTH = 4          # minimal acceptable password length
LARGE_FILE_WARNING_BYTES = 100 * 1024 * 1024  # 100 MB

# ---- Utility functions ----
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def _write_atomic(path: str, data: bytes):
    """
    Write bytes to path atomically: write to temp file then replace.
    """
    dirn = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dirn, prefix=".tmp_axion_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        # atomic replace
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise

def _safe_output_path(input_path: str, suffix: str):
    """
    Create an output path that does not clobber existing files.
    If file exists, append numeric suffix.
    """
    base = input_path + suffix
    if not os.path.exists(base):
        return base
    # add incremental suffix
    i = 1
    while True:
        candidate = f"{input_path}{suffix}.{i}"
        if not os.path.exists(candidate):
            return candidate
        i += 1

# ---- Crypto functions (symmetric, with PBKDF2 + AES-CBC) ----
def encrypt_file(input_path: str, password: str, expected_ext: str):
    # Basic validation
    if not input_path or not os.path.isfile(input_path):
        return False, "Input file not found."
    if not input_path.lower().endswith(expected_ext):
        return False, f"Only {expected_ext} files are supported for encryption."

    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

    try:
        file_size = os.path.getsize(input_path)
        if file_size >= LARGE_FILE_WARNING_BYTES:
            # warn caller (UI will show message) but continue
            warn = f"Warning: file is large ({file_size//1024//1024} MB). Operation may take time."
        else:
            warn = None

        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        iv = os.urandom(BLOCK_SIZE)

        # Read file (medium safety: we read all at once to keep logic simple)
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # PKCS7-like padding (simple)
        padding_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
        if padding_length == 0:
            padding_length = BLOCK_SIZE
        plaintext += bytes([padding_length]) * padding_length

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        output_path = _safe_output_path(input_path, '.docenc')
        # File layout: salt + iv + ciphertext
        out_bytes = salt + iv + ciphertext
        _write_atomic(output_path, out_bytes)
        msg = f"Encrypted: {output_path}"
        if warn:
            msg = warn + "\n" + msg
        return True, msg
    except Exception as e:
        return False, f"Encryption failed: {str(e)}"

def decrypt_file(input_path: str, password: str, expected_ext: str, output_ext: str):
    # validation
    if not input_path or not os.path.isfile(input_path):
        return False, "Input file not found."
    if not input_path.lower().endswith('.docenc'):
        return False, "Only .docenc files are supported for decryption."

    if not password or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."

    try:
        with open(input_path, 'rb') as f:
            data = f.read()

        if len(data) < SALT_SIZE + BLOCK_SIZE + 1:
            return False, "File appears too small or corrupted."

        salt = data[:SALT_SIZE]
        iv = data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
        ciphertext = data[SALT_SIZE + BLOCK_SIZE:]

        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Validate padding (safe)
        if not plaintext_padded:
            return False, "Decrypted data is empty (wrong key or corrupted)."

        padding_length = plaintext_padded[-1]
        if not (1 <= padding_length <= BLOCK_SIZE):
            # invalid padding value
            return False, "Decryption failed: invalid padding (wrong password or corrupted file)."

        # ensure last padding_length bytes all equal to padding_length
        if plaintext_padded[-padding_length:] != bytes([padding_length]) * padding_length:
            return False, "Decryption failed: bad padding (wrong password or corrupted file)."

        plaintext = plaintext_padded[:-padding_length]

        # Validate output filename and write atomically
        output_path = _safe_output_path(input_path.replace('.docenc', f'.decrypted{output_ext}'), '')
        _write_atomic(output_path, plaintext)
        return True, f"Decrypted: {output_path}"

    except ValueError as ve:
        # cryptography can raise ValueError for wrong key / finalize issues
        return False, f"Decryption failed: {str(ve)}"
    except Exception as e:
        return False, f"Decryption failed: {str(e)}"

# ---- GUI classes (medium-safety tweaks) ----
class BaseLockerWindow(QWidget):
    def __init__(self, file_type, ext, output_ext):
        super().__init__()
        self.file_type = file_type
        self.ext = ext
        self.output_ext = output_ext
        self.logo_path = r"C:\Users\sridh\Desktop\Silicon rush\logo2.png"
        self.setWindowTitle(f"{file_type} Locker")
        self.setGeometry(300, 200, 600, 370)
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

        # Title bar with logo
        title_bar = QHBoxLayout()
        logo_label = QLabel()
        try:
            if os.path.exists(self.logo_path):
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

        # File row
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
        layout.addSpacing(10)

        # Password row
        pwd_row = QHBoxLayout()
        pwd_label = QLabel("  Enter Password  ")
        pwd_label.setStyleSheet("background-color: #4aa3ff; color: black; padding: 6px; border-radius: 5px;")
        pwd_row.addWidget(pwd_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        pwd_row.addWidget(self.password_input)
        layout.addLayout(pwd_row)
        layout.addSpacing(12)

        # Buttons
        btn_row = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt")
        decrypt_btn = QPushButton("Decrypt")
        encrypt_btn.clicked.connect(self.run_encrypt)
        decrypt_btn.clicked.connect(self.run_decrypt)
        btn_row.addWidget(encrypt_btn)
        btn_row.addWidget(decrypt_btn)
        layout.addLayout(btn_row)
        layout.addSpacing(12)

        # Progress bar + status label
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.status_label = QLabel("")  # safer place for messages
        self.status_label.setStyleSheet("color: #cfcfcf; font-size: 13px;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)
        self.old_pos = None

    def set_status(self, text: str, percent: int = 100):
        # update progress & status label
        try:
            self.progress.setValue(percent)
        except Exception:
            pass
        self.status_label.setText(text)

    def run_encrypt(self):
        path = self.file_display.text().strip()
        password = self.password_input.text()
        if not path:
            self.set_status("Missing file.", 0)
            return
        if not password:
            self.set_status("Missing password.", 0)
            return
        # do encryption
        self.set_status("Encrypting...", 10)
        ok, msg = encrypt_file(path, password, self.ext)
        self.set_status(msg, 100 if ok else 0)
        if not ok:
            QMessageBox.warning(self, "Encrypt", msg)
        else:
            QMessageBox.information(self, "Encrypt", msg)

    def run_decrypt(self):
        path = self.file_display.text().strip()
        password = self.password_input.text()
        if not path:
            self.set_status("Missing file.", 0)
            return
        if not password:
            self.set_status("Missing password.", 0)
            return
        self.set_status("Decrypting...", 10)
        ok, msg = decrypt_file(path, password, self.ext, self.output_ext)
        self.set_status(msg, 100 if ok else 0)
        if not ok:
            QMessageBox.warning(self, "Decrypt", msg)
        else:
            QMessageBox.information(self, "Decrypt", msg)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Select {self.ext.upper()} File", "",
            f"{self.ext.upper()} Files (*{self.ext});;Encrypted Files (*.docenc);;All Files (*)"
        )
        if file_path:
            self.file_display.setText(file_path)

    # Drag & paint events preserved
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

# Specific file windows
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

# Main launcher
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
            if os.path.exists(self.logo_path):
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
        text_btn = QPushButton("Text"); text_btn.clicked.connect(self.open_text_locker)
        doc_btn = QPushButton("DOC"); doc_btn.clicked.connect(self.open_docx_locker)
        ppt_btn = QPushButton("PPT"); ppt_btn.clicked.connect(self.open_ppt_locker)
        pdf_btn = QPushButton("PDF"); pdf_btn.clicked.connect(self.open_pdf_locker)
        btn_row.addWidget(text_btn); btn_row.addWidget(doc_btn); btn_row.addWidget(ppt_btn); btn_row.addWidget(pdf_btn)
        main_layout.addLayout(btn_row)
        main_layout.addSpacing(10)
        line = QFrame(); line.setFrameShape(QFrame.HLine); line.setStyleSheet("color: #444; background-color: #444; max-height: 2px;")
        main_layout.addWidget(line); main_layout.addSpacing(20)
        center_logo = QLabel()
        try:
            if os.path.exists(self.logo_path):
                big_pix = QPixmap(self.logo_path).scaled(270, 270, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                center_logo.setPixmap(big_pix)
        except Exception:
            pass
        center_logo.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(center_logo)
        self.setLayout(main_layout)
        self.old_pos = None

    def open_text_locker(self): self.text_window = TextLockerWindow(); self.text_window.show()
    def open_docx_locker(self): self.docx_window = DocxLockerWindow(); self.docx_window.show()
    def open_ppt_locker(self): self.ppt_window = PptLockerWindow(); self.ppt_window.show()
    def open_pdf_locker(self): self.pdf_window = PdfLockerWindow(); self.pdf_window.show()

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

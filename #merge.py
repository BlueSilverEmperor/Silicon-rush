import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QLineEdit, QProgressBar, QFrame
)
from PyQt5.QtGui import QFont, QPainter, QBrush, QColor, QPixmap, QIcon
from PyQt5.QtCore import Qt, QPoint
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# RSA Key Loading
def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# Encryption
def encrypt_file(input_path, pub_key_path, ext):
    if not input_path.lower().endswith(ext):
        return f"Only {ext} files are supported for encryption."
    try:
        public_key = load_public_key(pub_key_path)
        with open(input_path, "rb") as f:
            plaintext = f.read()

        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )

        output_path = input_path + ".rsaenc"
        with open(output_path, "wb") as f:
            f.write(ciphertext)
        return f"Encrypted:\n{output_path}"
    except Exception as e:
        return f"Encryption failed: {str(e)}"

# Decryption
def decrypt_file(input_path, priv_key_path, ext, output_ext):
    if not input_path.lower().endswith(".rsaenc"):
        return "Only .rsaenc files are supported for decryption."
    try:
        private_key = load_private_key(priv_key_path)
        with open(input_path, "rb") as f:
            ciphertext = f.read()

        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )

        output_path = input_path.replace(".rsaenc", f".decrypted{output_ext}")
        with open(output_path, "wb") as f:
            f.write(plaintext)
        return f"Decrypted:\n{output_path}"
    except Exception as e:
        return f"Decryption failed: {str(e)}"

# Base GUI Window
class BaseLockerWindow(QWidget):
    def __init__(self, file_type, ext, output_ext):
        super().__init__()
        self.file_type = file_type
        self.ext = ext
        self.output_ext = output_ext
        self.logo_path = r"C:\Users\sridh\Desktop\Silicon rush\logo2.png"
        self.setWindowTitle(f"{file_type} Locker")
        self.setWindowIcon(QIcon(r"C:\Users\sridh\Desktop\Silicon rush\axion_icon.ico"))
        self.setGeometry(300, 200, 600, 400)
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

        # Title bar
        title_bar = QHBoxLayout()
        logo_label = QLabel()
        pix = QPixmap(self.logo_path).scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pix)
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

        # File selection
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

        # Public key
        pub_row = QHBoxLayout()
        pub_label = QLabel("  Public Key File  ")
        pub_label.setStyleSheet("background-color: #4aa3ff; color: black; padding: 6px; border-radius: 5px;")
        pub_row.addWidget(pub_label)
        self.pub_key_input = QLineEdit()
        pub_row.addWidget(self.pub_key_input)
        pub_browse = QPushButton("Browse")
        pub_browse.clicked.connect(lambda: self.browse_key(self.pub_key_input))
        pub_row.addWidget(pub_browse)
        layout.addLayout(pub_row)
        layout.addSpacing(10)

        # Private key
        priv_row = QHBoxLayout()
        priv_label = QLabel("  Private Key File  ")
        priv_label.setStyleSheet("background-color: #4aa3ff; color: black; padding: 6px; border-radius: 5px;")
        priv_row.addWidget(priv_label)
        self.priv_key_input = QLineEdit()
        priv_row.addWidget(self.priv_key_input)
        priv_browse = QPushButton("Browse")
        priv_browse.clicked.connect(lambda: self.browse_key(self.priv_key_input))
        priv_row.addWidget(priv_browse)
        layout.addLayout(priv_row)
        layout.addSpacing(10)

        # Buttons
        btn_row = QHBoxLayout()
        encrypt_btn = QPushButton("Encrypt")
        decrypt_btn = QPushButton("Decrypt")
        encrypt_btn.clicked.connect(self.run_encrypt)
        decrypt_btn.clicked.connect(self.run_decrypt)
        btn_row.addWidget(encrypt_btn)
        btn_row.addWidget(decrypt_btn)
        layout.addLayout(btn_row)
        layout.addSpacing(15)

        # Progress bar
        self.progress = QProgressBar()
        layout.addWidget(self.progress)
        self.setLayout(layout)
        self.old_pos = None

    def run_encrypt(self):
        path = self.file_display.text()
        pub_key = self.pub_key_input.text()
        if not path or not pub_key:
            self.progress.setValue(0)
            self.progress.setFormat("Missing file or public key")
            return
        result = encrypt_file(path, pub_key, self.ext)
        self.progress.setValue(100)
        self.progress.setFormat(result)

    def run_decrypt(self):
        path = self.file_display.text()
        priv_key = self.priv_key_input.text()
        if not path or not priv_key:
            self.progress.setValue(0)
            self.progress.setFormat("Missing file or private key")
            return
        result = decrypt_file(path, priv_key, self.ext, self.output_ext)
        self.progress.setValue(100)
        self.progress.setFormat(result)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Select {self.ext.upper()} File", "",
            f"{self.ext.upper()} Files (*{self.ext});;Encrypted Files (*.rsaenc)"
        )
        if file_path:
            self.file_display.setText(file_path)

        def browse_key(self, target_input):
            key_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "PEM Files (*.pem)")
            if key_path:
                target_input.setText(key_path)

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
        self.setWindowIcon(QIcon(r"C:\Users\sridh\Desktop\Silicon rush\axion_icon.ico"))
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
        pix = QPixmap(self.logo_path).scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_small.setPixmap(pix)
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

        btn_row.addWidget(text_btn)
        btn_row.addWidget(doc_btn)
        btn_row.addWidget(ppt_btn)
        btn_row.addWidget(pdf_btn)

        main_layout.addLayout(btn_row)
        main_layout.addSpacing(10)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #444; background-color: #444; max-height: 2px;")
        main_layout.addWidget(line)
        main_layout.addSpacing(20)

        center_logo = QLabel()
        big_pix = QPixmap(self.logo_path).scaled(270, 270, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        center_logo.setPixmap(big_pix)
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
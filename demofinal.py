import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout,
    QHBoxLayout, QFileDialog, QLineEdit, QProgressBar
)
from PyQt5.QtGui import QFont, QPainter, QBrush, QColor, QPixmap
from PyQt5.QtCore import Qt, QPoint

class SecureFileLocker(QWidget):
    def __init__(self):
        super().__init__()

        # AXION LOGO PATH
        self.logo_path = r"C:\Users\Admin\Downloads\axion_logo.png.jpeg"

        self.setWindowTitle("Secure File Locker")
        self.setGeometry(300, 200, 600, 350)

        # Borderless window
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        # Dark theme
        self.base_style = """
            QWidget {
                background-color: #1e1e1e;
                color: white;
                border-radius: 12px;
                font-family: Arial;
            }
            QLabel {
                font-size: 14px;
            }
            QLineEdit {
                background-color: #2c2c2c;
                padding: 6px;
                border: 1px solid #444;
                border-radius: 5px;
                color: white;
            }
            QPushButton {
                background-color: #4aa3ff;
                color: black;
                padding: 6px 10px;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #74bdff;
            }
            QProgressBar {
                background-color: #2e2e2e;
                border: 1px solid #3f3f3f;
                border-radius: 5px;
                height: 16px;
            }
            QProgressBar::chunk {
                background-color: #4aa3ff;
            }
        """
        self.setStyleSheet(self.base_style)

        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)

        # ---------------- CUSTOM TITLE BAR ----------------
        title_bar = QHBoxLayout()

        # Add AXION LOGO into title bar
        logo_label = QLabel()
        pix = QPixmap(self.logo_path).scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_label.setPixmap(pix)
        title_bar.addWidget(logo_label)

        title = QLabel("  AXION ")
        title.setFont(QFont("Arial", 14))
        title_bar.addWidget(title)
        title_bar.addStretch(1)

        # Minimize button
        minimize_btn = QPushButton("-")
        minimize_btn.setFixedSize(30, 22)
        minimize_btn.clicked.connect(self.showMinimized)
        minimize_btn.setStyleSheet("background-color: #333; color: white; border-radius: 4px;")

        # Close button
        close_btn = QPushButton("x")
        close_btn.setFixedSize(30, 22)
        close_btn.clicked.connect(self.close)
        close_btn.setStyleSheet("background-color: #aa0000; color: white; border-radius: 4px;")

        title_bar.addWidget(minimize_btn)
        title_bar.addWidget(close_btn)

        main_layout.addLayout(title_bar)
        main_layout.addSpacing(10)

        # ---------------- FILE SELECTION ROW ----------------
        file_row = QHBoxLayout()

        file_label = QLabel("  Select File  ")
        file_label.setStyleSheet("background-color: #4aa3ff; color: black; padding: 6px; border-radius: 5px;")
        file_row.addWidget(file_label)

        self.file_display = QLineEdit()
        self.file_display.setReadOnly(True)
        file_row.addWidget(self.file_display)

        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_row.addWidget(browse_btn)

        main_layout.addLayout(file_row)
        main_layout.addSpacing(20)

        # ---------------- PASSWORD ROW ----------------
        pwd_row = QHBoxLayout()

        pwd_label = QLabel("  Enter Password  ")
        pwd_label.setStyleSheet("background-color: #4aa3ff; color: black; padding: 6px; border-radius: 5px;")
        pwd_row.addWidget(pwd_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        pwd_row.addWidget(self.password_input)

        main_layout.addLayout(pwd_row)
        main_layout.addSpacing(20)

        # ---------------- ENCRYPT + DECRYPT BUTTONS ----------------
        btn_row = QHBoxLayout()

        encrypt_btn = QPushButton("Encrypt")
        decrypt_btn = QPushButton("Decrypt")

        btn_row.addWidget(encrypt_btn)
        btn_row.addWidget(decrypt_btn)

        main_layout.addLayout(btn_row)
        main_layout.addSpacing(15)

        # ---------------- PROGRESS BAR ----------------
        self.progress = QProgressBar()
        main_layout.addWidget(self.progress)

        self.setLayout(main_layout)

        # Dragging support
        self.old_pos = None

    # Drag window
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

    # Browse file
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_display.setText(file_path)

    # Paint rounded corners
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        brush = QBrush(QColor(30, 30, 30))
        painter.setBrush(brush)
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 12, 12)


app = QApplication(sys.argv)
window = SecureFileLocker()
window.show()
sys.exit(app.exec_())

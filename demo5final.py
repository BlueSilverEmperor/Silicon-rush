import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QHBoxLayout,
    QVBoxLayout, QFrame
)
from PyQt5.QtGui import QPixmap, QColor, QPainter, QBrush, QFont
from PyQt5.QtCore import Qt, QPoint


class AxionFileWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.logo_path = "C:\\Users\\sridh\\Desktop\\Silicon rush\\logo2.png"

        self.setWindowTitle("Axion")
        self.setGeometry(300, 200, 650, 420)

        # Borderless
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        # Theme
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

        # ---------------- TITLE BAR ----------------
        title_bar = QHBoxLayout()

        logo_small = QLabel()
        pix = QPixmap(self.logo_path).scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        logo_small.setPixmap(pix)
        title_bar.addWidget(logo_small)

        title = QLabel("  Axion")
        title.setFont(QFont("Arial", 14))
        title_bar.addWidget(title)

        title_bar.addStretch(1)

        # Minimize
        minimize_btn = QPushButton("-")
        minimize_btn.setFixedSize(30, 22)
        minimize_btn.clicked.connect(self.showMinimized)
        minimize_btn.setStyleSheet("background-color: #333; color: white; border-radius: 4px;")

        # Close
        close_btn = QPushButton("x")
        close_btn.setFixedSize(30, 22)
        close_btn.clicked.connect(self.close)
        close_btn.setStyleSheet("background-color: #aa0000; color: white; border-radius: 4px;")

        title_bar.addWidget(minimize_btn)
        title_bar.addWidget(close_btn)

        main_layout.addLayout(title_bar)
        main_layout.addSpacing(15)

        # ---------------- TOP BUTTON ROW ----------------
        btn_row = QHBoxLayout()

        text_btn = QPushButton("Text")
        doc_btn = QPushButton("DOC")
        ppt_btn = QPushButton("PPT")
        pdf_btn = QPushButton("PDF")

        btn_row.addWidget(text_btn)
        btn_row.addWidget(doc_btn)
        btn_row.addWidget(ppt_btn)
        btn_row.addWidget(pdf_btn)

        main_layout.addLayout(btn_row)
        main_layout.addSpacing(10)

        # ---------------- LINE SEPARATOR ----------------
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #444; background-color: #444; max-height: 2px;")

        main_layout.addWidget(line)
        main_layout.addSpacing(20)

        # ---------------- CENTER BIG LOGO ----------------
        center_logo = QLabel()
        big_pix = QPixmap(self.logo_path).scaled(270, 270, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        center_logo.setPixmap(big_pix)
        center_logo.setAlignment(Qt.AlignCenter)

        main_layout.addWidget(center_logo)

        self.setLayout(main_layout)

        # Dragging
        self.old_pos = None

    # Allow dragging
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

    # Rounded background
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QBrush(QColor(30, 30, 30)))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 12, 12)


# ---------------- RUN ----------------
app = QApplication(sys.argv)
window = AxionFileWindow()
window.show()
sys.exit(app.exec_())

#docx
import os
import tkinter.messagebox as messagebox
from tkinter import filedialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import customtkinter as ctk

BLOCK_SIZE = 16
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100_000

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_path, password):
    if not input_path.lower().endswith('.docx'):
        messagebox.showerror("Error", "Only .docx files are supported for encryption.")
        return

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    iv = os.urandom(BLOCK_SIZE)

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    padding_length = BLOCK_SIZE - len(plaintext) % BLOCK_SIZE
    plaintext += bytes([padding_length]) * padding_length

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    output_path = input_path + '.docenc'
    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    messagebox.showinfo("Success", f"Document encrypted:\n{output_path}")

def decrypt_file(input_path, password):
    if not input_path.lower().endswith('.docenc'):
        messagebox.showerror("Error", "Only .docenc files are supported for decryption.")
        return

    with open(input_path, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
    ciphertext = data[SALT_SIZE + BLOCK_SIZE:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    padding_length = plaintext_padded[-1]
    plaintext = plaintext_padded[:-padding_length]

    output_path = input_path.replace('.docenc', '.decrypted.docx')
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    messagebox.showinfo("Success", f"Document decrypted:\n{output_path}")

def browse_file():
    filetypes = [("Word Documents", "*.docx"), ("Encrypted Docs", "*.docenc")]
    path = filedialog.askopenfilename(filetypes=filetypes)
    file_entry.delete(0, 'end')
    file_entry.insert(0, path)

def run_encrypt():
    if not file_entry.get() or not password_entry.get():
        messagebox.showerror("Error", "Please select a .docx file and enter a password.")
        return
    encrypt_file(file_entry.get(), password_entry.get())

def run_decrypt():
    if not file_entry.get() or not password_entry.get():
        messagebox.showerror("Error", "Please select a .docenc file and enter a password.")
        return
    decrypt_file(file_entry.get(), password_entry.get())

# GUI Setup
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.title("Axion DOCX Encrypter")
root.geometry("600x180")
root.iconbitmap("C:\\Users\\sridh\\Desktop\\Silicon rush\\logo2.ico")
root.resizable(False, False)

# Exit button
exit_btn = ctk.CTkButton(root, text="Exit", command=root.quit, width=30, height=20)
exit_btn.place(x=10, y=8)

# File Path row
file_label = ctk.CTkLabel(root, text="Word Document (.docx):")
file_label.place(x=20, y=48)
file_entry = ctk.CTkEntry(root, width=240)
file_entry.place(x=200, y=45)
browse_btn = ctk.CTkButton(root, text="Browse", command=browse_file, width=60)
browse_btn.place(x=500, y=45)

# Password row
password_label = ctk.CTkLabel(root, text="Password:")
password_label.place(x=20, y=92)
password_entry = ctk.CTkEntry(root, show="*", width=240)
password_entry.place(x=200, y=90)

# Encrypt/Decrypt buttons
encrypt_btn = ctk.CTkButton(root, text="Encrypt", command=run_encrypt, width=140)
encrypt_btn.place(x=55, y=135)
decrypt_btn = ctk.CTkButton(root, text="Decrypt", command=run_decrypt, width=140)
decrypt_btn.place(x=235, y=135)

root.mainloop()
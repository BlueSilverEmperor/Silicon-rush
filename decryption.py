import customtkinter as ctk
import random

# ---------------- Encryption Methods ----------------
def caesar_cipher(text):
    return "".join(
        chr((ord(char) - 32 + 3) % 95 + 32) if 32 <= ord(char) <= 126 else char
        for char in text
    )

def reverse_string(text):
    return text[::-1]

def ascii_shift(text):
    return "".join(
        chr((ord(char) - 32 + 1) % 95 + 32) if 32 <= ord(char) <= 126 else char
        for char in text
    )

# ---------------- Decryption Methods ----------------
def caesar_decipher(text):
    return "".join(
        chr((ord(char) - 32 - 3) % 95 + 32) if 32 <= ord(char) <= 126 else char
        for char in text
    )

def ascii_unshift(text):
    return "".join(
        chr((ord(char) - 32 - 1) % 95 + 32) if 32 <= ord(char) <= 126 else char
        for char in text
    )

# ---------------- GUI Functions ----------------



def decrypt_text():
    text = entry.get()
    method = decrypt_method.get()
    if not text.strip():
        output_label.configure(text="Please enter an encrypted string!")
        return
    if method == "Caesar Cipher (+3)":
        result = caesar_decipher(text)
    elif method == "Reverse String":
        result = reverse_string(text)
    elif method == "ASCII Shift (+1)":
        result = ascii_unshift(text)
    else:
        result = "Invalid decryption method selected."
    output_label.configure(text=f"Decrypted: {result}")

# ---------------- GUI Setup ----------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Character Swapper, Encryptor & Decryptor")
app.geometry("520x500")

title = ctk.CTkLabel(app, text="Swap, Encrypt & Decrypt", font=("Arial", 20, "bold"))
title.pack(pady=15)

entry = ctk.CTkEntry(app, width=400, placeholder_text="Enter a string...")
entry.pack(pady=10)


# Decryption dropdown
decrypt_method = ctk.StringVar(value="Caesar Cipher (+3)")
decrypt_menu = ctk.CTkOptionMenu(app, variable=decrypt_method,
                                 values=["Caesar Cipher (+3)", "Reverse String", "ASCII Shift (+1)"])
decrypt_menu.pack(pady=10)

decrypt_btn = ctk.CTkButton(app, text="Decrypt", command=decrypt_text)
decrypt_btn.pack(pady=10)

output_label = ctk.CTkLabel(app, text="", font=("Arial", 14), wraplength=450)
output_label.pack(pady=20)

app.mainloop()
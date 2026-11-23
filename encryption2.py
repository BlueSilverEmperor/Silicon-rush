import customtkinter as ctk
import random


# Encryption Method 1: Caesar Cipher (shift by 3)
def caesar_cipher(text):
    return "".join(
        chr((ord(char) - 32 + 3) % 95 + 32) if 32 <= ord(char) <= 126 else char
        for char in text
    )

# Encryption Method 2: Reverse String
def reverse_string(text):
    return text[::-1]

# Encryption Method 3: ASCII Shift (shift each character by 1)
def ascii_shift(text):
    return "".join(
        chr((ord(char) - 32 + 1) % 95 + 32) if 32 <= ord(char) <= 126 else char
        for char in text
    )

# Random encryption selector
def encrypt_randomly():
    text = entry.get()

    if not text.strip():
        output_label.configure(text="Please enter some text!")
        return

    choice = random.randint(1, 3)

    if choice == 1:
        result = caesar_cipher(text)
        method = "Caesar Cipher (+3)"
    elif choice == 2:
        result = reverse_string(text)
        method = "Reverse String"
    else:
        result = ascii_shift(text)
        method = "ASCII Shift (+1)"

    output_label.configure(text=f"{method}: {result}")

# ---------------- GUI ----------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Character Swapper & Encryptor")
app.geometry("500x400")

title = ctk.CTkLabel(app, text="Swap & Encrypt Characters", font=("Arial", 20, "bold"))
title.pack(pady=15)

entry = ctk.CTkEntry(app, width=380, placeholder_text="Enter a string...")
entry.pack(pady=10)



encrypt_btn = ctk.CTkButton(app, text="Encrypt Randomly", command=encrypt_randomly)
encrypt_btn.pack(pady=10)

output_label = ctk.CTkLabel(app, text="", font=("Arial", 14), wraplength=400)
output_label.pack(pady=20)

app.mainloop()
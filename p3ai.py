import customtkinter as ctk
from tkinter import filedialog



root = ctk.CTk()
root.title("Axion")
root.geometry("450x180")
root.resizable(False, False)

# Exit button (menu simulation)
exit_btn = ctk.CTkButton(root, text="Exit", command=root.quit, width=30, height=20)
exit_btn.place(x=10, y=8)
txt_btn= ctk.CTkButton(root, text=".txt ", width=40, height=20)
txt_btn.place(x=100, y=8,)
doc_btn= ctk.CTkButton(root, text=".docx ", width=50, height=20)
doc_btn.place(x=150, y=8,)
# File Path row
file_label = ctk.CTkLabel(root, text="File Path:")
file_label.place(x=30, y=48)
file_entry = ctk.CTkEntry(root, width=240)
file_entry.place(x=110, y=45)



root.mainloop()

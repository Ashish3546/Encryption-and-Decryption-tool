import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet

# Function to generate a key and save it into a file
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Function to load the previously generated key
def load_key():
    try:
        return open("secret.key", "rb").read()
    except FileNotFoundError:
        messagebox.showerror("Error", "Key not found. Generate a key first.")
        return None

# Function to encrypt a message
def encrypt_message():
    key = load_key()
    if key:
        message = entry_message.get()
        if not message:
            messagebox.showerror("Error", "Please enter a message to encrypt.")
            return
        encoded_message = message.encode()
        f = Fernet(key)
        encrypted_message = f.encrypt(encoded_message)
        result_var.set(encrypted_message.decode())

# Function to decrypt an encrypted message
def decrypt_message():
    key = load_key()
    if key:
        encrypted_message = entry_message.get()
        if not encrypted_message:
            messagebox.showerror("Error", "Please enter a message to decrypt.")
            return
        try:
            f = Fernet(key)
            decrypted_message = f.decrypt(encrypted_message.encode())
            result_var.set(decrypted_message.decode())
        except Exception as e:
            messagebox.showerror("Error", "Invalid encrypted message.")

# Function to generate and save a new key
def generate_key_and_notify():
    generate_key()
    messagebox.showinfo("Key Generated", "A new encryption key has been generated and saved.")

# Set up the GUI
root = tk.Tk()
root.title("Encryption and Decryption")

# Set a background color for the window
root.configure(bg="#f0f0f0")

# Message Entry
tk.Label(root, text="Message:", bg="#f0f0f0", font=('Arial', 12)).grid(row=0, column=0, padx=10, pady=10)
entry_message = tk.Entry(root, width=50, font=('Arial', 12))
entry_message.grid(row=0, column=1, padx=10, pady=10)

# Result Display
result_var = tk.StringVar()
tk.Label(root, text="Result:", bg="#f0f0f0", font=('Arial', 12)).grid(row=1, column=0, padx=10, pady=10)
entry_result = tk.Entry(root, textvariable=result_var, width=50, font=('Arial', 12), state='readonly')
entry_result.grid(row=1, column=1, padx=10, pady=10)

# Buttons with custom colors
btn_encrypt = tk.Button(root, text="Encrypt", command=encrypt_message, bg="#4CAF50", fg="white", font=('Arial', 12))
btn_encrypt.grid(row=2, column=0, padx=10, pady=10)

btn_decrypt = tk.Button(root, text="Decrypt", command=decrypt_message, bg="#f44336", fg="white", font=('Arial', 12))
btn_decrypt.grid(row=2, column=1, padx=10, pady=10)

btn_generate_key = tk.Button(root, text="Generate Key", command=generate_key_and_notify, bg="#2196F3", fg="white", font=('Arial', 12))
btn_generate_key.grid(row=3, column=0, columnspan=2, pady=10)

# Set a minimum size for the window and center it
root.update_idletasks()
width = root.winfo_width()
height = root.winfo_height()
x = (root.winfo_screenwidth() // 2) - (width // 2)
y = (root.winfo_screenheight() // 2) - (height // 2)
root.geometry(f"{width}x{height}+{x}+{y}")
root.minsize(width, height)

# Run the GUI loop
root.mainloop()

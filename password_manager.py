# --- Password Generation & Encyption Program ---

import tkinter as tk
from tkinter import messagebox
import secrets
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json

# --- Password Functions ---

def generate_password(length=16, include_uppercase=True, include_digits=True, include_symbols=True):
    """Generates a random password."""

    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_digits:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation

    password = ''.join(secrets.choice(characters)
 for i in range(length))
    return password

def encrypt_password(password, master_password):
    """Encrypts the password using the master password."""

    # Generate a salt
    salt = secrets.token_bytes(16)

    # Derive the encryption key from the master password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


    # Encrypt the password
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())

    return salt, encrypted_password

def decrypt_password(encrypted_password, master_password, salt):
    """Decrypts the password using the master password and salt."""

    # Derive the encryption key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


    # Decrypt the password
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()

    return decrypted_password

# --- GUI Functions ---

def generate_and_display_password():
    """Generates a password and displays it in the password_entry field."""
    new_password = generate_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, new_password)

def save_password():
    """Saves the website, username, and encrypted password to a JSON file."""
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    master_password = master_password_entry.get()

    if not all([website, username, password, master_password]):
        messagebox.showerror("Error", "Please fill all fields.")
        return

    salt, encrypted_pwd = encrypt_password(password, master_password)

    try:
        with open("passwords.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    data[website] = {"username": username, "salt": base64.b64encode(salt).decode(), "encrypted_password": base64.b64encode(encrypted_pwd).decode()}

    with open("passwords.json", "w") as f:
        json.dump(data, f, indent=4)

    messagebox.showinfo("Success", "Password saved!")
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    master_password_entry.delete(0, tk.END)

def get_password():
    """Retrieves and decrypts the password for the given website."""
    website = website_entry.get()
    master_password = master_password_entry.get()

    if not all([website, master_password]):
        messagebox.showerror("Error", "Please enter website and master password.")
        return

    try:
        with open("passwords.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        messagebox.showerror("Error", "Password file not found.")
        return

    if website not in data:
        messagebox.showerror("Error", "No password found for this website.")
        return

    salt = base64.b64decode(data[website]["salt"].encode())
    encrypted_pwd = base64.b64decode(data[website]["encrypted_password"].encode())
    try:
        decrypted_pwd = decrypt_password(encrypted_pwd, master_password, salt)
    except cryptography.fernet.InvalidToken:
        messagebox.showerror("Error", "Incorrect master password.")
        return

    messagebox.showinfo("Password", f"Password for {website}: {decrypted_pwd}")

# --- GUI Setup ---

window = tk.Tk()
window.title("Password Manager")

website_label = tk.Label(window, text="Website:")
website_label.grid(row=0, column=0, padx=5, pady=5)
website_entry = tk.Entry(window)
website_entry.grid(row=0, column=1, padx=5, pady=5)

username_label = tk.Label(window, text="Username:")
username_label.grid(row=1, column=0, padx=5, pady=5)
username_entry = tk.Entry(window)
username_entry.grid(row=1, column=1, padx=5, pady=5)

password_label = tk.Label(window, text="Password:")
password_label.grid(row=2, column=0, padx=5, pady=5)
password_entry = tk.Entry(window, show="*")
password_entry.grid(row=2, column=1, padx=5, pady=5)

master_password_label = tk.Label(window, text="Master Password:")
master_password_label.grid(row=3, column=0, padx=5, pady=5)
master_password_entry = tk.Entry(window, show="*")
master_password_entry.grid(row=3, column=1, padx=5, pady=5)

generate_button = tk.Button(window, text="Generate Password", command=generate_and_display_password)
generate_button.grid(row=2, column=2, padx=5, pady=5)

save_button = tk.Button(window, text="Save Password Information", command=save_password)
save_button.grid(row=4, column=1, padx=5, pady=5)

get_button = tk.Button(window, text="Get Password", command=get_password)
get_button.grid(row=4, column=2, padx=5, pady=5)

window.mainloop()

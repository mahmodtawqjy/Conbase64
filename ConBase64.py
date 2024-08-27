import base64
import tkinter as tk
from tkinter import messagebox


# Function to encrypt a password
def encrypt_password(password):
    encoded_bytes = base64.b64encode(password.encode())
    return encoded_bytes.decode()


# Function to decrypt an encoded password
def decrypt_password(encoded_password):
    decoded_bytes = base64.b64decode(encoded_password.encode())
    return decoded_bytes.decode()


# Event handler for the "Encrypt" button
def on_encrypt_button_click():
    password = password_entry.get()
    encrypted_password = encrypt_password(password)
    result_label.config(
        text=f"{encrypted_password}",
        bg="#0C2D57",
        fg="#ffffff",
        font=("Arial", 10),
    )


# Event handler for the "Decrypt" button
def on_decrypt_button_click():
    base64_string = base64_entry.get()
    try:
        decrypted_password = decrypt_password(base64_string)
        result_label.config(
            text=f"{decrypted_password.split(':')[-1].strip()}",
            bg="#0C2D57",
            fg="#ffffff",
            font=("Arial", 10),
        )
    except Exception as e:
        messagebox.showerror(
            "Error",
            f"Error decoding base64: {str(e)}",
        )


# Event handler for the "Copy Result" button
def on_copy_button_click():
    result = result_label.cget("text")
    root.clipboard_clear()
    root.clipboard_append(result)


# Event handler for the "Close" button
def on_close_button_click():
    root.destroy()


# Create the main application window
root = tk.Tk()
root.title("ConBase64")
root.geometry("500x300")  # Set window dimensions
root.resizable(0, 0)  # Disable window resizing
root.configure(bg="#0C2D57")  # background color

# Create UI elements
password_label = tk.Label(
    root, text="Enter Password:", bg="#0C2D57", fg="#ffffff", font=("Arial", 10)
)
password_entry = tk.Entry(root, bg="#F6F5F2")
password_label.pack(pady=1)
password_entry.pack()

encrypt_button = tk.Button(
    root, text="Encrypt", command=on_encrypt_button_click, bg="#64CCC5", padx=10
)
encrypt_button.pack(pady=5)

base64_label = tk.Label(
    root, text="Enter Base64 String:", bg="#0C2D57", fg="#ffffff", font=("Arial", 10)
)
base64_entry = tk.Entry(root, bg="#F6F5F2")
base64_label.pack(pady=1)
base64_entry.pack()

decrypt_button = tk.Button(
    root, text="Decrypt", command=on_decrypt_button_click, bg="#64CCC5", padx=10
)
decrypt_button.pack(pady=5)

result_label = tk.Label(root, text="")
result_label.pack()

copy_button = tk.Button(
    root,
    text="Copy",
    command=on_copy_button_click,
    bg="#64CCC5",
    padx=10,
)
copy_button.pack(pady=3)

close_button = tk.Button(
    root, text="Close", command=on_close_button_click, bg="#64CCC5", padx=10
)
close_button.pack(pady=3)

# Start the application event loop
root.mainloop()

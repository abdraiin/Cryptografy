import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class AESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Kriptografi")
        self.root.geometry("1000x600")
        self.root.configure(bg="#ffffff")

        # Inisialisasi kunci otomatis
        self.key = get_random_bytes(32)  # 32-byte key untuk AES-256

        # Heading
        title = tk.Label(
            root,
            text="AES Kriptografi",
            font=("Helvetica", 20, "bold"),
            fg="#4da6ff",  # Light blue color
            pady=20,
            bg="#ffffff",
            relief="flat",
        )
        title.pack(fill="x")

        # Informasi Key
        key_label = tk.Label(root, text=f"Generated Key: {base64.b64encode(self.key).decode()}", font=("Helvetica", 10), fg="#000000", bg="#ffffff", wraplength=800)
        key_label.pack(pady=10, padx=30, anchor="w")

        # Input Frames
        tk.Label(root, text="Plaintext:", font=("Helvetica", 12), fg="#000000", bg="#ffffff").pack(anchor="w", padx=30)
        self.plaintext_entry = tk.Text(root, width=80, height=5, font=("Helvetica", 10), bg="#f0f0f0", fg="#000000", bd=0, wrap="word")
        self.plaintext_entry.pack(padx=30, pady=5, fill="x")

        # Encrypted Text Output
        tk.Label(root, text="Encrypted Text:", font=("Helvetica", 12), fg="#000000", bg="#ffffff").pack(anchor="w", padx=30)
        self.encrypted_text = tk.Text(root, width=80, height=5, font=("Helvetica", 10), state="disabled", bg="#f0f0f0", fg="#000000", bd=0)
        self.encrypted_text.pack(padx=30, pady=5, fill="x")

        # Decrypted Text Output
        tk.Label(root, text="Decrypted Text:", font=("Helvetica", 12), fg="#000000", bg="#ffffff").pack(anchor="w", padx=30)
        self.decrypted_text = tk.Text(root, width=80, height=5, font=("Helvetica", 10), state="disabled", bg="#f0f0f0", fg="#000000", bd=0)
        self.decrypted_text.pack(padx=30, pady=5, fill="x")

        # Buttons Frame
        button_frame = tk.Frame(root, bg="#ffffff")
        button_frame.pack(pady=20)
        encrypt_button = tk.Button(button_frame, text="Encrypt", font=("Helvetica", 10, "bold"), bg="#0078d7", fg="white", width=15, height=1, relief="flat", command=self.encrypt)
        encrypt_button.grid(row=0, column=0, padx=10)
        decrypt_button = tk.Button(button_frame, text="Decrypt", font=("Helvetica", 10, "bold"), bg="#28a745", fg="white", width=15, height=1, relief="flat", command=self.decrypt)
        decrypt_button.grid(row=0, column=1, padx=10)

    def encrypt(self):
        try:
            plaintext = self.plaintext_entry.get("1.0", tk.END).strip()

            if not plaintext:
                raise ValueError("Plaintext cannot be empty.")

            cipher = AES.new(self.key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
            encrypted = base64.b64encode(cipher.iv + ciphertext).decode()

            self.encrypted_text.config(state="normal")
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert(tk.END, encrypted)
            self.encrypted_text.config(state="disabled")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption error: {e}")

    def decrypt(self):
        try:
            encrypted_text = self.encrypted_text.get("1.0", tk.END).strip()

            if not encrypted_text:
                raise ValueError("No encrypted text to decrypt.")

            data = base64.b64decode(encrypted_text)
            iv, ciphertext = data[:16], data[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

            self.decrypted_text.config(state="normal")
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, plaintext)
            self.decrypted_text.config(state="disabled")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()

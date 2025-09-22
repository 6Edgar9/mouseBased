import tkinter as tk
import random
import string
import json
import base64
import os
import pyperclip  # Copiar al portapapeles
from tkinter import ttk, simpledialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

MAX_MOVEMENTS = 500  # Movimientos para generar la clave
PASSWORD_LENGTH = 30  # Longitud de la contraseña
SALT = b"random_salt_value"  # Sal para PBKDF2
PASSWORDS_FILE = "passwords.json"
MASTER_KEY_FILE = "master_key.json"
MAX_ATTEMPTS = 3  # Límite de intentos

def derive_key(master_password):
    return PBKDF2(master_password, SALT, dkLen=32, count=100000)

def encrypt_master_key(master_password):
    key = derive_key(master_password)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(master_password.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + encrypted).decode()

def decrypt_master_key(encrypted_key, master_password):
    key = derive_key(master_password)
    data = base64.b64decode(encrypted_key)
    iv = data[:AES.block_size]
    ciphertext = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

def verify_master_password():
    """Verifica la clave maestra con un límite de intentos."""
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        if os.path.exists(MASTER_KEY_FILE):
            with open(MASTER_KEY_FILE, "r") as file:
                stored_key = json.load(file)["master_key"]

            master_password = simpledialog.askstring("Clave Maestra", f"Ingreso {attempts+1}/{MAX_ATTEMPTS}: Ingresa tu clave maestra:", show='*')
            if not master_password:
                exit(0)

            try:
                decrypted_key = decrypt_master_key(stored_key, master_password)
                if decrypted_key == master_password:
                    return master_password
            except:
                attempts += 1
                messagebox.showerror("Error", f"Clave maestra incorrecta. Intentos restantes: {MAX_ATTEMPTS - attempts}")

        else:
            master_password = simpledialog.askstring("Configurar Clave Maestra", "Crea una clave maestra:", show='*')
            if not master_password:
                exit(0)
            
            encrypted_key = encrypt_master_key(master_password)
            with open(MASTER_KEY_FILE, "w") as file:
                json.dump({"master_key": encrypted_key}, file)

            messagebox.showinfo("Clave Creada", "Clave maestra configurada correctamente.")
            return master_password

    messagebox.showerror("Bloqueado", "Demasiados intentos fallidos. Bloqueando acceso.")
    exit(0)

class MousePasswordGenerator:
    def __init__(self, root, master_password):
        self.root = root
        self.root.title("Gestor de Contraseñas Seguras")
        self.master_password = master_password
        self.reset_generator()
        
        self.label = tk.Label(root, text="Mueve el mouse para generar una contraseña segura.", font=("Arial", 12))
        self.label.pack(pady=10)

        self.progress = ttk.Progressbar(root, length=300, mode='determinate', maximum=MAX_MOVEMENTS)
        self.progress.pack(pady=10)

        self.password_label = tk.Label(root, text="", font=("Arial", 14, "bold"), fg="blue")
        self.password_label.pack(pady=10)

        self.copy_button = tk.Button(root, text="Copiar Contraseña", command=self.copy_password, state=tk.DISABLED)
        self.copy_button.pack(pady=5)

        self.save_button = tk.Button(root, text="Guardar Contraseña", command=self.save_password, state=tk.DISABLED)
        self.save_button.pack(pady=5)

        self.view_button = tk.Button(root, text="Ver Contraseñas Guardadas", command=self.view_passwords)
        self.view_button.pack(pady=5)

        self.new_password_button = tk.Button(root, text="Generar Nueva Contraseña", command=self.reset_generator)
        self.new_password_button.pack(pady=5)

        self.root.bind('<Motion>', self.track_mouse)

    def copy_password(self):
        """Copia la contraseña generada al portapapeles."""
        if self.password:
            pyperclip.copy(self.password)
            self.copy_button.config(text="¡Copiada!", state=tk.DISABLED)

    def reset_generator(self):
        self.movements = 0
        self.random_data = ""
        self.password = ""
        if hasattr(self, 'progress'):
            self.progress['value'] = 0
        if hasattr(self, 'password_label'):
            self.password_label.config(text="")
        if hasattr(self, 'copy_button'):
            self.copy_button.config(state=tk.DISABLED, text="Copiar Contraseña")
        if hasattr(self, 'save_button'):
            self.save_button.config(state=tk.DISABLED)

    def track_mouse(self, event):
        if self.movements < MAX_MOVEMENTS:
            data = f"{event.x}{event.y}{random.randint(0, 9999)}"
            self.random_data += data
            self.movements += 1
            self.progress['value'] = self.movements

        if self.movements >= MAX_MOVEMENTS and not self.password:
            self.generate_password()

    def generate_password(self):
        derived_key = PBKDF2(self.random_data, SALT, dkLen=64, count=100000)
        self.password = ''.join(random.choices(base64.b64encode(derived_key).decode('utf-8') + string.ascii_letters + string.digits + "!@#$%^&*()", k=PASSWORD_LENGTH))
        self.password_label.config(text="Contraseña generada.")
        self.copy_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)

    def encrypt_password(self, password, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(password.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext).decode()

    def decrypt_password(self, encrypted_password, key):
        data = base64.b64decode(encrypted_password)
        iv = data[:AES.block_size]
        ciphertext = data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    def save_password(self):
        key = derive_key(self.master_password)
        title = simpledialog.askstring("Guardar Contraseña", "Ingresa un título para esta contraseña:")
        if not title:
            return

        encrypted_password = self.encrypt_password(self.password, key)

        try:
            with open(PASSWORDS_FILE, "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {}
        
        data[title] = encrypted_password
        with open(PASSWORDS_FILE, "w") as file:
            json.dump(data, file, indent=4)
        
        messagebox.showinfo("Guardado", "Contraseña guardada correctamente.")

    def view_passwords(self):
        key = derive_key(self.master_password)
        try:
            with open(PASSWORDS_FILE, "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            messagebox.showerror("Error", "No hay contraseñas guardadas.")
            return

        passwords_text = ""
        for title, encrypted_password in data.items():
            try:
                decrypted_password = self.decrypt_password(encrypted_password, key)
                passwords_text += f"{title}: {decrypted_password}\n"
            except:
                passwords_text += f"{title}: [ERROR AL DESCIFRAR]\n"

        messagebox.showinfo("Contraseñas Guardadas", passwords_text if passwords_text else "No hay contraseñas disponibles.")

if __name__ == "__main__":
    master_password = verify_master_password()
    root = tk.Tk()
    app = MousePasswordGenerator(root, master_password)
    master_password = None
    root.mainloop()

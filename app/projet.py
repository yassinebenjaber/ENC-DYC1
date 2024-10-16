
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import time
import base64
import pyperclip

class EncryptionApplication:
    def __init__(self):
        self.backend = default_backend()
        self.file_key = self.generate_key()  # Key for file encryption
        self.text_key = self.generate_key()  # Key for text encryption
        self.algorithm_var = None

    def setup_gui_variables(self, algorithm_var):
        self.algorithm_var = algorithm_var

    def generate_key(self, key_size=32):
        if key_size not in {16, 24, 32}:
            raise ValueError("Invalid key size. Supported sizes are 16, 24, or 32 bytes.")
        return base64.urlsafe_b64encode(Fernet.generate_key()[:key_size])

    def generate_iv(self):
        return os.urandom(16)

    def get_algorithm(self):
        if self.algorithm_var is None:
            raise ValueError("Encryption algorithm not selected")
        algorithm_name = self.algorithm_var.get()
        if algorithm_name == "AES":
            return algorithms.AES
        elif algorithm_name == "DES3":
            return algorithms.TripleDES
        else:
            raise ValueError("Unsupported algorithm")

    def encrypt_text(self, text):
        if not self.algorithm_var:
            raise ValueError("Encryption algorithm not selected")
        
        f = Fernet(self.text_key)
        encrypted_text_bytes = f.encrypt(text.encode())
        return encrypted_text_bytes

    def decrypt_text(self, encrypted_text):
        f = Fernet(self.text_key)
        decrypted_text = f.decrypt(encrypted_text).decode()
        return decrypted_text

    def encrypt_file(self, file_path):
        if not self.algorithm_var:
            raise ValueError("Encryption algorithm not selected")
        
        iv = self.generate_iv()
        algorithm = self.get_algorithm()
        cipher = Fernet(self.file_key)
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_file_data = cipher.encrypt(file_data)

        # Save the encrypted data to a new file
        encrypted_file_path = file_path + ".encrypted"
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(iv + encrypted_file_data)

        return encrypted_file_path

    def decrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                data = file.read()
            if len(data) < 16:
                raise ValueError("Invalid file format")
            iv = data[:16]
            encrypted_file_data = data[16:]
            cipher = Fernet(self.file_key)
            decrypted_file_data = cipher.decrypt(encrypted_file_data)
            return decrypted_file_data
        except Exception as e:
            print(f"Error during file decryption: {str(e)}")
            raise e

    def brute_force_attack(self, encrypted_text, key):
        start_time = time.time()
        success = False
        try:
            f = Fernet(key)
            decrypted_text = f.decrypt(encrypted_text).decode()
            success = True
        except Exception as e:
            pass  # Incorrect key, decryption failed
        end_time = time.time()
        elapsed_time = end_time - start_time
        return success, elapsed_time

class AppGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Encryption Application")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.create_widgets()

    def create_widgets(self):
        self.algorithm_var = tk.StringVar()
        self.test_type_var = tk.StringVar()

        self.text_entry_label = ttk.Label(self.master, text="Enter text:")
        self.text_entry_label.grid(row=0, column=0, pady=10, padx=10, sticky="w")

        self.text_entry = ttk.Entry(self.master, width=50)
        self.text_entry.grid(row=0, column=1, pady=10, padx=10, sticky="w")

        self.encrypt_button = ttk.Button(self.master, text="Encrypt Text", command=self.encrypt_text)
        self.encrypt_button.grid(row=1, column=0, pady=10, padx=10, sticky="w")

        self.decrypt_button = ttk.Button(self.master, text="Decrypt Text", command=self.decrypt_text)
        self.decrypt_button.grid(row=1, column=1, pady=10, padx=10, sticky="w")

        self.file_path_label = ttk.Label(self.master, text="Select file:")
        self.file_path_label.grid(row=2, column=0, pady=10, padx=10, sticky="w")

        self.file_path_entry = ttk.Entry(self.master, width=50, state='disabled')
        self.file_path_entry.grid(row=2, column=1, pady=10, padx=10, sticky="w")

        self.browse_button = ttk.Button(self.master, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=3, column=0, pady=10, padx=10, sticky="w")

        self.encrypt_file_button = ttk.Button(self.master, text="Encrypt File", command=self.encrypt_file)
        self.encrypt_file_button.grid(row=3, column=1, pady=10, padx=10, sticky="w")

        self.decrypt_file_button = ttk.Button(self.master, text="Decrypt File", command=self.decrypt_file)
        self.decrypt_file_button.grid(row=4, column=0, columnspan=2, pady=10, padx=10, sticky="w")

        self.security_test_button = ttk.Button(self.master, text="Perform Security Tests", command=self.perform_security_tests)
        self.security_test_button.grid(row=5, column=0, columnspan=2, pady=10, padx=10, sticky="w")

        self.algorithm_label = ttk.Label(self.master, text="Encryption Algorithm:")
        self.algorithm_label.grid(row=6, column=0, pady=10, padx=10, sticky="w")

        self.algorithm_combobox = ttk.Combobox(self.master, values=["AES", "DES3"], state="readonly", textvariable=self.algorithm_var)
        self.algorithm_combobox.grid(row=6, column=1, pady=10, padx=10, sticky="w")

        self.test_type_label = ttk.Label(self.master, text="Select Test Type:")
        self.test_type_label.grid(row=7, column=0, pady=10, padx=10, sticky="w")

        self.test_type_combobox = ttk.Combobox(self.master, values=["Brute Force", "Sensitivity"], state="readonly", textvariable=self.test_type_var)
        self.test_type_combobox.grid(row=7, column=1, pady=10, padx=10, sticky="w")

    def encrypt_text(self):
        text = self.text_entry.get()
        if not self.algorithm_var.get():
            messagebox.showerror("Error", "Please select an encryption algorithm.")
            return

        app.setup_gui_variables(self.algorithm_var)
        encrypted_text_bytes = app.encrypt_text(text)
        encrypted_text_str = base64.b64encode(encrypted_text_bytes).decode('utf-8')
        pyperclip.copy(str(encrypted_text_str))
        messagebox.showinfo("Encrypted Text", f"Encrypted Text:\n{encrypted_text_str}\n\nCopied to clipboard!")

    def decrypt_text(self):
        encrypted_text = self.text_entry.get()
        if not self.algorithm_var.get():
            messagebox.showerror("Error", "Please select an encryption algorithm.")
            return

        app.setup_gui_variables(self.algorithm_var)
        decrypted_text = app.decrypt_text(base64.b64decode(encrypted_text.encode()))
        messagebox.showinfo("Decrypted Text", f"Decrypted Text:\n{decrypted_text}")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_entry.config(state='normal')
        self.file_path_entry.delete(0, 'end')
        self.file_path_entry.insert(0, file_path)
        self.file_path_entry.config(state='disabled')

    def encrypt_file(self):
        file_path = self.file_path_entry.get()
        if not self.algorithm_var.get():
            messagebox.showerror("Error", "Please select an encryption algorithm.")
            return

        try:
            app.setup_gui_variables(self.algorithm_var)
            encrypted_file_path = app.encrypt_file(file_path)
            messagebox.showinfo("Encryption", f"File encrypted successfully! Encrypted file saved at:\n{encrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error during file encryption: {str(e)}")

    def decrypt_file(self):
        file_path = self.file_path_entry.get()
        if not self.algorithm_var.get():
            messagebox.showerror("Error", "Please select an encryption algorithm.")
            return

        try:
            app.setup_gui_variables(self.algorithm_var)
            decrypted_file_data = app.decrypt_file(file_path)
            decrypted_file_path = file_path.rstrip('.encrypted') + "_decrypted.txt"
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_file_data)
            messagebox.showinfo("Decryption", f"File decrypted successfully! Decrypted file saved at:\n{decrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Error during file decryption: {str(e)}")

    def perform_security_tests(self):
        text = self.text_entry.get()
        if not self.algorithm_var.get():
            messagebox.showerror("Error", "Please select an encryption algorithm.")
            return

        app.setup_gui_variables(self.algorithm_var)
        encrypted_text_bytes = app.encrypt_text(text)

        test_type = self.test_type_var.get()

        if test_type == "Brute Force":
            key = app.text_key
            success, elapsed_time = app.brute_force_attack(encrypted_text_bytes, key)
            if success:
                messagebox.showwarning("Security Test", "Brute force attack successful!\nDecryption succeeded.")
            else:
                messagebox.showinfo("Security Test", f"Brute force attack unsuccessful.\nElapsed Time: {elapsed_time:.6f} seconds.")
        elif test_type == "Sensitivity":
            key_lengths = [16, 24, 32]
            for key_length in key_lengths:
                key = app.generate_key(key_length)
                success, elapsed_time = app.brute_force_attack(encrypted_text_bytes, key)
                if success:
                    messagebox.showwarning("Security Test", f"Sensitivity test successful!\nKey Length: {key_length} bytes\nDecryption succeeded.")
                else:
                    messagebox.showinfo("Security Test", f"Sensitivity test unsuccessful.\nKey Length: {key_length} bytes\nElapsed Time: {elapsed_time:.6f} seconds.")
        else:
            messagebox.showerror("Error", "Invalid test type selected.")

if __name__ == "__main__":
    app = EncryptionApplication()
    root = tk.Tk()
    gui = AppGUI(root)
    root.mainloop()
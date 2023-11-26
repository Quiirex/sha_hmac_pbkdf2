import tkinter as tk
from tkinter import filedialog, messagebox
import secrets
import hashlib
import struct


class StorePassword:
    def generate_salt(self, byte_len=64):
        return secrets.token_urlsafe(byte_len)

    def sha_with_salt(self, mode, password, salt):
        return mode((password + salt).encode()).hexdigest()


class HMAC:
    def __init__(self, key: bytes, message=None, mode=None):
        # Assign the mode to messageDigest directly
        self.messageDigest = mode

        # Initialize input and output message digests
        self.input = self.messageDigest()
        self.output = self.messageDigest()

        # Get block size
        self.block_size = self.input.block_size

        # If key length is greater than block size, digest it
        if len(key) > self.block_size:
            key = self.messageDigest(key).digest()

        # Pad key to block size with null bytes
        key = key.ljust(self.block_size, b"\0")

        # Define ipad and opad constants
        self.ipad = 0x36
        self.opad = 0x5C

        # Compute input and output signatures
        self.input_signature = bytes((key_byte ^ self.ipad) for key_byte in key)
        self.output_signature = bytes((key_byte ^ self.opad) for key_byte in key)

        # Update input and output with their respective signatures
        self.input.update(self.input_signature)
        self.output.update(self.output_signature)

        # If message is not None, update input with message
        if message is not None:
            self.input.update(message)

    def hexdigest(self):
        # Copy output message digest
        hmac_copy = self.output.copy()

        # Update copy with input digest
        hmac_copy.update(self.input.digest())

        # Return hexadecimal representation of digest
        return hmac_copy.hexdigest()

    def digest(self):
        # Copy output message digest
        hmac_copy = self.output.copy()

        # Update copy with input digest
        hmac_copy.update(self.input.digest())

        # Return digest
        return hmac_copy.digest()


class PBKDF2:
    def __init__(self, mode, password, salt, number_of_iterations, derived_key_length):
        self.mode = mode
        self.password = password
        self.salt = salt
        self.number_of_iterations = number_of_iterations
        self.derived_key_length = derived_key_length

    def pbkdf2_function(self, passwd, salt, count, i):
        result = u = HMAC(passwd, salt + struct.pack(">i", i), self.mode).digest()
        for iteration in range(2, count + 1):
            u = HMAC(passwd, u, self.mode).digest()
            result = bytes(i ^ j for i, j in zip(result, u))
        return result

    def result(self):
        derived_key, hash_length = b"", self.mode().digest_size
        blocks = (self.derived_key_length // hash_length) + (
            1 if self.derived_key_length % hash_length else 0
        )
        for block in range(1, blocks + 1):
            derived_key += self.pbkdf2_function(
                self.password, self.salt, self.number_of_iterations, block
            )
        return derived_key[: self.derived_key_length].hex()


class GUI:
    def __init__(self, root):
        self.root = root
        root.title("SHA-256/512 hashing, HMAC, PBKDF2")

        self.algorithm_options = ["SHA-256", "SHA-512"]
        self.mode_options = ["Store password", "HMAC", "PBKDF2"]

        self.selected_algorithm = tk.StringVar()
        self.selected_algorithm.set(self.algorithm_options[0])

        self.selected_mode = tk.StringVar()
        self.selected_mode.set(self.mode_options[0])

        self.main_frame = tk.Frame(root)
        self.main_frame.pack(padx=10, pady=10)

        tk.Label(self.main_frame, text="Algorithm:").grid(row=0, column=0, padx=10)
        self.algorithm_menu = tk.OptionMenu(
            self.main_frame, self.selected_algorithm, *self.algorithm_options
        )
        self.algorithm_menu.config(width=10)
        self.algorithm_menu.grid(row=0, column=1, sticky="w")

        tk.Label(self.main_frame, text="Mode:").grid(row=1, column=0, padx=10)
        self.mode_menu = tk.OptionMenu(
            self.main_frame, self.selected_mode, *self.mode_options
        )
        self.mode_menu.config(width=10)
        self.mode_menu.grid(row=1, column=1, sticky="w")

        tk.Label(self.main_frame, text="Password:").grid(row=2, column=0, padx=10)
        self.pass_input = tk.Entry(self.main_frame, width=41)
        self.pass_input.grid(row=2, column=1)

        tk.Label(self.main_frame, text="Salt:").grid(row=3, column=0, padx=10)
        self.salt_input = tk.Entry(self.main_frame, width=41)
        self.salt_input.grid(row=3, column=1)
        tk.Button(
            self.main_frame, text="Generate salt", command=self.generate_salt, width=8
        ).grid(row=3, column=2)

        tk.Label(self.main_frame, text="Key:").grid(row=4, column=0, padx=10)
        self.key_input = tk.Entry(self.main_frame, width=41)
        self.key_input.grid(row=4, column=1)
        tk.Button(
            self.main_frame, text="Generate key", command=self.generate_key, width=8
        ).grid(row=4, column=2)

        tk.Label(self.main_frame, text="Output:").grid(row=5, column=0, padx=10)
        self.output_text = tk.Text(self.main_frame, width=53, height=4)
        self.output_text.grid(row=5, column=1)
        self.output_text.config(state=tk.DISABLED)

        self.save_grid = tk.Frame(self.main_frame)
        self.save_grid.grid(row=5, column=2)

        tk.Button(
            self.save_grid, text="Save output", command=self.save_output, width=8
        ).grid(row=0, column=0)
        tk.Button(self.save_grid, text="Save key", command=self.save_key, width=8).grid(
            row=1, column=0
        )

        tk.Button(self.main_frame, text="Process", command=self.process_inputs).grid(
            row=6, column=0
        )

    def generate_salt(self):
        self.salt_input.delete(0, tk.END)
        self.salt_input.insert(tk.END, secrets.token_urlsafe(32))

    def generate_key(self):
        self.key_input.delete(0, tk.END)
        self.key_input.insert(tk.END, secrets.token_urlsafe(32))

    def process_inputs(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)

        selected_algorithm = self.selected_algorithm.get()
        selected_mode = self.selected_mode.get()

        if selected_mode == "Store password":
            print("----------------------------------------")
            print(f"Selected hashing algorithm: {selected_algorithm}")
            print(f"Selected mode: {selected_mode}")
            print("Processing..")
            salt = self.salt_input.get()
            password = self.pass_input.get()

            store_password = StorePassword()
            if selected_algorithm == "SHA-256":
                result = store_password.sha_with_salt(hashlib.sha256, password, salt)
            elif selected_algorithm == "SHA-512":
                result = store_password.sha_with_salt(hashlib.sha512, password, salt)
            self.output_text.insert(tk.END, result + "\n")
            print("Done")

        elif selected_mode == "HMAC":
            print("----------------------------------------")
            print(f"Selected hashing algorithm: {selected_algorithm}")
            print(f"Selected mode: {selected_mode}")
            print("Processing..")
            key = self.key_input.get().encode("utf-8")
            password = self.pass_input.get().encode("utf-8")

            if selected_algorithm == "SHA-256":
                result = HMAC(key, password, hashlib.sha256)
            elif selected_algorithm == "SHA-512":
                result = HMAC(key, password, hashlib.sha512)
            self.output_text.insert(tk.END, result.hexdigest() + "\n")
            print("Done")

        elif selected_mode == "PBKDF2":
            print("----------------------------------------")
            print(f"Selected hashing algorithm: {selected_algorithm}")
            print(f"Selected mode: {selected_mode}")
            print("Processing..")
            salt = self.salt_input.get().encode("utf-8")
            password = self.pass_input.get().encode("utf-8")

            if selected_algorithm == "SHA-256":
                result = PBKDF2(hashlib.sha256, password, salt, 31000, 32)
            elif selected_algorithm == "SHA-512":
                result = PBKDF2(hashlib.sha512, password, salt, 12000, 64)
            self.output_text.insert(tk.END, result.result() + "\n")
            print("Done")

    def save_output(self):
        content = self.output_text.get("1.0", tk.END).strip()
        if content:
            self.save_to_file(content)
        else:
            messagebox.showinfo("No Output", "No output to save!")

    def save_key(self):
        content = self.key_input.get().strip()
        if content:
            self.save_to_file(content)
        else:
            messagebox.showinfo("No Key", "No key to save!")

    def save_to_file(self, content):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if file_path:
            with open(file_path, "w") as file:
                file.write(content)


if __name__ == "__main__":
    root = tk.Tk()
    gui = GUI(root)
    root.mainloop()

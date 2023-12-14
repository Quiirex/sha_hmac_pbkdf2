import tkinter as tk
from tkinter import filedialog, messagebox
import secrets
import hashlib
import struct


class PS:
    @staticmethod
    def hash_password_with_salt(password, salt, hash_function):
        return hash_function((password + salt).encode()).hexdigest()


class HMAC:
    def __init__(self, key, message, hash_function):
        self.key = key
        self.message = message
        self.hash_function = hash_function
        self.block_size = hash_function().block_size
        self.padded_key = self._pad_key(self.key)

    def _pad_key(self, key):
        if len(key) > self.block_size:
            key = self.hash_function(key).digest()
        key += b"\x00" * (self.block_size - len(key))
        return key

    def _generate(self):
        o_key_pad = bytes([x ^ 0x5C for x in self.padded_key])
        i_key_pad = bytes([x ^ 0x36 for x in self.padded_key])
        return self.hash_function(
            o_key_pad + self.hash_function(i_key_pad + self.message).digest()
        )

    def generate_and_hexdigest(self):
        return self._generate().hexdigest()

    def generate_and_digest(self):
        return self._generate().digest()


class PBKDF2:
    def __init__(self, password, salt, hash_function, iterations, derived_key_length):
        self.password = password
        self.salt = salt
        self.hash_function = hash_function
        self.derived_key_length = derived_key_length
        self.iterations = iterations

    def generate_key(self):
        digest_size = self.hash_function().digest_size
        block_length = -(-self.derived_key_length // digest_size)
        remaining_length = self.derived_key_length - (block_length - 1) * digest_size

        key = b""
        for block_index in range(1, block_length + 1):
            key += self._generate_block(block_index, self.iterations)
        return key[: self.derived_key_length].hex()

    def _generate_block(self, block_index, iterations):
        hmac_result = HMAC(
            self.password,
            self.salt + block_index.to_bytes(4),
            self.hash_function,
        ).generate_and_digest()

        result = bytearray(hmac_result)

        for iteration_index in range(2, iterations + 1):
            hmac_result = HMAC(
                self.password, hmac_result, self.hash_function
            ).generate_and_digest()

            for byte_index in range(len(result)):
                result[byte_index] ^= hmac_result[byte_index]

        return bytes(result)


class GUI:
    def __init__(self, root):
        self.root = root
        root.title("SHA-256/512 hashing, HMAC, PBKDF2")

        self.algorithm_options = ["SHA-256", "SHA-512"]
        self.mode_options = ["Password Store", "HMAC", "PBKDF2"]

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

        tk.Label(self.main_frame, text="Message:").grid(row=2, column=0, padx=10)
        self.message_input = tk.Entry(self.main_frame, width=50)
        self.message_input.grid(row=2, column=1)

        tk.Label(self.main_frame, text="Password:").grid(row=3, column=0, padx=10)
        self.pass_input = tk.Entry(self.main_frame, width=50)
        self.pass_input.grid(row=3, column=1)

        tk.Label(self.main_frame, text="Salt:").grid(row=4, column=0, padx=10)
        self.salt_input = tk.Entry(self.main_frame, width=50)
        self.salt_input.grid(row=4, column=1)
        tk.Button(
            self.main_frame, text="Generate salt", command=self.generate_salt, width=8
        ).grid(row=4, column=2)

        tk.Label(self.main_frame, text="Key:").grid(row=5, column=0, padx=10)
        self.key_input = tk.Entry(self.main_frame, width=50)
        self.key_input.grid(row=5, column=1)
        tk.Button(
            self.main_frame, text="Generate key", command=self.generate_key, width=8
        ).grid(row=5, column=2)

        tk.Label(self.main_frame, text="Output:").grid(row=6, column=0, padx=10)
        self.output_text = tk.Text(self.main_frame, width=65, height=4)
        self.output_text.grid(row=6, column=1)
        self.output_text.config(state=tk.DISABLED)

        tk.Button(self.main_frame, text="Process", command=self.process_inputs).grid(
            row=7, column=0
        )

    def generate_salt(self):
        self.salt_input.delete(0, tk.END)
        self.salt_input.insert(tk.END, secrets.token_urlsafe(64))

    def generate_key(self):
        self.key_input.delete(0, tk.END)
        self.key_input.insert(tk.END, secrets.token_urlsafe(64))

    def process_inputs(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)

        selected_algorithm = self.selected_algorithm.get()
        selected_mode = self.selected_mode.get()

        if selected_mode == "Password Store":
            print("----------------------------------------")
            print(f"Selected hashing algorithm: {selected_algorithm}")
            print(f"Selected mode: {selected_mode}")
            print("Processing..")
            salt = self.salt_input.get()
            password = self.pass_input.get()

            if not salt or not password:
                messagebox.showerror("Error", "Salt and password cannot be empty!")
                return

            hash_function = getattr(
                hashlib, selected_algorithm.lower().replace("-", "")
            )
            result = PS.hash_password_with_salt(password, salt, hash_function)
            self.output_text.insert(tk.END, result + "\n")
            print("Done")

        elif selected_mode == "HMAC":
            print("----------------------------------------")
            print(f"Selected hashing algorithm: {selected_algorithm}")
            print(f"Selected mode: {selected_mode}")
            print("Processing..")
            key = self.key_input.get().encode("utf-8")
            message = self.message_input.get().encode("utf-8")

            if not key or not message:
                messagebox.showerror("Error", "Key and message cannot be empty!")
                return

            hash_function = getattr(
                hashlib, selected_algorithm.lower().replace("-", "")
            )
            result = HMAC(key, message, hash_function).generate_and_hexdigest()
            self.output_text.insert(tk.END, result + "\n")
            print("Done")

        elif selected_mode == "PBKDF2":
            print("----------------------------------------")
            print(f"Selected hashing algorithm: {selected_algorithm}")
            print(f"Selected mode: {selected_mode}")
            print("Processing..")
            salt = self.salt_input.get().encode("utf-8")
            password = self.pass_input.get().encode("utf-8")

            if not salt or not password:
                messagebox.showerror("Error", "Salt and password cannot be empty!")
                return

            hash_function = getattr(
                hashlib, selected_algorithm.lower().replace("-", "")
            )
            iterations = 600000 if hash_function == hashlib.sha256 else 210000
            derived_key_length = 32 if hash_function == hashlib.sha256 else 64
            result = PBKDF2(
                password, salt, hash_function, iterations, derived_key_length
            ).generate_key()
            self.output_text.insert(tk.END, result + "\n")
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

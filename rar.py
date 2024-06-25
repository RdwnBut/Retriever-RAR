import os
import subprocess
import string
import tkinter as tk
from tkinter import filedialog, Text, Scrollbar, Button, Label, Entry, messagebox, IntVar, Checkbutton, Toplevel
import threading
import itertools

class PasswordRetrieverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RAR Password Retriever")
        self.root.geometry("600x400")

        self.file_path = None
        self.unrar_path = r"C:\Program Files\WinRAR\UnRAR.exe"
        self.password_threads = []
        self.cancel_event = threading.Event()

        # Main frame
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        # File selection
        self.file_label = Label(self.main_frame, text="Select RAR File:")
        self.file_label.grid(row=0, column=0, sticky=tk.W)

        self.file_path_entry = Entry(self.main_frame, width=50)
        self.file_path_entry.grid(row=0, column=1, padx=10, pady=5)

        self.browse_button = Button(self.main_frame, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=10)

        # Password options
        self.password_options_frame = tk.LabelFrame(self.main_frame, text="Password Options")
        self.password_options_frame.grid(row=1, column=0, columnspan=3, padx=10, pady=(20, 10), sticky=tk.W)

        self.alpha_var = tk.IntVar(value=1)
        self.num_var = tk.IntVar(value=0)
        self.space_var = tk.IntVar(value=0)

        self.alpha_check = tk.Checkbutton(self.password_options_frame, text="Alphabet", variable=self.alpha_var, onvalue=1, offvalue=0)
        self.alpha_check.grid(row=0, column=0, sticky=tk.W)

        self.num_check = tk.Checkbutton(self.password_options_frame, text="Numeric", variable=self.num_var, onvalue=1, offvalue=0)
        self.num_check.grid(row=1, column=0, sticky=tk.W)

        self.space_check = tk.Checkbutton(self.password_options_frame, text="Space", variable=self.space_var, onvalue=1, offvalue=0)
        self.space_check.grid(row=2, column=0, sticky=tk.W)

        # Password length selection
        self.password_length_label = Label(self.main_frame, text="Password Length Range:")
        self.password_length_label.grid(row=2, column=0, pady=(20, 10), sticky=tk.W)

        self.password_length_min_entry = Entry(self.main_frame, width=5)
        self.password_length_min_entry.insert(tk.END, "3")
        self.password_length_min_entry.grid(row=2, column=1, padx=(0, 10), pady=(20, 10))

        self.password_length_max_entry = Entry(self.main_frame, width=5)
        self.password_length_max_entry.insert(tk.END, "6")
        self.password_length_max_entry.grid(row=2, column=2, pady=(20, 10))

        # Retrieve button
        self.retrieve_button = Button(self.main_frame, text="Retrieve Password", command=self.start_password_retrieval)
        self.retrieve_button.grid(row=3, column=0, columnspan=3, pady=(20, 10))

        # Cancel button
        self.cancel_button = Button(self.main_frame, text="Cancel", command=self.cancel_password_retrieval)
        self.cancel_button.grid(row=4, column=0, columnspan=3, pady=(10, 20))

        # Passwords tried display
        self.tried_passwords_label = Label(self.main_frame, text="Tried Passwords:")
        self.tried_passwords_label.grid(row=5, column=0, pady=(20, 10), sticky=tk.W)

        self.tried_passwords_text = Text(self.main_frame, wrap='none', height=10)
        self.tried_passwords_text.grid(row=6, column=0, columnspan=3, padx=(0, 10), pady=(0, 20), sticky=tk.NSEW)

        scrollbar_y = Scrollbar(self.main_frame, command=self.tried_passwords_text.yview)
        scrollbar_y.grid(row=6, column=3, sticky=tk.NS)
        self.tried_passwords_text.config(yscrollcommand=scrollbar_y.set)

        scrollbar_x = Scrollbar(self.main_frame, orient='horizontal', command=self.tried_passwords_text.xview)
        scrollbar_x.grid(row=7, column=0, columnspan=3, sticky=tk.EW)
        self.tried_passwords_text.config(xscrollcommand=scrollbar_x.set)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("RAR files", "*.rar")])
        if self.file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(tk.END, self.file_path)

    def start_password_retrieval(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a RAR file first.")
            return

        try:
            min_length = int(self.password_length_min_entry.get())
            max_length = int(self.password_length_max_entry.get())
            if min_length <= 0 or max_length <= 0:
                messagebox.showerror("Error", "Password length must be a positive integer.")
                return
            if min_length > max_length:
                messagebox.showerror("Error", "Minimum password length cannot be greater than maximum.")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid input for password length.")
            return

        # Clear previous tried passwords
        self.tried_passwords_text.delete('1.0', tk.END)

        # Create a thread for password retrieval
        password_thread = threading.Thread(target=self.retrieve_password,
                                           args=(min_length, max_length))
        self.password_threads.append(password_thread)
        password_thread.start()

    def cancel_password_retrieval(self):
        self.cancel_event.set()
        self.tried_passwords_text.insert(tk.END, "Password retrieval cancelled.\n")

    def retrieve_password(self, min_length, max_length):
        temp_dir = os.path.join(os.path.expanduser('~'), 'RAR_TEMP')
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        try:
            if self.alpha_var.get() == 1 and self.num_var.get() == 0 and self.space_var.get() == 0:
                passwords = self.generate_alpha_passwords(min_length, max_length)
            elif self.alpha_var.get() == 0 and self.num_var.get() == 1 and self.space_var.get() == 0:
                passwords = self.generate_numeric_passwords(min_length, max_length)
            elif self.alpha_var.get() == 0 and self.num_var.get() == 0 and self.space_var.get() == 1:
                passwords = self.generate_space_passwords(min_length, max_length)
            elif self.alpha_var.get() == 1 and self.num_var.get() == 1 and self.space_var.get() == 0:
                passwords = self.generate_alpha_numeric_passwords(min_length, max_length)
            elif self.alpha_var.get() == 1 and self.num_var.get() == 0 and self.space_var.get() == 1:
                passwords = self.generate_alpha_space_passwords(min_length, max_length)
            elif self.alpha_var.get() == 0 and self.num_var.get() == 1 and self.space_var.get() == 1:
                passwords = self.generate_numeric_space_passwords(min_length, max_length)
            elif self.alpha_var.get() == 1 and self.num_var.get() == 1 and self.space_var.get() == 1:
                passwords = self.generate_alpha_numeric_space_passwords(min_length, max_length)
            else:
                messagebox.showerror("Error", "Please select at least one password option.")
                return

            for pass_guess in passwords:
                if self.cancel_event.is_set():
                    self.tried_passwords_text.insert(tk.END, "Password retrieval cancelled.\n")
                    return

                result = subprocess.run([self.unrar_path, 'e', '-inul', f'-p{pass_guess}', self.file_path, temp_dir],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode == 0:
                    self.show_password_found(pass_guess)
                    return
                else:
                    self.display_tried_password(pass_guess)
        except FileNotFoundError:
            messagebox.showerror("Error", f"UnRAR executable not found at {self.unrar_path}. Please ensure the path is correct.")
        finally:
            self.cleanup(temp_dir)

    def generate_alpha_passwords(self, min_length, max_length):
        return (''.join(combination) for length in range(min_length, max_length + 1)
                for combination in itertools.product(string.ascii_lowercase, repeat=length))

    def generate_numeric_passwords(self, min_length, max_length):
        return (''.join(combination) for length in range(min_length, max_length + 1)
                for combination in itertools.product(string.digits, repeat=length))

    def generate_space_passwords(self, min_length, max_length):
        return (''.join(combination) for length in range(min_length, max_length + 1)
                for combination in itertools.product(' ', repeat=length))

    def generate_alpha_numeric_passwords(self, min_length, max_length):
        return (''.join(combination) for length in range(min_length, max_length + 1)
                for combination in itertools.product(string.ascii_lowercase + string.digits, repeat=length))

    def generate_alpha_space_passwords(self, min_length, max_length):
        return (''.join(combination) for length in range(min_length, max_length + 1)
                for combination in itertools.product(string.ascii_lowercase + ' ', repeat=length))

    def generate_numeric_space_passwords(self, min_length, max_length):
        return (''.join(combination) for length in range(min_length, max_length + 1)
                for combination in itertools.product(string.digits + ' ', repeat=length))

    def generate_alpha_numeric_space_passwords(self, min_length, max_length):
        return (''.join(combination) for length in range(min_length, max_length + 1)
                for combination in itertools.product(string.ascii_lowercase + string.digits + ' ', repeat=length))

    def display_tried_password(self, password):
        self.tried_passwords_text.insert(tk.END, f"Tried Password: {password}\n")
        self.tried_passwords_text.see(tk.END)

    def show_password_found(self, password):
        password_found_window = tk.Toplevel(self.root)
        password_found_window.title("Password Found")
        password_found_window.geometry("300x100")
        label = tk.Label(password_found_window, text=f"The password is: {password}")
        label.pack(padx=20, pady=20)

    def cleanup(self, temp_dir):
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordRetrieverApp(root)
    root.mainloop()

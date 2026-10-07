import os
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk
from cryptography.exceptions import InvalidTag

from file_manager import (
    encrypt_file,
    decrypt_file,
    calculate_file_sha256
)

from database import (
    init_database,
    create_user,
    get_user_by_login,
    get_user_by_id,
    save_vault_file,
    get_vault_owner,
    mark_user_verified
)

from auth_manager import (
    hash_password,
    verify_password
)

from otp_manager import (
    send_otp,
    verify_otp
)


# =========================================================
# CUSTOMTKINTER SETTINGS
# =========================================================

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


# =========================================================
# MAIN APPLICATION
# =========================================================

class SecureFileVaultApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        init_database()

        self.title("Secure File Vault")
        self.geometry("1050x900")
        self.minsize(900, 760)

        self.current_user = None
        self.selected_file = ""
        self.last_output_path = ""
        self.password_visible = False

        self.show_login_screen()

    # =====================================================
    # COMMON HELPERS
    # =====================================================

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def set_status(self, message, status_type="normal"):
        if hasattr(self, "status_label"):
            prefixes = {
                "normal": "●",
                "working": "●",
                "success": "✓",
                "error": "✗"
            }

            self.status_label.configure(
                text=f"{prefixes.get(status_type, '●')}  {message}"
            )

    def change_appearance(self, mode):
        ctk.set_appearance_mode(mode)

    def show_message(self, title, message):
        messagebox.showinfo(title, message)

    # =====================================================
    # LOGIN SCREEN
    # =====================================================

    def show_login_screen(self):
        self.clear_window()

        self.geometry("650x650")
        self.minsize(560, 600)

        self.login_frame = ctk.CTkFrame(
            self,
            corner_radius=20
        )
        self.login_frame.pack(
            padx=50,
            pady=50,
            fill="both",
            expand=True
        )

        ctk.CTkLabel(
            self.login_frame,
            text="🔐 SECURE FILE VAULT",
            font=ctk.CTkFont(
                size=30,
                weight="bold"
            )
        ).pack(pady=(45, 5))

        ctk.CTkLabel(
            self.login_frame,
            text="AES-256-GCM + SHA-256",
            font=ctk.CTkFont(size=16)
        ).pack(pady=(0, 30))

        ctk.CTkLabel(
            self.login_frame,
            text="Login",
            font=ctk.CTkFont(
                size=22,
                weight="bold"
            )
        ).pack(pady=(5, 15))

        self.login_value_entry = ctk.CTkEntry(
            self.login_frame,
            width=400,
            height=42,
            placeholder_text="Email address or mobile number"
        )
        self.login_value_entry.pack(pady=8)

        self.login_password_entry = ctk.CTkEntry(
            self.login_frame,
            width=400,
            height=42,
            show="*",
            placeholder_text="Account password"
        )
        self.login_password_entry.pack(pady=8)

        self.login_button = ctk.CTkButton(
            self.login_frame,
            text="Login",
            width=250,
            height=45,
            command=self.login
        )
        self.login_button.pack(pady=(20, 8))

        self.register_button = ctk.CTkButton(
            self.login_frame,
            text="Create New Account",
            width=250,
            height=42,
            fg_color="transparent",
            border_width=1,
            command=self.show_register_screen
        )
        self.register_button.pack(pady=5)

        ctk.CTkButton(
            self.login_frame,
            text="Appearance",
            width=120,
            command=lambda: self.show_appearance_menu()
        ).pack(pady=(20, 5))

        ctk.CTkLabel(
            self.login_frame,
            text=(
                "Login verification uses an OTP sent to your "
                "registered email or mobile number."
            ),
            wraplength=430,
            justify="center"
        ).pack(pady=15)

    # =====================================================
    # APPEARANCE MENU
    # =====================================================

    def show_appearance_menu(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Appearance")
        dialog.geometry("300x230")
        dialog.resizable(False, False)

        ctk.CTkLabel(
            dialog,
            text="Choose Appearance",
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            )
        ).pack(pady=(25, 15))

        for mode in ["System", "Light", "Dark"]:
            ctk.CTkButton(
                dialog,
                text=mode,
                width=180,
                command=lambda m=mode: (
                    self.change_appearance(m),
                    dialog.destroy()
                )
            ).pack(pady=5)

    # =====================================================
    # REGISTER SCREEN
    # =====================================================

    def show_register_screen(self):
        self.clear_window()

        self.geometry("700x780")
        self.minsize(600, 700)

        frame = ctk.CTkFrame(
            self,
            corner_radius=20
        )
        frame.pack(
            padx=45,
            pady=35,
            fill="both",
            expand=True
        )

        ctk.CTkLabel(
            frame,
            text="Create Account",
            font=ctk.CTkFont(
                size=28,
                weight="bold"
            )
        ).pack(pady=(30, 20))

        self.reg_name = ctk.CTkEntry(
            frame,
            width=430,
            height=40,
            placeholder_text="Full name"
        )
        self.reg_name.pack(pady=7)

        self.reg_email = ctk.CTkEntry(
            frame,
            width=430,
            height=40,
            placeholder_text="Email address"
        )
        self.reg_email.pack(pady=7)

        self.reg_mobile = ctk.CTkEntry(
            frame,
            width=430,
            height=40,
            placeholder_text="Mobile number, optional"
        )
        self.reg_mobile.pack(pady=7)

        self.reg_password = ctk.CTkEntry(
            frame,
            width=430,
            height=40,
            show="*",
            placeholder_text="Account password"
        )
        self.reg_password.pack(pady=7)

        self.reg_confirm = ctk.CTkEntry(
            frame,
            width=430,
            height=40,
            show="*",
            placeholder_text="Confirm account password"
        )
        self.reg_confirm.pack(pady=7)

        ctk.CTkLabel(
            frame,
            text="OTP delivery method"
        ).pack(pady=(15, 5))

        self.reg_method = ctk.CTkOptionMenu(
            frame,
            values=["Email", "SMS"],
            width=220
        )
        self.reg_method.pack(pady=5)

        ctk.CTkButton(
            frame,
            text="Register & Send OTP",
            width=260,
            height=45,
            command=self.register_user
        ).pack(pady=(20, 8))

        ctk.CTkButton(
            frame,
            text="Back to Login",
            width=220,
            fg_color="transparent",
            border_width=1,
            command=self.show_login_screen
        ).pack(pady=5)

        ctk.CTkLabel(
            frame,
            text=(
                "At least one verified contact method is required. "
                "Email is the default method."
            ),
            wraplength=480,
            justify="center"
        ).pack(pady=15)

    # =====================================================
    # REGISTER USER
    # =====================================================

    def register_user(self):
        name = self.reg_name.get().strip()
        email = self.reg_email.get().strip().lower()
        mobile = self.reg_mobile.get().strip()
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()

        if not name:
            messagebox.showwarning(
                "Registration",
                "Please enter your name."
            )
            return

        if not email and not mobile:
            messagebox.showwarning(
                "Registration",
                "Enter at least an email address or mobile number."
            )
            return

        if email and "@" not in email:
            messagebox.showwarning(
                "Registration",
                "Please enter a valid email address."
            )
            return

        if len(password) < 8:
            messagebox.showwarning(
                "Registration",
                "Account password must contain at least 8 characters."
            )
            return

        if password != confirm:
            messagebox.showwarning(
                "Registration",
                "Passwords do not match."
            )
            return

        method = self.reg_method.get().lower()

        if method == "email" and not email:
            messagebox.showwarning(
                "Registration",
                "Email OTP requires an email address."
            )
            return

        if method == "sms" and not mobile:
            messagebox.showwarning(
                "Registration",
                "SMS OTP requires a mobile number."
            )
            return

        password_hash, password_salt = hash_password(password)

        user_id = create_user(
            name,
            email,
            mobile,
            password_hash,
            password_salt
        )

        if user_id is None:
            messagebox.showerror(
                "Registration Failed",
                "An account with this email or mobile number "
                "already exists."
            )
            return

        destination = (
            email
            if method == "email"
            else mobile
        )

        result = send_otp(
            user_id,
            method,
            destination,
            "registration"
        )

        if not result["success"]:
            messagebox.showerror(
                "OTP Error",
                result["message"]
            )
            return

        self.show_otp_screen(
            user_id=user_id,
            method=method,
            purpose="registration",
            destination=destination,
            next_action="login"
        )

        if result["demo_otp"]:
            self.demo_otp = result["demo_otp"]
        else:
            self.demo_otp = None

    # =====================================================
    # OTP SCREEN
    # =====================================================

    def show_otp_screen(
        self,
        user_id,
        method,
        purpose,
        destination,
        next_action="login"
    ):
        self.clear_window()

        self.geometry("650x600")
        self.minsize(560, 550)

        self.otp_user_id = user_id
        self.otp_method = method
        self.otp_purpose = purpose
        self.otp_destination = destination
        self.otp_next_action = next_action

        frame = ctk.CTkFrame(
            self,
            corner_radius=20
        )
        frame.pack(
            padx=50,
            pady=50,
            fill="both",
            expand=True
        )

        ctk.CTkLabel(
            frame,
            text="OTP Verification",
            font=ctk.CTkFont(
                size=28,
                weight="bold"
            )
        ).pack(pady=(40, 10))

        masked = destination

        if method == "email" and "@" in destination:
            parts = destination.split("@")
            local = parts[0]
            masked = (
                (local[:2] + "***")
                + "@"
                + parts[1]
            )
        elif method == "sms" and len(destination) > 4:
            masked = "***" + destination[-4:]

        ctk.CTkLabel(
            frame,
            text=f"OTP sent using {method.upper()} to:\n{masked}",
            justify="center"
        ).pack(pady=10)

        self.otp_entry = ctk.CTkEntry(
            frame,
            width=260,
            height=45,
            placeholder_text="Enter 6-digit OTP"
        )
        self.otp_entry.pack(pady=20)

        ctk.CTkButton(
            frame,
            text="Verify OTP",
            width=240,
            height=45,
            command=self.verify_current_otp
        ).pack(pady=8)

        ctk.CTkButton(
            frame,
            text="Resend OTP",
            width=220,
            fg_color="transparent",
            border_width=1,
            command=self.resend_current_otp
        ).pack(pady=8)

        ctk.CTkButton(
            frame,
            text="Cancel",
            width=160,
            fg_color="transparent",
            command=self.show_login_screen
        ).pack(pady=8)

        if getattr(self, "demo_otp", None):
            ctk.CTkLabel(
                frame,
                text=(
                    "DEMO MODE OTP: "
                    + self.demo_otp
                ),
                font=ctk.CTkFont(
                    size=15,
                    weight="bold"
                )
            ).pack(pady=(15, 5))

    def verify_current_otp(self):
        entered = self.otp_entry.get().strip()

        if not entered:
            messagebox.showwarning(
                "OTP",
                "Please enter the OTP."
            )
            return

        valid, message = verify_otp(
            self.otp_user_id,
            self.otp_purpose,
            self.otp_method,
            entered
        )

        if not valid:
            messagebox.showerror(
                "OTP Verification",
                message
            )
            return

        mark_user_verified(
            self.otp_user_id,
            self.otp_method
        )

        if self.otp_purpose == "registration":
            messagebox.showinfo(
                "Registration Successful",
                "Your account has been created and verified."
            )
            self.show_login_screen()
            return

        if self.otp_purpose == "login":
            self.current_user = get_user_by_id(
                self.otp_user_id
            )

            if not self.current_user:
                messagebox.showerror(
                    "Login",
                    "User account could not be loaded."
                )
                self.show_login_screen()
                return

            self.show_main_application()

    def resend_current_otp(self):
        result = send_otp(
            self.otp_user_id,
            self.otp_method,
            self.otp_destination,
            self.otp_purpose
        )

        if not result["success"]:
            messagebox.showwarning(
                "Resend OTP",
                result["message"]
            )
            return

        self.demo_otp = result["demo_otp"]

        if self.demo_otp:
            messagebox.showinfo(
                "OTP",
                "DEMO OTP: " + self.demo_otp
            )
        else:
            messagebox.showinfo(
                "OTP",
                "A new OTP has been sent."
            )

    # =====================================================
    # LOGIN
    # =====================================================

    def login(self):
        login_value = self.login_value_entry.get().strip().lower()
        password = self.login_password_entry.get()

        if not login_value or not password:
            messagebox.showwarning(
                "Login",
                "Enter your email/mobile and password."
            )
            return

        user = get_user_by_login(login_value)

        if not user:
            messagebox.showerror(
                "Login Failed",
                "Invalid login credentials."
            )
            return

        if not verify_password(
            password,
            user["password_hash"],
            user["password_salt"]
        ):
            messagebox.showerror(
                "Login Failed",
                "Invalid login credentials."
            )
            return

        if user["email"] and user["email_verified"]:
            method = "email"
            destination = user["email"]

        elif user["mobile"] and user["mobile_verified"]:
            method = "sms"
            destination = user["mobile"]

        elif user["email"]:
            method = "email"
            destination = user["email"]

        elif user["mobile"]:
            method = "sms"
            destination = user["mobile"]

        else:
            messagebox.showerror(
                "Login",
                "No verified contact method is available."
            )
            return

        result = send_otp(
            user["id"],
            method,
            destination,
            "login"
        )

        if not result["success"]:
            messagebox.showwarning(
                "OTP",
                result["message"]
            )
            return

        self.demo_otp = result["demo_otp"]

        self.show_otp_screen(
            user_id=user["id"],
            method=method,
            purpose="login",
            destination=destination,
            next_action="dashboard"
        )

    # =====================================================
    # MAIN APPLICATION
    # =====================================================

    def show_main_application(self):
        self.clear_window()

        self.geometry("1050x900")
        self.minsize(900, 760)

        self.selected_file = ""
        self.last_output_path = ""
        self.password_visible = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # =================================================
        # HEADER
        # =================================================

        self.header_frame = ctk.CTkFrame(
            self,
            corner_radius=0,
            fg_color="transparent"
        )
        self.header_frame.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=30,
            pady=(20, 5)
        )

        self.header_frame.grid_columnconfigure(0, weight=1)

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="🔐  SECURE FILE VAULT",
            font=ctk.CTkFont(
                size=32,
                weight="bold"
            )
        )
        self.title_label.grid(
            row=0,
            column=0,
            pady=(0, 3)
        )

        user_text = (
            f"Logged in as: {self.current_user['name']}  |  "
            f"User ID: {self.current_user['id']}"
        )

        ctk.CTkLabel(
            self.header_frame,
            text=user_text,
            font=ctk.CTkFont(size=14)
        ).grid(
            row=1,
            column=0
        )

        self.appearance_menu = ctk.CTkOptionMenu(
            self.header_frame,
            values=["System", "Light", "Dark"],
            command=self.change_appearance,
            width=130
        )
        self.appearance_menu.set("System")
        self.appearance_menu.grid(
            row=0,
            column=1,
            rowspan=2,
            padx=(15, 0)
        )

        ctk.CTkButton(
            self.header_frame,
            text="Logout",
            width=100,
            command=self.logout
        ).grid(
            row=0,
            column=2,
            rowspan=2,
            padx=(10, 0)
        )

        # =================================================
        # SCROLLABLE CONTENT
        # =================================================

        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            corner_radius=15
        )
        self.scroll_frame.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=30,
            pady=(5, 25)
        )

        self.scroll_frame.grid_columnconfigure(0, weight=1)

        self.build_file_section()
        self.build_password_section()
        self.build_operation_section()
        self.build_result_section()
        self.build_security_section()
        self.build_how_it_works_section()
        self.build_about_section()

        self.set_status(
            "Ready.",
            "normal"
        )

    # =====================================================
    # FILE SECTION
    # =====================================================

    def build_file_section(self):
        card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=15
        )
        card.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=8,
            pady=8
        )
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text="1. FILE SELECTION",
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            )
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=20,
            pady=(18, 10)
        )

        row = ctk.CTkFrame(
            card,
            fg_color="transparent"
        )
        row.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=20
        )
        row.grid_columnconfigure(0, weight=1)

        self.file_entry = ctk.CTkEntry(
            row,
            height=42,
            placeholder_text="Choose a file..."
        )
        self.file_entry.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=(0, 10)
        )

        ctk.CTkButton(
            row,
            text="Browse",
            width=120,
            height=42,
            command=self.browse_file
        ).grid(
            row=0,
            column=1
        )

        self.file_info_label = ctk.CTkLabel(
            card,
            text="No file selected.",
            justify="left",
            anchor="w"
        )
        self.file_info_label.grid(
            row=2,
            column=0,
            sticky="ew",
            padx=20,
            pady=(10, 18)
        )

    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select a file"
        )

        if not file_path:
            return

        self.selected_file = file_path

        self.file_entry.delete(0, "end")
        self.file_entry.insert(0, file_path)

        try:
            size = os.path.getsize(file_path)

            if size < 1024:
                size_text = f"{size} bytes"
            elif size < 1024 * 1024:
                size_text = f"{size / 1024:.2f} KB"
            else:
                size_text = f"{size / (1024 * 1024):.2f} MB"

            file_name = os.path.basename(file_path)

            self.file_info_label.configure(
                text=(
                    f"Name: {file_name}\n"
                    f"Size: {size_text}\n"
                    f"Location: {os.path.dirname(file_path)}"
                )
            )

        except Exception:
            self.file_info_label.configure(
                text="File selected."
            )

        self.clear_hash()
        self.set_status(
            "File selected.",
            "normal"
        )

    # =====================================================
    # PASSWORD SECTION
    # =====================================================

    def build_password_section(self):
        card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=15
        )
        card.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=8,
            pady=8
        )
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text="2. FILE PASSWORD",
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            )
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=20,
            pady=(18, 10)
        )

        row = ctk.CTkFrame(
            card,
            fg_color="transparent"
        )
        row.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=20
        )
        row.grid_columnconfigure(0, weight=1)

        self.password_entry = ctk.CTkEntry(
            row,
            height=42,
            show="*",
            placeholder_text="Enter file encryption/decryption password"
        )
        self.password_entry.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=(0, 10)
        )

        self.password_button = ctk.CTkButton(
            row,
            text="Show",
            width=90,
            height=42,
            command=self.toggle_password
        )
        self.password_button.grid(
            row=0,
            column=1
        )

        ctk.CTkLabel(
            card,
            text=(
                "This password is used by the existing AES-256-GCM "
                "file encryption system. It is not stored in the database."
            ),
            wraplength=800,
            justify="left"
        ).grid(
            row=2,
            column=0,
            sticky="w",
            padx=20,
            pady=(8, 18)
        )

    def toggle_password(self):
        self.password_visible = not self.password_visible

        if self.password_visible:
            self.password_entry.configure(show="")
            self.password_button.configure(text="Hide")
        else:
            self.password_entry.configure(show="*")
            self.password_button.configure(text="Show")

    def get_password(self):
        password = self.password_entry.get()

        if not password:
            messagebox.showwarning(
                "Password Required",
                "Please enter a file password."
            )
            return None

        return password

    # =====================================================
    # OPERATION SECTION
    # =====================================================

    def build_operation_section(self):
        card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=15
        )
        card.grid(
            row=2,
            column=0,
            sticky="ew",
            padx=8,
            pady=8
        )

        ctk.CTkLabel(
            card,
            text="3. OPERATIONS",
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(18, 10)
        )

        row = ctk.CTkFrame(
            card,
            fg_color="transparent"
        )
        row.pack(
            pady=(0, 18)
        )

        self.encrypt_button = ctk.CTkButton(
            row,
            text="🔐  Encrypt File",
            width=190,
            height=48,
            command=self.encrypt_selected_file
        )
        self.encrypt_button.pack(
            side="left",
            padx=8
        )

        self.decrypt_button = ctk.CTkButton(
            row,
            text="🔓  Decrypt File",
            width=190,
            height=48,
            command=self.decrypt_selected_file
        )
        self.decrypt_button.pack(
            side="left",
            padx=8
        )

        ctk.CTkButton(
            row,
            text="Clear",
            width=120,
            height=48,
            fg_color="transparent",
            border_width=1,
            command=self.clear_all
        ).pack(
            side="left",
            padx=8
        )

        self.progress_bar = ctk.CTkProgressBar(
            card,
            mode="indeterminate",
            height=8
        )
        self.progress_bar.pack(
            fill="x",
            padx=20,
            pady=(0, 18)
        )
        self.progress_bar.set(0)

    # =====================================================
    # ENCRYPT
    # =====================================================

    def encrypt_selected_file(self):
        file_path = self.file_entry.get().strip()

        if not file_path:
            messagebox.showwarning(
                "File Required",
                "Please select a file first."
            )
            return

        if not os.path.isfile(file_path):
            messagebox.showerror(
                "File Not Found",
                "The selected file does not exist."
            )
            return

        if file_path.lower().endswith(".vault"):
            messagebox.showwarning(
                "Invalid File",
                "This file is already a Secure File Vault file."
            )
            return

        password = self.get_password()

        if password is None:
            return

        try:
            self.progress_bar.start()
            self.set_status(
                "Encrypting file...",
                "working"
            )
            self.update()

            vault_path, original_hash = encrypt_file(
                file_path,
                password
            )

            self.show_hash(original_hash)

            save_vault_file(
                self.current_user["id"],
                os.path.basename(file_path),
                os.path.abspath(vault_path),
                original_hash
            )

            self.last_output_path = vault_path

            self.set_status(
                "File encrypted successfully.",
                "success"
            )

            messagebox.showinfo(
                "Encryption Successful",
                "File encrypted successfully!\n\n"
                f"Vault file:\n{vault_path}\n\n"
                "The vault has been registered to the "
                "currently logged-in user."
            )

        except Exception as error:
            self.set_status(
                "Encryption failed.",
                "error"
            )

            messagebox.showerror(
                "Encryption Error",
                f"Could not encrypt the file.\n\n{error}"
            )

        finally:
            self.progress_bar.stop()

    # =====================================================
    # DECRYPT
    # =====================================================

    def decrypt_selected_file(self):
        file_path = self.file_entry.get().strip()

        if not file_path:
            messagebox.showwarning(
                "File Required",
                "Please select a .vault file."
            )
            return

        if not os.path.isfile(file_path):
            messagebox.showerror(
                "File Not Found",
                "The selected file does not exist."
            )
            return

        if not file_path.lower().endswith(".vault"):
            messagebox.showwarning(
                "Invalid File",
                "Please select a .vault file for decryption."
            )
            return

        password = self.get_password()

        if password is None:
            return

        try:
            owner = get_vault_owner(
                os.path.abspath(file_path)
            )

            if owner and owner["user_id"] != self.current_user["id"]:
                messagebox.showerror(
                    "Access Denied",
                    "This vault belongs to another user account."
                )
                return

            self.progress_bar.start()
            self.set_status(
                "Decrypting file...",
                "working"
            )
            self.update()

            decrypted_path, original_hash = decrypt_file(
                file_path,
                password
            )

            decrypted_hash = calculate_file_sha256(
                decrypted_path
            )

            self.show_hash(decrypted_hash)
            self.last_output_path = decrypted_path

            if decrypted_hash == original_hash:
                self.set_status(
                    "Decryption successful. Integrity verified.",
                    "success"
                )

                messagebox.showinfo(
                    "Decryption Successful",
                    "File decrypted successfully!\n\n"
                    f"Decrypted file:\n{decrypted_path}\n\n"
                    "SHA-256 integrity verification PASSED."
                )

            else:
                self.set_status(
                    "Integrity verification failed.",
                    "error"
                )

                messagebox.showerror(
                    "Integrity Error",
                    "The file was decrypted, but the SHA-256 "
                    "hash does not match the original."
                )

        except InvalidTag:
            self.set_status(
                "Decryption failed: wrong password or tampering detected.",
                "error"
            )

            messagebox.showerror(
                "Decryption Failed",
                "AES-256-GCM rejected the vault.\n\n"
                "Possible reasons:\n"
                "• Wrong password\n"
                "• Vault file was modified\n"
                "• Encrypted data was tampered with"
            )

        except Exception as error:
            self.set_status(
                "Decryption failed.",
                "error"
            )

            messagebox.showerror(
                "Decryption Failed",
                "The file could not be decrypted.\n\n"
                f"Details: {error}"
            )

        finally:
            self.progress_bar.stop()

    # =====================================================
    # RESULT SECTION
    # =====================================================

    def build_result_section(self):
        card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=15
        )
        card.grid(
            row=3,
            column=0,
            sticky="ew",
            padx=8,
            pady=8
        )
        card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card,
            text="4. RESULTS",
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            )
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=20,
            pady=(18, 10)
        )

        self.hash_entry = ctk.CTkEntry(
            card,
            height=42,
            placeholder_text="SHA-256 hash will appear here"
        )
        self.hash_entry.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=20,
            pady=5
        )

        ctk.CTkButton(
            card,
            text="Copy SHA-256",
            width=140,
            command=self.copy_hash
        ).grid(
            row=2,
            column=0,
            sticky="w",
            padx=20,
            pady=(5, 8)
        )

        self.output_label = ctk.CTkLabel(
            card,
            text="Output: None",
            justify="left",
            anchor="w"
        )
        self.output_label.grid(
            row=3,
            column=0,
            sticky="ew",
            padx=20,
            pady=(5, 18)
        )

        self.status_label = ctk.CTkLabel(
            card,
            text="●  Ready.",
            font=ctk.CTkFont(
                size=15,
                weight="bold"
            ),
            anchor="w"
        )
        self.status_label.grid(
            row=4,
            column=0,
            sticky="ew",
            padx=20,
            pady=(0, 18)
        )

    def show_hash(self, hash_value):
        self.hash_entry.delete(0, "end")
        self.hash_entry.insert(0, hash_value)

        self.output_label.configure(
            text=f"Output: {self.last_output_path or 'Available after operation'}"
        )

    def copy_hash(self):
        value = self.hash_entry.get().strip()

        if not value:
            messagebox.showwarning(
                "SHA-256",
                "There is no hash to copy yet."
            )
            return

        self.clipboard_clear()
        self.clipboard_append(value)

        self.set_status(
            "SHA-256 copied to clipboard.",
            "success"
        )

    def clear_hash(self):
        if hasattr(self, "hash_entry"):
            self.hash_entry.delete(0, "end")

    def clear_all(self):
        self.selected_file = ""
        self.last_output_path = ""

        if hasattr(self, "file_entry"):
            self.file_entry.delete(0, "end")

        if hasattr(self, "password_entry"):
            self.password_entry.delete(0, "end")

        if hasattr(self, "hash_entry"):
            self.hash_entry.delete(0, "end")

        if hasattr(self, "file_info_label"):
            self.file_info_label.configure(
                text="No file selected."
            )

        if hasattr(self, "output_label"):
            self.output_label.configure(
                text="Output: None"
            )

        self.set_status(
            "Ready.",
            "normal"
        )

    # =====================================================
    # SECURITY INFORMATION
    # =====================================================

    def build_security_section(self):
        card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=15
        )
        card.grid(
            row=4,
            column=0,
            sticky="ew",
            padx=8,
            pady=8
        )

        ctk.CTkLabel(
            card,
            text="5. SECURITY INFORMATION",
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(18, 10)
        )

        text = (
            "✓ AES-256-GCM file encryption\n"
            "✓ PBKDF2-HMAC-SHA256 key derivation\n"
            "✓ 600,000 PBKDF2 iterations\n"
            "✓ Random 16-byte salt\n"
            "✓ Random 12-byte AES-GCM nonce\n"
            "✓ SHA-256 integrity verification\n"
            "✓ Authenticated user accounts\n"
            "✓ OTP-based login verification\n"
            "✓ User-specific vault ownership records"
        )

        ctk.CTkLabel(
            card,
            text=text,
            justify="left",
            anchor="w"
        ).pack(
            fill="x",
            padx=20,
            pady=(0, 18)
        )

    # =====================================================
    # HOW IT WORKS
    # =====================================================

    def build_how_it_works_section(self):
        card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=15
        )
        card.grid(
            row=5,
            column=0,
            sticky="ew",
            padx=8,
            pady=8
        )

        ctk.CTkLabel(
            card,
            text="6. HOW IT WORKS",
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(18, 10)
        )

        text = (
            "LOGIN:\n"
            "Account password → OTP → authenticated user\n\n"
            "ENCRYPTION:\n"
            "File → PBKDF2-HMAC-SHA256 → AES-256-GCM → .vault\n\n"
            "INTEGRITY:\n"
            "Original file → SHA-256 → stored with vault metadata\n\n"
            "DECRYPTION:\n"
            ".vault → AES-256-GCM → restored file → SHA-256 comparison\n\n"
            "TAMPERING:\n"
            "Modified encrypted data → AES-GCM authentication failure"
        )

        ctk.CTkLabel(
            card,
            text=text,
            justify="left",
            anchor="w"
        ).pack(
            fill="x",
            padx=20,
            pady=(0, 18)
        )

    # =====================================================
    # ABOUT
    # =====================================================

    def build_about_section(self):
        card = ctk.CTkFrame(
            self.scroll_frame,
            corner_radius=15
        )
        card.grid(
            row=6,
            column=0,
            sticky="ew",
            padx=8,
            pady=8
        )

        ctk.CTkLabel(
            card,
            text="ABOUT",
            font=ctk.CTkFont(
                size=18,
                weight="bold"
            )
        ).pack(
            anchor="w",
            padx=20,
            pady=(18, 10)
        )

        ctk.CTkLabel(
            card,
            text=(
                "Secure File Vault is a Cryptography and Network Security "
                "project demonstrating AES-256-GCM encryption, PBKDF2 "
                "password-based key derivation, SHA-256 integrity checking, "
                "authenticated user accounts and OTP-based login verification.\n\n"
                "The existing file encryption/decryption backend is retained."
            ),
            wraplength=800,
            justify="left"
        ).pack(
            fill="x",
            padx=20,
            pady=(0, 18)
        )

    # =====================================================
    # LOGOUT
    # =====================================================

    def logout(self):
        self.current_user = None
        self.show_login_screen()


# =========================================================
# START APPLICATION
# =========================================================

if __name__ == "__main__":
    app = SecureFileVaultApp()
    app.mainloop()

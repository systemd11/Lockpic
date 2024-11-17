import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from stegano import lsb

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 500000

# Encryption Functions
def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_message(message, password):
    key, salt = derive_key(password)
    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(nonce + salt + encrypted_message + encryptor.tag).decode()

def decrypt_message(encrypted_message, password):
    encrypted_message = base64.b64decode(encrypted_message)
    nonce = encrypted_message[:NONCE_SIZE]
    salt = encrypted_message[NONCE_SIZE:NONCE_SIZE + SALT_SIZE]
    tag = encrypted_message[-16:]
    encrypted_message = encrypted_message[NONCE_SIZE + SALT_SIZE:-16]
    key, _ = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode()

# App GUI Class
class EncryptionApp(Gtk.Window):
    def __init__(self):
        super().__init__(title="Lockpic")
        self.set_border_width(30)  
        self.set_default_size(600, 450)
        self.set_resizable(False) 

        # Main layout
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)  # Increased spacing
        main_box.set_margin_top(30)  
        main_box.set_margin_bottom(30) 
        main_box.set_margin_start(45) 
        main_box.set_margin_end(45) 
        self.add(main_box)

        # App header label
        header_label = Gtk.Label(label="Lockpic")
        header_label.set_markup("<span size='xx-large' weight='bold'>Lockpic</span>") 
        main_box.pack_start(header_label, False, False, 0)

        # App description
        description_label = Gtk.Label(label="An application to encrypt and decrypt images with hidden messages.")
        main_box.pack_start(description_label, False, False, 0)

        # Encrypt button
        self.encrypt_button = Gtk.Button(label="Encrypt Image")
        self.encrypt_button.set_margin_top(15)  
        self.encrypt_button.set_margin_bottom(15) 
        self.encrypt_button.connect("clicked", self.on_encrypt_clicked)
        main_box.pack_start(self.encrypt_button, True, True, 0)

        # Decrypt button
        self.decrypt_button = Gtk.Button(label="Decrypt Image")
        self.decrypt_button.set_margin_top(15)  
        self.decrypt_button.set_margin_bottom(15) 
        self.decrypt_button.connect("clicked", self.on_decrypt_clicked)
        main_box.pack_start(self.decrypt_button, True, True, 0)

# Reusable Dialog
    def create_dialog(self, title):
        dialog = Gtk.Dialog(title=title, transient_for=self, flags=0)
        dialog.set_modal(True)
        dialog.set_border_width(22)  
        dialog.set_default_size(450, 300)  

        # Content layout for dialog
        content_area = dialog.get_content_area()
        content_area.set_spacing(15)  
        dialog_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15) 
        dialog_box.set_halign(Gtk.Align.CENTER)
        content_area.add(dialog_box)

        # Add labels and input fields
        dialog_box.set_margin_top(15)  
        dialog_box.set_margin_bottom(15)

        return dialog, dialog_box

    def on_encrypt_clicked(self, widget):
        dialog, dialog_box = self.create_dialog("Encrypt Image")

        # File chooser for input file
        file_chooser = Gtk.FileChooserButton(title="Select Image", action=Gtk.FileChooserAction.OPEN)
        dialog_box.pack_start(Gtk.Label(label="Choose Image File:"), False, False, 0)
        dialog_box.pack_start(file_chooser, False, False, 0)

        # Directory chooser
        dir_chooser = Gtk.FileChooserButton(title="Select Directory", action=Gtk.FileChooserAction.SELECT_FOLDER)
        dialog_box.pack_start(Gtk.Label(label="Output Directory:"), False, False, 0)
        dialog_box.pack_start(dir_chooser, False, False, 0)

        # Filename entry
        filename_entry = Gtk.Entry()
        filename_entry.set_text("output_image")  # Default name
        dialog_box.pack_start(Gtk.Label(label="Output Image Name:"), False, False, 0)
        dialog_box.pack_start(filename_entry, False, False, 0)

        # Secret message and password input
        message_entry = Gtk.Entry()
        dialog_box.pack_start(Gtk.Label(label="Secret Message:"), False, False, 0)
        dialog_box.pack_start(message_entry, False, False, 0)

        password_entry = Gtk.Entry()
        password_entry.set_visibility(False)
        dialog_box.pack_start(Gtk.Label(label="Password:"), False, False, 0)
        dialog_box.pack_start(password_entry, False, False, 0)

        # Center buttons at the bottom of the dialog
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=22)
        button_box.set_halign(Gtk.Align.CENTER)

        # Adding Encrypt and Cancel buttons
        encrypt_button = Gtk.Button(label="Encrypt Now")
        encrypt_button.connect("clicked", self.perform_encryption, file_chooser, dir_chooser, filename_entry, message_entry, password_entry)
        button_box.pack_start(encrypt_button, True, True, 0)

        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", lambda w: dialog.destroy())
        button_box.pack_start(cancel_button, True, True, 0)

        dialog_box.pack_start(button_box, False, False, 0)

        dialog.show_all()
        dialog.run()
        dialog.destroy()

    def perform_encryption(self, widget, file_chooser, dir_chooser, filename_entry, message_entry, password_entry):
        input_file = file_chooser.get_filename()
        output_dir = dir_chooser.get_filename()
        filename = filename_entry.get_text()
        message = message_entry.get_text()
        password = password_entry.get_text()

        if not filename.endswith('.png'):
            filename += '.png'

        output_file = os.path.join(output_dir, filename)

        try:
            encrypted_message = encrypt_message(message, password)
            secret_image = lsb.hide(input_file, encrypted_message)
            secret_image.save(output_file)

            success_dialog = Gtk.MessageDialog(
                transient_for=self, flags=0, message_type=Gtk.MessageType.INFO,
                buttons=Gtk.ButtonsType.OK, text="Image Encrypted Successfully!"
            )
            success_dialog.format_secondary_text(f"Encrypted image saved to {output_file}")
            success_dialog.run()
            success_dialog.destroy()

        except Exception as e:
            error_dialog = Gtk.MessageDialog(
                transient_for=self, flags=0, message_type=Gtk.MessageType.ERROR,
                buttons=Gtk.ButtonsType.OK, text="Error during encryption"
            )
            error_dialog.format_secondary_text(str(e))
            error_dialog.run()
            error_dialog.destroy()

    def on_decrypt_clicked(self, widget):
        dialog, dialog_box = self.create_dialog("Decrypt Image")

        # File chooser for encrypted image
        file_chooser = Gtk.FileChooserButton(title="Select Image", action=Gtk.FileChooserAction.OPEN)
        dialog_box.pack_start(Gtk.Label(label="Choose Encrypted Image File:"), False, False, 0)
        dialog_box.pack_start(file_chooser, False, False, 0)

        # Password input
        password_entry = Gtk.Entry()
        password_entry.set_visibility(False)
        dialog_box.pack_start(Gtk.Label(label="Password:"), False, False, 0)
        dialog_box.pack_start(password_entry, False, False, 0)

        # Center buttons at the bottom of the dialog
        button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=22)
        button_box.set_halign(Gtk.Align.CENTER)

        # Adding Decrypt and Cancel buttons
        decrypt_button = Gtk.Button(label="Decrypt Now")
        decrypt_button.connect("clicked", self.perform_decryption, file_chooser, password_entry)
        button_box.pack_start(decrypt_button, True, True, 0)

        cancel_button = Gtk.Button(label="Cancel")
        cancel_button.connect("clicked", lambda w: dialog.destroy())
        button_box.pack_start(cancel_button, True, True, 0)

        dialog_box.pack_start(button_box, False, False, 0)

        dialog.show_all()
        dialog.run()
        dialog.destroy()

    def perform_decryption(self, widget, file_chooser, password_entry):
        input_file = file_chooser.get_filename()
        password = password_entry.get_text()

        try:
            extracted_message = lsb.reveal(input_file)
            decrypted_message = decrypt_message(extracted_message, password)

            result_dialog = Gtk.MessageDialog(
                transient_for=self, flags=0, message_type=Gtk.MessageType.INFO,
                buttons=Gtk.ButtonsType.OK, text="Decrypted Message"
            )
            result_dialog.format_secondary_text(decrypted_message)
            result_dialog.run()
            result_dialog.destroy()

        except Exception as e:
            error_dialog = Gtk.MessageDialog(
                transient_for=self, flags=0, message_type=Gtk.MessageType.ERROR,
                buttons=Gtk.ButtonsType.OK, text="Error during decryption"
            )
            error_dialog.format_secondary_text(str(e))
            error_dialog.run()
            error_dialog.destroy()

# Run the app
if __name__ == "__main__":
    app = EncryptionApp()
    app.connect("destroy", Gtk.main_quit)
    app.show_all()
    Gtk.main()

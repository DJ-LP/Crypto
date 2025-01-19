import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from PIL import Image, ImageDraw, ImageFont

# Globale Schlüsselvariable
key = None
cipher_suite = None

# Funktion: Schlüssel generieren
def generate_key():
    global key, cipher_suite
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    messagebox.showinfo("Key Generated", "A new encryption key has been generated!")

# Funktion: Schlüssel aus Datei laden
def load_key():
    global key, cipher_suite
    filepath = filedialog.askopenfilename(filetypes=[("Key Files", "*.key")])
    if not filepath:
        return
    with open(filepath, "rb") as file:
        key = file.read()
    cipher_suite = Fernet(key)
    messagebox.showinfo("Key Loaded", "Encryption key has been loaded successfully!")

# Funktion: Schlüssel speichern
def save_key():
    if not key:
        messagebox.showerror("Error", "No key to save. Please generate or load a key first!")
        return
    filepath = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key Files", "*.key")])
    if not filepath:
        return
    with open(filepath, "wb") as file:
        file.write(key)
    messagebox.showinfo("Key Saved", "Encryption key has been saved successfully!")

# Funktion: Text verschlüsseln
def encrypt_text():
    if not cipher_suite:
        messagebox.showerror("Error", "No encryption key found. Please generate or load a key first!")
        return
    text = text_entry.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "No text to encrypt!")
        return
    encrypted = cipher_suite.encrypt(text.encode())
    text_entry.delete("1.0", tk.END)
    text_entry.insert(tk.END, encrypted.decode())
    messagebox.showinfo("Success", "Text encrypted successfully!")

# Funktion: Text entschlüsseln
def decrypt_text():
    if not cipher_suite:
        messagebox.showerror("Error", "No decryption key found. Please generate or load a key first!")
        return
    encrypted_text = text_entry.get("1.0", tk.END).strip()
    if not encrypted_text:
        messagebox.showerror("Error", "No text to decrypt!")
        return
    try:
        decrypted = cipher_suite.decrypt(encrypted_text.encode())
        text_entry.delete("1.0", tk.END)
        text_entry.insert(tk.END, decrypted.decode())
        messagebox.showinfo("Success", "Text decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt text: {e}")

# Funktion: Text in Bild einbetten
def embed_text_in_image():
    text = text_entry.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "No text to embed!")
        return
    filepath = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.jpg *.jpeg")])
    if not filepath:
        return

    try:
        image = Image.open(filepath).convert("RGBA")
        width, height = image.size
        overlay = Image.new("RGBA", (width, height), (255, 255, 255, 0))
        draw = ImageDraw.Draw(overlay)

        # Schriftgröße dynamisch anpassen
        font_size = min(width // 20, height // 20)
        font = ImageFont.truetype("arial.ttf", font_size)
        text_size = draw.textsize(text, font=font)
        text_position = ((width - text_size[0]) // 2, (height - text_size[1]) // 2)
        draw.text(text_position, text, font=font, fill=(255, 255, 255, 128))

        combined = Image.alpha_composite(image, overlay)
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if save_path:
            combined.save(save_path)
            messagebox.showinfo("Success", "Text embedded in image successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to embed text in image: {e}")

# GUI erstellen
root = tk.Tk()
root.title("Secure Cryptography Tool")
root.geometry("600x500")

# Label und Eingabefeld für den Text
tk.Label(root, text="Enter your text below:", font=("Arial", 12)).pack(pady=5)
text_entry = tk.Text(root, wrap=tk.WORD, height=10, width=50)
text_entry.pack(pady=5)

# Schlüsselsteuerung
key_frame = tk.Frame(root)
key_frame.pack(pady=10)
tk.Button(key_frame, text="Generate Key", command=generate_key, width=15).grid(row=0, column=0, padx=5)
tk.Button(key_frame, text="Save Key", command=save_key, width=15).grid(row=0, column=1, padx=5)
tk.Button(key_frame, text="Load Key", command=load_key, width=15).grid(row=0, column=2, padx=5)

# Buttons für Textverschlüsselung und -entschlüsselung
button_frame = tk.Frame(root)
button_frame.pack(pady=10)
tk.Button(button_frame, text="Encrypt Text", command=encrypt_text, width=15).grid(row=0, column=0, padx=5)
tk.Button(button_frame, text="Decrypt Text", command=decrypt_text, width=15).grid(row=0, column=1, padx=5)

# Buttons für Bildfunktionen
tk.Button(root, text="Embed Text in Image", command=embed_text_in_image, width=20).pack(pady=5)

# Hauptloop starten
root.mainloop()

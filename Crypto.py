import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from PIL import Image
import pytesseract

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

# Funktion: Text in Bild verstecken (Steganografie)
def hide_text_in_image():
    text = text_entry.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "No text to hide!")
        return
    filepath = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
    if not filepath:
        return

    try:
        image = Image.open(filepath)
        pixels = image.load()

        # Text in Binärformat konvertieren
        binary_text = ''.join(format(ord(char), '08b') for char in text) + '1111111111111110'  # Stoppmarke
        binary_index = 0

        # Text in die niedrigsten Bits der Pixel einbetten
        for y in range(image.height):
            for x in range(image.width):
                if binary_index < len(binary_text):
                    r, g, b = pixels[x, y][:3]
                    r = (r & ~1) | int(binary_text[binary_index])  # Ändere LSB von Rot
                    binary_index += 1
                    if binary_index < len(binary_text):
                        g = (g & ~1) | int(binary_text[binary_index])  # Ändere LSB von Grün
                        binary_index += 1
                    if binary_index < len(binary_text):
                        b = (b & ~1) | int(binary_text[binary_index])  # Ändere LSB von Blau
                        binary_index += 1
                    pixels[x, y] = (r, g, b)
                else:
                    break

        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if save_path:
            image.save(save_path)
            messagebox.showinfo("Success", "Text hidden in image successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to hide text in image: {e}")

# Funktion: Text aus Bild extrahieren
def extract_text_from_image():
    filepath = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
    if not filepath:
        return

    try:
        image = Image.open(filepath)
        pixels = image.load()

        binary_text = ""
        for y in range(image.height):
            for x in range(image.width):
                r, g, b = pixels[x, y][:3]
                binary_text += str(r & 1)  # LSB von Rot
                binary_text += str(g & 1)  # LSB von Grün
                binary_text += str(b & 1)  # LSB von Blau

        # Suche nach der Stoppmarke
        stop_marker = '1111111111111110'
        if stop_marker in binary_text:
            binary_text = binary_text.split(stop_marker)[0]
            # Sicherstellen, dass die Länge durch 8 teilbar ist
            if len(binary_text) % 8 != 0:
                binary_text = binary_text[:-(len(binary_text) % 8)]
            text = ''.join(chr(int(binary_text[i:i + 8], 2)) for i in range(0, len(binary_text), 8))

            text_entry.delete("1.0", tk.END)
            text_entry.insert(tk.END, text)
            messagebox.showinfo("Success", "Text extracted from image successfully!")
        else:
            messagebox.showerror("Error", "No hidden text found in the image.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to extract text from image: {e}")

# GUI erstellen
root = tk.Tk()
root.title("Secure Cryptography Tool")
root.geometry("600x600")

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
tk.Button(root, text="Hide Text in Image", command=hide_text_in_image, width=25).pack(pady=5)
tk.Button(root, text="Extract Text from Image", command=extract_text_from_image, width=25).pack(pady=5)

# Hauptloop starten
root.mainloop()


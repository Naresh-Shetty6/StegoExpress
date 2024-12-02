import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from PIL import Image, ImageTk
import smtplib
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import threading
import subprocess
import webbrowser
import http.server
import socketserver
import sys
import os


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography Tool")
        self.root.geometry("700x650")
        self.root.configure(bg="#1e1e1e")

        # Title
        tk.Label(
            self.root,
            text="  Image Steganography Tool !!!",
            font=("Helvetica", 18, "bold"),
            bg="#1e1e1e",
            fg="#00FF00",
        ).grid(row=0, column=0, columnspan=3, pady=10)

        # Email Inputs
        self.email_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.email_frame.grid(row=1, column=0, columnspan=3, pady=20, sticky="ew")

        tk.Label(
            self.email_frame,
            text="Sender Email:",
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#00FF00",
        ).grid(row=0, column=0, sticky="w", padx=20)
        self.sender_email_entry = tk.Entry(
            self.email_frame, width=50, font=("Arial", 10), bg="#333", fg="#00FF00"
        )
        self.sender_email_entry.grid(row=0, column=1, padx=20, pady=5)

        tk.Label(
            self.email_frame,
            text="Sender Password:",
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#00FF00",
        ).grid(row=1, column=0, sticky="w", padx=20)
        self.sender_password_entry = tk.Entry(
            self.email_frame,
            width=50,
            font=("Arial", 10),
            show="*",
            bg="#333",
            fg="#00FF00",
        )
        self.sender_password_entry.grid(row=1, column=1, padx=20, pady=5)

        tk.Label(
            self.email_frame,
            text="Recipient Email:",
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#00FF00",
        ).grid(row=2, column=0, sticky="w", padx=20)
        self.recipient_email_entry = tk.Entry(
            self.email_frame, width=50, font=("Arial", 10), bg="#333", fg="#00FF00"
        )
        self.recipient_email_entry.grid(row=2, column=1, padx=20, pady=5)

        # Image File and Message
        self.file_message_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.file_message_frame.grid(
            row=2, column=0, columnspan=3, pady=10, sticky="ew"
        )

        tk.Label(
            self.file_message_frame,
            text="Image File:",
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#00FF00",
        ).grid(row=0, column=0, sticky="w", padx=10)
        self.image_path = tk.StringVar()
        tk.Entry(
            self.file_message_frame,
            textvariable=self.image_path,
            width=40,
            font=("Arial", 10),
            bg="#333",
            fg="#00FF00",
        ).grid(row=0, column=1, padx=10)
        tk.Button(
            self.file_message_frame,
            text="Browse",
            font=("Arial", 10),
            command=self.browse_image,
            bg="#00FF00",
            fg="black",
            relief="flat",
        ).grid(row=0, column=2, padx=10)

        self.message_label = tk.Label(
            self.file_message_frame,
            text="Message to Encrypt:",
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#00FF00",
        )
        self.message_label.grid(row=1, column=0, sticky="w", padx=10)
        self.message_entry = tk.Entry(
            self.file_message_frame,
            width=50,
            font=("Arial", 10),
            bg="#333",
            fg="#00FF00",
        )
        self.message_entry.grid(row=1, column=1, padx=10, pady=5)

        # Radio Buttons for Operation
        self.operation = tk.StringVar(value="encrypt")
        operations_frame = tk.Frame(self.root, bg="#1e1e1e")
        operations_frame.grid(row=3, column=0, columnspan=3, pady=10)

        tk.Radiobutton(
            operations_frame,
            text="Encrypt",
            variable=self.operation,
            value="encrypt",
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#00FF00",
            selectcolor="#1e1e1e",
            command=self.toggle_mode,
        ).grid(row=0, column=0, padx=20)

        tk.Radiobutton(
            operations_frame,
            text="Decrypt",
            variable=self.operation,
            value="decrypt",
            font=("Arial", 12),
            bg="#1e1e1e",
            fg="#00FF00",
            selectcolor="#1e1e1e",
            command=self.toggle_mode,
        ).grid(row=0, column=1, padx=20)

        # Image Preview Section
        self.preview_frame = tk.Frame(self.root, bg="#1e1e1e", width=700, height=600)
        self.preview_frame.grid(row=4, column=0, columnspan=3, pady=10)
        self.preview_label = tk.Label(self.preview_frame, bg="#1e1e1e")
        self.preview_label.grid(row=0, column=0)

        # Action Button
        self.action_button = tk.Button(
            self.root,
            text="Encrypt",
            font=("Arial", 12),
            command=self.encrypt_action,
            bg="#00FF00",
            fg="black",
            relief="flat",
        )
        self.action_button.grid(row=5, column=0, columnspan=3, pady=20)

        # Tool Info Button
        self.tool_info_button = tk.Button(
            self.root,
            text="Tool Info",
            font=("Arial", 12),
            command=self.tool_info,
            bg="#00FF00",
            fg="black",
            relief="flat",
        )
        self.tool_info_button.grid(row=6, column=0, columnspan=3, pady=10)

        # Initialize mode
        self.toggle_mode()

    def toggle_mode(self):
        if self.operation.get() == "encrypt":
            self.action_button.config(text="Encrypt", command=self.encrypt_action)
            self.message_label.config(text="Message to Encrypt:")
            self.email_frame.grid(row=1, column=0, columnspan=3, pady=20, sticky="ew")
        else:
            self.action_button.config(text="Decrypt", command=self.decrypt_action)
            self.message_label.config(text="Key for Decryption:")
            self.email_frame.grid_forget()

    def browse_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png *.jpg *.jpeg")]
        )
        if file_path:
            self.image_path.set(file_path)
            self.update_image_preview(file_path)

    def update_image_preview(self, image_path):
        try:
            image = Image.open(image_path)
            image.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(image)
            self.preview_label.config(image=photo)
            self.preview_label.image = photo
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")

    def tool_info(self):
        # Generate the HTML content with the provided details
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Project Information</title>
        <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #1e1e1e;
            color: #00FF00;
            text-align: center;
            padding: 20px;
        }
        h1, h2 {
            font-size: 2em;
            margin-bottom: 20px;
        }
        p {
            font-size: 1.2em;
            line-height: 1.6;
            text-align: left;
            margin: 0 auto;
            width: 90%;
            max-width: 800px;
        }
        a {
            color: #00FF00;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        ul {
            text-align: left;
            margin: 0 auto;
            padding: 0;
            list-style-type: disc;
            width: 90%;
            max-width: 800px;
        }
        li {
            margin: 10px 0;
        }
        table {
            margin: 20px auto;
            border-collapse: collapse;
            width: 90%;
            max-width: 800px;
            color: #00FF00;
        }
        th, td {
            border: 1px solid #00FF00;
            padding: 10px;
            text-align: left;
        }
        th {
            background-color: #333;
        }
    </style>
</head>
<body>
    <h1>Project Information</h1>
    <p>This project was developed by Naresh G, Madhihally Arun Kumar Tarun, Manoj S Rathod, Harish D as part of a 5th Sem mini project. 
    It is designed to secure organizations in the real world from cyber frauds performed by hackers.</p>
    
    <h2>Project Details</h2>
    <table>
        <tr><th>Project Name</th><td>Image Steganography using LSB</td></tr>
        <tr><th>Project Description</th><td>Hiding Message with Encryption in Image using LSB Algorithm</td></tr>
        <tr><th>Project Start Date</th><td>30-SEP-2024</td></tr>
        <tr><th>Project End Date</th><td>07-DEC-2024</td></tr>
        <tr><th>Project Status</th><td>Completed</td></tr>
    </table>

    <h2>Developer Details</h2>
    <table>
        <tr><th>Name</th><th>USN</th><th>Email</th></tr>
        <tr><td>Naresh G</td><td>1ST22CY036</td><td>gnaresh3003@gmail.com</td></tr>
        <tr><td>Madhihally Arun Kumar Tarun</td><td>1ST22CY033</td><td>tarunma04@gmail.com</td></tr>
        <tr><td>Manoj S Rathod</td><td>1ST22CY030</td><td>manojsrathode432@gmail.com</td></tr>
        <tr><td>Harish D</td><td>1ST22CY014</td><td>harishdj2002@gmail.com</td></tr>
    </table>

    <h2>College Details</h2>
    <table>
        <tr><th>College Name</th><td>Sambhram Institute of Technology</td></tr>
        <tr><th>Project Guide</th><td>Dr. Sanjeetha R</td></tr>
        <tr><th>Designation</th><td>HOD of CSE Cyber Secrity Department</td></tr>
    </table>
</body>
</html>
"""

        # Save the HTML content to a temporary file
        html_file = "tool_info.html"
        with open(html_file, "w") as file:
            file.write(html_content)

        # Serve the file locally using a temporary HTTP server
        def serve_file():
            handler = http.server.SimpleHTTPRequestHandler
            with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
                # Get the dynamically assigned port and open the browser
                port = httpd.server_address[1]
                url = f"http://127.0.0.1:{port}/{html_file}"
                threading.Thread(target=webbrowser.open, args=(url,)).start()
                httpd.serve_forever()

        threading.Thread(target=serve_file, daemon=True).start()


    def encrypt_action(self):
        image_file = self.image_path.get()
        message = self.message_entry.get()
        sender_email = self.sender_email_entry.get()
        sender_password = self.sender_password_entry.get()
        recipient_email = self.recipient_email_entry.get()

        if not all([image_file, message, sender_email, sender_password, recipient_email]):
            messagebox.showerror("Error", "All fields are required.")
            return

        try:
            # Generate the encryption key
            key = Fernet.generate_key()
            f = Fernet(key)
            secret_message = f.encrypt(message.encode())

            # Open the image
            image = Image.open(image_file)
            pixels = list(image.getdata())

            # Convert the encrypted message to binary
            binary_secret = "".join(format(byte, "08b") for byte in secret_message)
            new_pixels = []
            pixel_index = 0

            # Embed the binary data into the least significant bits of the image pixels
            for pixel in pixels:
                r, g, b = pixel
                if pixel_index < len(binary_secret):
                    r = r & 0xFE | int(binary_secret[pixel_index])
                    pixel_index += 1
                if pixel_index < len(binary_secret):
                    g = g & 0xFE | int(binary_secret[pixel_index])
                    pixel_index += 1
                if pixel_index < len(binary_secret):
                    b = b & 0xFE | int(binary_secret[pixel_index])
                    pixel_index += 1
                new_pixels.append((r, g, b))

            image.putdata(new_pixels)
            output_image_path = f"{os.path.splitext(os.path.basename(image_file))[0]}.png"
            image.save(output_image_path, "PNG")

            # Send the email with the encryption key in the subject
            self.send_email(
                output_image_path,
                key.decode(),
                sender_email,
                sender_password,
                recipient_email,
            )

            messagebox.showinfo(
                "Success", f"Image encrypted and sent to {recipient_email}."
            )
            self.clear_fields()

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during encryption: {str(e)}")
    def check_image_capacity(self, message):
        # Convert message to binary
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        message_length_in_bits = len(binary_message)
    
        # Calculate the available space in the image
        image_file = self.image_path.get()
        image = Image.open(image_file)
        image_pixels = image.size[0] * image.size[1] * 3  # 3 channels: R, G, B
    
        if message_length_in_bits > image_pixels:
            messagebox.showerror("Error", "The message is too long for this image. Please select a larger image or split the message.")
            return False
        return True
    
    
    def embed_message(self, image, message):
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        pixels = list(image.getdata())
        new_pixels = []
        pixel_index = 0

        for pixel in pixels:
            r, g, b = pixel
            if pixel_index < len(binary_message):
                r = r & 0xFC | int(binary_message[pixel_index:pixel_index+2], 2)
                pixel_index += 2
            if pixel_index < len(binary_message):
                g = g & 0xFC | int(binary_message[pixel_index:pixel_index+2], 2)
                pixel_index += 2
            if pixel_index < len(binary_message):
                b = b & 0xFC | int(binary_message[pixel_index:pixel_index+2], 2)
                pixel_index += 2
            new_pixels.append((r, g, b))

        image.putdata(new_pixels)
        return image
    def split_message(self, message, max_image_capacity):
        # Split the message into parts that can fit into the image
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        parts = []
    
        while len(binary_message) > max_image_capacity:
            parts.append(binary_message[:max_image_capacity])
            binary_message = binary_message[max_image_capacity:]
    
        if binary_message:
            parts.append(binary_message)
    
        return parts




    def send_email(self, image_path, key, sender_email, sender_password, recipient_email):
        try:
            msg = MIMEMultipart()
            msg["From"] = sender_email
            msg["To"] = recipient_email
            msg["Subject"] = "Your Encryption Key and Image"

            # Modify the body text to include the encryption key
            body = f"Please find the attached encrypted image. Use the encryption key provided in the subject to decrypt it: {key}"
            msg.attach(MIMEText(body, "plain"))

            # Attach the image
            with open(image_path, "rb") as image_attachment:
                img_base = MIMEBase("application", "octet-stream")
                img_base.set_payload(image_attachment.read())
                encoders.encode_base64(img_base)
                img_base.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{os.path.basename(image_path)}"'
                )
                msg.attach(img_base)

            # Send the email
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to send email: {str(e)}")


    def decrypt_action(self):
        encrypted_image_path = self.image_path.get()
        key = self.message_entry.get()

        if not encrypted_image_path or not key:
            messagebox.showerror("Error", "Please select the encrypted image and provide the decryption key.")
            return

        # Run decryption in a separate thread to keep the UI responsive
        decryption_thread = threading.Thread(target=self.perform_decryption, args=(encrypted_image_path, key))
        decryption_thread.start()

    def perform_decryption(self, encrypted_image_path, key):
        try:
            # Convert the key from string to bytes for Fernet
            f = Fernet(key.encode())
            print(f"Using key: {key}")

            # Open the encrypted image and extract the pixel data
            encoded_image = Image.open(encrypted_image_path)
            pixels = list(encoded_image.getdata())

            # Extract the binary data hidden in the image pixels
            binary_secret = ''
            for pixel in pixels:
                r, g, b = pixel
                binary_secret += str(r & 1)  # Extract LSB of red channel
                binary_secret += str(g & 1)  # Extract LSB of green channel
                binary_secret += str(b & 1)  # Extract LSB of blue channel

            print(f"Binary secret extracted: {binary_secret[:100]}...")  # Log first 100 bits for debugging

            # Check if the binary secret has sufficient length
            expected_len = len(binary_secret)
            print(f"Total extracted binary bits: {expected_len}")

            if expected_len < 8:
                raise Exception("Insufficient data extracted. The image may not contain enough hidden information.")

            # Convert the binary string into the original message bytes
            byte_array = bytearray()
            for i in range(0, len(binary_secret), 8):
                byte = binary_secret[i:i + 8]
                if len(byte) == 8:  # Only consider valid 8-bit segments
                    byte_array.append(int(byte, 2))

            print(f"Byte array length: {len(byte_array)} bytes")  # Check the byte array length
            print(f"First 20 bytes: {byte_array[:20]}...")  # Log first 20 bytes for debugging

            # Ensure that we have a reasonable message length
            if len(byte_array) < 10:
                raise Exception("The extracted binary data is too short to be a valid encrypted message.")

            # Convert byte array to a string and remove padding (null bytes) if necessary
            extracted_message = bytes(byte_array).decode('utf-8', errors='ignore').rstrip('\x00')

            # Decrypt the message using Fernet
            print(f"Extracted message length: {len(extracted_message)} characters")
            original_message = f.decrypt(extracted_message.encode()).decode()

            # Show the decrypted message in the main thread
            self.root.after(0, messagebox.showinfo, "Success", "The Hidden Text is:\n" + original_message)
            self.clear_fields()

        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"An error occurred during decryption: {str(e)}")
            self.clear_fields()





    def clear_fields(self):
        self.image_path.set("")
        self.message_entry.delete(0, tk.END)
        self.sender_email_entry.delete(0, tk.END)
        self.sender_password_entry.delete(0, tk.END)
        self.recipient_email_entry.delete(0, tk.END)
        self.preview_label.config(image="")
        self.preview_label.image = None


# Main program execution
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()

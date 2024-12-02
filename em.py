print('This is a dummy Python file')
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
    
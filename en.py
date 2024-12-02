print('dummy python')
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

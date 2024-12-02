print('dummy python')
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


# Image Steganography using LSB

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/) [![License: Custom](https://img.shields.io/badge/License-Educational%2FResearch-lightgrey)](./LICENSE)

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Screenshots](#screenshots)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Requirements](#requirements)
- [Project Details](#project-details)
- [License](#license)
- [Acknowledgements](#acknowledgements)
- [Contributing](#contributing)
- [Issues](#issues)

---

## Overview
Image Steganography Tool is a desktop application that allows users to securely hide (encrypt) and extract (decrypt) secret messages within image files using the Least Significant Bit (LSB) algorithm, combined with strong encryption (Fernet). The tool also supports sending the stego-image and encryption key via email, making it ideal for secure communication.

[View on GitHub](https://github.com/yourusername/StegoXpress)  
[Report Issues](https://github.com/yourusername/StegoXpress/issues)

---

## Features
- **Hide (Encrypt) Messages in Images:** Securely embed encrypted text messages into PNG/JPG images using LSB steganography.
- **Extract (Decrypt) Hidden Messages:** Retrieve and decrypt secret messages from stego-images using the provided key.
- **Email Integration:** Send the encrypted image and key directly to a recipient via email.
- **User-Friendly GUI:** Modern, intuitive interface built with Tkinter.
- **Image Preview:** Visualize the selected image before and after embedding.
- **Tool Info:** View project, developer, and company details from within the app.

---

## Screenshots
![App Logo](logo.png)

---

## Getting Started

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/StegoXpress.git
   cd StegoXpress
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the application:**
   ```bash
   python steganography_app.py
   ```

### Packaging as Executable (Optional)
To build a standalone executable (Windows):
```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=logo.png steganography_app.py
```
The executable will be in the `dist/` folder.

---

## Usage
1. **Encrypt Mode:**
   - Select an image file (PNG/JPG).
   - Enter the message to hide.
   - Provide sender and recipient email credentials.
   - Click "Encrypt" to embed and send the image.
2. **Decrypt Mode:**
   - Select the stego-image.
   - Enter the decryption key (received via email).
   - Click "Decrypt" to reveal the hidden message.

---

## Requirements
- `cryptography`
- `Pillow`

Install all requirements with:
```bash
pip install -r requirements.txt
```

---

## Project Details
- **Project Name:** Image Steganography using LSB
- **Description:** Hiding Message with Encryption in Image using LSB Algorithm
- **Status:** Completed

### Developers
| Name             | Email                        |
|------------------|------------------------------|
| Naresh G         | gnaresh3003@gmail.com        |


---

## License
This project is for **educational and research purposes only**. For commercial use, please contact the developer . See [LICENSE](./LICENSE) for details.

---

## Acknowledgements
- Developed as part of a Cyber Security Internship to help secure organizations from cyber fraud.
- Uses [cryptography](https://cryptography.io/) and [Pillow](https://python-pillow.org/) libraries.

---

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

## Issues
If you encounter any problems or have suggestions, please [open an issue](https://github.com/yourusername/StegoXpress/issues). 

# SRENOGRAPHY-WEB
## 1.Description

- **What the project does:**  
  This project is a web-based application that allows users to hide and retrieve secret messages within an uploaded     digital image using steganography and encryption techniques.

- **What problem it solves:**  
  It addresses the challenge of securely transmitting sensitive information without attracting attention. Instead of    sending visible encrypted messages, the information is concealed inside an image, making the communication appear     normal while keeping the content protected.

- **How it works:**  
  The application uses Least Significant Bit (LSB), steganography to embed data into image pixels in a way that is      visually imperceptible. Before embedding, the message is encrypted using a password-based key derivation process.     During decoding, the hidden data is extracted from the image and decrypted using the same password to recover the     original message.
  
## 2.Features

- **Message Encoding:**  
  Allows users to hide a secret text message inside an image using steganography.

- **Message Decoding:**  
  Enables extraction of hidden messages from encoded images using the correct password.

- **Password Protection:**  
  Messages are encrypted before embedding, ensuring that only authorized users can access the content.

- **Image Support:**  
  Works with common image formats such as PNG, JPG, and BMP (PNG recommended for best results).

- **Error Handling:**  
  Detects incorrect passwords, corrupted images, or missing hidden data and provides user-friendly feedback.

- **Capacity Estimation:**  
  Displays an estimate of how much text can be hidden in an image before encoding.

- **User-Friendly Interface:**  
  Built with Streamlit to provide an interactive and easy-to-use web interface.

## 3.How to Run

- **Step 1: Install Python**  
  Make sure you have Python (version 3.8 or higher) installed on your system.  
  You can check by running on the terminal:
   - python --version
     
- **Step 2: Install dependencies**  
  Install all required libraries using the provided requirements file:
   - pip install -r requirements.txt
     
  This will install:
   - streamlit
   - pillow
   - cryptography

- **Step 3: Run the application**  
  Launch the Streamlit web app with:
   - streamlit run app.py
  
- **Step 4: Open in browser**  
  After running the command, Streamlit will provide a local URL.  
  Open this link in your browser to use the application.

- **Step 5: Use the application**  
  To encode: upload an image, enter a secret message and password, then download the encoded image.  
  To decode: upload an encoded image, enter the correct password, and retrieve the hidden message.

## 4.Technologies Used

- **Python**  
  Core programming language used for implementing the application logic and functionality.

- **Streamlit**  
  Framework used to build the interactive web-based user interface quickly and efficiently.

- **Pillow (PIL)**  
  Library used for image processing, including reading, modifying, and saving image data.

- **Cryptography**  
  Used to securely encrypt and decrypt messages באמצעות password-based key derivation (PBKDF2) and symmetric encryption (Fernet).

- **Standard Python Libraries**  
  Includes modules such as `io`, `base64`, and `secrets` for handling data encoding, random generation, and file        processing.

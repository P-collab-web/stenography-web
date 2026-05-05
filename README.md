# IMAGE STEGANOGRAPHY-WEB

A web app that hides and retrieves encrypted messages inside images using Least Significant Bit (LSB) steganography. The hidden data can only be extracted and decrypted with the correct password

**Features**

The web app can encode and decode messages, has password-protected encryption and supports common image formats (recommend PNG for better results)

**Installation**

## Installation

`conda env create -f environment.yml`
`conda activate steganography-env`
`pip install -e`

**Run**

`streamlit run app.py`

**Usage**

To encode:
Uploade the image, enter the message, choose a password, download results

To decode:
Upload encryptyed image, enter the correct password, view message

**Packages**

streamlit, pillow, cryptography

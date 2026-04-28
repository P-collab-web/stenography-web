import io
import base64
import secrets
import streamlit as st
from PIL import Image
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend


MAGIC = b"STEGO1"
HEADER_SIZE = len(MAGIC) + 16 + 4  # magic + salt + encrypted length


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_message(message: str, password: str) -> Tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(message.encode("utf-8"))
    return salt, encrypted


def decrypt_message(encrypted: bytes, password: str, salt: bytes) -> str:
    key = derive_key(password, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode("utf-8")


def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            break
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def get_capacity_chars(image: Image.Image) -> int:
    image = image.convert("RGB")
    total_bits = image.width * image.height * 3
    usable_bits = total_bits - (HEADER_SIZE * 8)
    if usable_bits < 0:
        return 0
    return usable_bits // 8


def encode_image(image: Image.Image, message: str, password: str) -> Image.Image:
    image = image.convert("RGB")
    salt, encrypted = encrypt_message(message, password)

    payload = MAGIC + salt + len(encrypted).to_bytes(4, "big") + encrypted
    payload_bits = bytes_to_bits(payload)

    pixels = list(image.getdata())
    capacity_bits = len(pixels) * 3

    if len(payload_bits) > capacity_bits:
        raise ValueError(
            f"Message too large for this image. Need {len(payload_bits)} bits, "
            f"but image only holds {capacity_bits} bits."
        )

    new_pixels = []
    bit_index = 0

    for r, g, b in pixels:
        rgb = [r, g, b]
        for channel in range(3):
            if bit_index < len(payload_bits):
                rgb[channel] = (rgb[channel] & 0xFE) | payload_bits[bit_index]
                bit_index += 1
        new_pixels.append(tuple(rgb))

    encoded = Image.new("RGB", image.size)
    encoded.putdata(new_pixels)
    return encoded


def decode_image(image: Image.Image, password: str) -> str:
    image = image.convert("RGB")
    pixels = list(image.getdata())

    bits = []
    for r, g, b in pixels:
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    raw = bits_to_bytes(bits)

    if len(raw) < HEADER_SIZE:
        raise ValueError("Image does not contain a valid hidden payload.")

    if raw[:len(MAGIC)] != MAGIC:
        raise ValueError("No hidden message found in this image.")

    salt_start = len(MAGIC)
    salt_end = salt_start + 16
    salt = raw[salt_start:salt_end]

    length_start = salt_end
    length_end = length_start + 4
    encrypted_len = int.from_bytes(raw[length_start:length_end], "big")

    encrypted_start = length_end
    encrypted_end = encrypted_start + encrypted_len

    if encrypted_end > len(raw):
        raise ValueError("Corrupted hidden payload.")

    encrypted = raw[encrypted_start:encrypted_end]
    return decrypt_message(encrypted, password, salt)


st.set_page_config(page_title="Steganography App", page_icon="🔐", layout="centered")

st.title("🔐 Steganography Web App")
st.write("Hide a secret message inside an image using LSB steganography and password-based encryption.")

tab1, tab2 = st.tabs(["Encode Message", "Decode Message"])


with tab1:
    st.subheader("Encode a Message into an Image")

    uploaded_image = st.file_uploader(
        "Upload an image",
        type=["png", "bmp", "jpg", "jpeg"],
        key="encode_uploader"
    )

    secret_message = st.text_area("Secret message", height=150)
    encode_password = st.text_input("Password", type="password", key="encode_password")

    if uploaded_image is not None:
        image = Image.open(uploaded_image)
        st.image(image, caption="Original image", use_container_width=True)

        capacity = get_capacity_chars(image)
        st.info(f"Estimated capacity: about {capacity} characters (rough estimate). Best results with PNG.")

        if st.button("Encode Image"):
            if not secret_message.strip():
                st.error("Please enter a secret message.")
            elif not encode_password.strip():
                st.error("Please enter a password.")
            else:
                try:
                    encoded_image = encode_image(image, secret_message, encode_password)

                    output = io.BytesIO()
                    encoded_image.save(output, format="PNG")
                    output.seek(0)

                    st.success("Message encoded successfully.")
                    st.download_button(
                        label="Download encoded image",
                        data=output,
                        file_name="encoded_image.png",
                        mime="image/png"
                    )
                except ValueError as e:
                    st.error(f"Input error: {e}")
                except Exception:
                    st.error("Unexpected error occurred.")


with tab2:
    st.subheader("Decode a Message from an Image")

    decode_uploaded_image = st.file_uploader(
        "Upload an encoded image",
        type=["png", "bmp", "jpg", "jpeg"],
        key="decode_uploader"
    )

    decode_password = st.text_input("Password", type="password", key="decode_password")

    if decode_uploaded_image is not None:
        image = Image.open(decode_uploaded_image)
        st.image(image, caption="Encoded image", use_container_width=True)

        if st.button("Decode Message"):
            if not decode_password.strip():
                st.error("Please enter the password.")
            else:
                try:
                    decoded_message = decode_image(image, decode_password)
                    st.success("Message decoded successfully.")
                    st.text_area("Decoded message", decoded_message, height=150)
                except ValueError as e:
                    st.error(f"Input error: {e}")
                except Exception:
                    st.error("Unexpected error occurred.")


st.markdown("---")
st.caption("Tip: Use PNG for the encoded image. JPEG compression can damage hidden data.")

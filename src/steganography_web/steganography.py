from PIL import Image

from steganography_web.crypto import decrypt_message, encrypt_message
from steganography_web.utils import bits_to_bytes, bytes_to_bits


MAGIC = b"STEGO1"
HEADER_SIZE = len(MAGIC) + 16 + 4  # magic + salt + encrypted length


def get_capacity_chars(image: Image.Image) -> int:
    """
    Estimates how many characters can be hidden in the image.

    The image is converted to RGB, and we use one bit from each color channel.

    Parameters:
        image (Image.Image): Image where the message will be hidden

    Returns:
        int: Approximate number of characters that can be stored
    """
    image = image.convert("RGB")
    total_bits = image.width * image.height * 3
    usable_bits = total_bits - (HEADER_SIZE * 8)
    if usable_bits < 0:
        return 0
    return usable_bits // 8


def encode_image(image: Image.Image, message: str, password: str) -> Image.Image:
    """
    Hides an encrypted message inside an image.

    The message is first encrypted with the password, then converted into bits.
    These bits are stored in the least significant bits of the image pixels.

    Parameters:
        image (Image.Image): Original image
        message (str): Secret message to hide
        password (str): Password used to encrypt the message

    Returns:
        Image.Image: New image containing the hidden message

    Raises:
        ValueError: If the message is too large for the image
    """
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
    """
    Extracts and decrypts a hidden message from an image.

    The function reads the least significant bits of the pixels, rebuilds the
    hidden data, checks that it has the correct header, and decrypts the message.

    Parameters:
        image (Image.Image): Image that may contain a hidden message
        password (str): Password used to decrypt the hidden message

    Returns:
        str: Hidden message

    Raises:
        ValueError: If no valid hidden message is found
    """
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
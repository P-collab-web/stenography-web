import pytest
from PIL import Image
from cryptography.fernet import InvalidToken

from steganography_web.steganography import encode_image, decode_image


def test_encode_decode_roundtrip():
    image = Image.new("RGB", (100, 100), color="white")

    encoded = encode_image(image, "secret message", "password123")
    decoded = decode_image(encoded, "password123")

    assert decoded == "secret message"


def test_decode_with_wrong_password_fails():
    image = Image.new("RGB", (100, 100), color="white")

    encoded = encode_image(image, "secret message", "correct-password")

    with pytest.raises(InvalidToken):
        decode_image(encoded, "wrong-password")


def test_message_too_large_raises_value_error():
    image = Image.new("RGB", (10, 10), color="white")
    huge_message = "A" * 10_000

    with pytest.raises(ValueError):
        encode_image(image, huge_message, "password123")
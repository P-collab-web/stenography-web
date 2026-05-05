def bytes_to_bits(data: bytes) -> list[int]:
    """
    Converts bytes into a list of bits (0s and 1s).

    Each byte is split into 8 bits, from most significant bit to least.

    Parameters:
        data (bytes): Input data in bytes

    Returns:
        list[int]: List of bits (0 or 1)
    """
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    """
    Converts a list of bits back into bytes.

    The bits are grouped in chunks of 8 to form each byte.

    Parameters:
        bits (list[int]): List of bits (0 or 1)

    Returns:
        bytes: Reconstructed byte data
    """
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
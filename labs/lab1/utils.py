import base64
from typing import Generator


def _pad(data: str, size: int) -> str:
    reminder = len(data) % size
    if reminder != 0:
        data = "0" * (size - reminder) + data
    return data


def _chunks(data: str, chunk_size: int) -> Generator[str, None, None]:
    data = _pad(data, chunk_size)
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


def _hex(data: int) -> str:
    return format(data, "02x")


# Conversion functions


def hex_2_bin(data: str) -> str:
    """Converts a hexadecimal string to a binary representation.

    Args:
        data (str): The hexadecimal string to be converted. It should have an
            even number of characters and only contain valid hexadecimal digits
            (0-9, A-F, a-f).

    Returns:
        str: The binary representation of the hexadecimal string, where each
            pair of hexadecimal digits is encoded as an 8-bit binary number.

    Examples:
        >>> hex_2_bin("01abcd")
        '000000011010101111001101'
        >>> hex_2_bin("0a")
        '00001010'
    """
    return "".join(f"{int(x, 16):08b}" for x in _chunks(data, 2))


def bin_2_hex(data: str) -> str:
    """Converts a binary string to a hexadecimal representation.

    Args:
        data (str): The binary string to be converted. It should have a multiple
            of 8 characters and only contain valid binary digits (0 or 1).

    Returns:
        str: The hexadecimal representation of the binary string, where each
            group of 8 binary digits is encoded as a pair of hexadecimal digits.

    Examples:
        >>> bin_2_hex("000000011010101111001101")
        '01abcd'
        >>> bin_2_hex("00001010")
        '0a'
    """
    return "".join(f"{int(b, 2):02x}" for b in _chunks(data, 8))


def str_2_bin(data: str) -> str:
    """Converts a string to a binary representation.

    Args:
        data (str): The string to be converted.

    Returns:
        str: The binary representation of the string, where each character is
            encoded as an 8-bit binary number.

    Examples:
        >>> str_2_bin("Hello")
        '0100100001100101011011000110110001101111'
        >>> str_2_bin("IC")
        '0100100101000011'
    """
    return "".join(f"{ord(c):08b}" for c in data)


def bin_2_str(data: str) -> str:
    """Converts a binary string to a string.

    Args:
        data (str): The binary string to be converted. It should have a multiple
            of 8 characters and only contain valid binary digits (0 or 1).

    Returns:
        str: The string representation of the binary string, where each group
            of 8 binary digits is decoded as a character.

    Examples:
        >>> bin_2_str("0100100001100101011011000110110001101111")
        'Hello'
        >>> bin_2_str("0100100101000011")
        'IC'
    """
    return "".join(chr(int(b, 2)) for b in _chunks(data, 8))


def str_2_hex(data: str) -> str:
    """Converts a string to a hexadecimal representation.

    Args:
        data (str): The string to be converted.

    Returns:
        str: The hexadecimal representation of the string, where each character
            is encoded as a pair of hexadecimal digits.

    Examples:
        >>> str_2_hex("Hello")
        '48656c6c6f'
        >>> str_2_hex("IC")
        '4943'
    """
    return "".join(f"{ord(c):02x}" for c in data)


def hex_2_str(data: str) -> str:
    """Converts a hexadecimal string to a string.

    Args:
        data (str): The hexadecimal string to be converted. It should have an
            even number of characters and only contain valid hexadecimal digits
            (0-9, A-F, a-f).

    Returns:
        str: The string representation of the hexadecimal string, where each
            pair of hexadecimal digits is decoded as a character.

    Examples:
        >>> hex_2_str("48656c6c6f")
        'Hello'
        >>> hex_2_str("4943")
        'IC'
    """
    return "".join(chr(int(x, 16)) for x in _chunks(data, 2))


# XOR functions


def strxor(operand_1: str, operand_2: str) -> str:
    """Performs a bitwise exclusive OR (XOR) operation on two strings.

    Args:
        operand_1 (str): The first string to be XORed.
        operand_2 (str): The second string to be XORed.

    Returns:
        str: The result of the XOR operation on the two strings, where each
            character is encoded as an 8-bit binary number. The result has
            the same length as the shorter input string.

    Examples:
        >>> strxor("Hello", "IC")
        '\\x01&'
        >>> strxor("secret", "key")
        '\\x18\\x00\\x1a'
    """
    return "".join(chr(ord(x) ^ ord(y)) for (x, y) in zip(operand_1, operand_2))


def bitxor(operand_1: str, operand_2: str) -> str:
    """Performs a bitwise exclusive OR (XOR) operation on two bit-strings.

    Args:
        operand_1 (str): The first bit-string to be XORed. It should only
            contain valid binary digits (0 or 1).
        operand_2 (str): The second bit-string to be XORed. It should only
            contain valid binary digits (0 or 1).

    Returns:
        str: The result of the XOR operation on the two bit-strings, where each
            bit is encoded as a character. The result has the same length as
            the shorter input bit-string.

    Examples:
        >>> bitxor("01001000", "01000010")
        '00001010'
        >>> bitxor("10101010", "00110011")
        '10011001'
    """
    return "".join(str(int(x) ^ int(y)) for (x, y) in zip(operand_1, operand_2))


def hexxor(operand_1: str, operand_2: str) -> str:
    """Performs a bitwise exclusive OR (XOR) operation on two hexadecimal
    strings.

    Args:
        operand_1 (str): The first hexadecimal string to be XORed. It should
            have an even number of characters and only contain valid hexadecimal
            digits (0-9, A-F, a-f).
        operand_2 (str): The second hexadecimal string to be XORed. It should
            have an even number of characters and only contain valid
            digits (0-9, A-F, a-f).

    Returns:
        str: The result of the XOR operation on the two hexadecimal strings,
            where each pair of hexadecimal digits is encoded as a pair of
            hexadecimal digits. The result has the same length as the shorter
            input hexadecimal string.

    Examples:
        >>> hexxor("48656c6c6f", "42696e67")
        '0a0c020b'
        >>> hexxor("736563726574", "6b6579")
        '18001a'
    """
    return "".join(
        _hex(int(x, 16) ^ int(y, 16))
        for (x, y) in zip(_chunks(operand_1, 2), _chunks(operand_2, 2))
    )


# Python3 'bytes' functions


def bytes_to_string(bytes_data: bytearray | bytes) -> str:
    """Converts a byte array or a byte string to a string.

    Args:
        bytes_data (bytearray | bytes): The byte array or the byte string to be
            converted. It should be encoded in Latin-1 format.

    Returns:
        str: The string representation of the byte array or the byte string,
            decoded using Latin-1 encoding.

    Examples:
        >>> bytes_to_string(b'Hello')
        'Hello'
        >>> bytes_to_string(bytearray(b'IC'))
        'IC'
    """
    return bytes_data.decode(encoding="raw_unicode_escape")


def string_to_bytes(string_data: str) -> bytes:
    """Converts a string to a byte string.

    Args:
        string_data (str): The string to be converted.

    Returns:
        bytes: The byte string representation of the string, encoded using
        Latin-1 encoding.

    Examples:
        >>> string_to_bytes('Hello')
        b'Hello'
        >>> string_to_bytes('IC')
        b'IC'
    """
    return string_data.encode(encoding="raw_unicode_escape")


# Base64 functions


def b64encode(data: str) -> str:
    """Encodes a string to base64.

    Parameters:
        data (str): The string to be encoded.

    Returns:
        str: The base64 encoded string, using Latin-1 encoding.

    Examples:
        >>> b64encode("Hello")
        'SGVsbG8='
        >>> b64encode("IC")
        'SUM='
    """
    return bytes_to_string(base64.b64encode(string_to_bytes(data)))


def b64decode(data: str) -> str:
    """Decodes a base64 encoded string.

    Args:
        data (str): The base64 encoded string to be decoded. It should only
            contain valid base64 characters (A-Z, a-z, 0-9, +, /, =).

    Returns:
        str: The decoded string, using Latin-1 encoding.

    Examples:
        >>> b64decode("SGVsbG8=")
        'Hello'
        >>> b64decode("SUM=")
        'IC'
    """
    return bytes_to_string(base64.b64decode(string_to_bytes(data)))
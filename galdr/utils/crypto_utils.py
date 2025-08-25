import base64
import base58
import base45
import codecs

# ##################################################################################
#  Base Encodings
# ##################################################################################

def base32_encode(text: str) -> str:
    """Encodes text to Base32."""
    return base64.b32encode(text.encode('utf-8')).decode('utf-8')

def base32_decode(encoded_text: str) -> str:
    """Decodes Base32 text."""
    return base64.b32decode(encoded_text.encode('utf-8')).decode('utf-8')

def base45_encode(text: str) -> str:
    """Encodes text to Base45."""
    return base45.b45encode(text.encode('utf-8')).decode('utf-8')

def base45_decode(encoded_text: str) -> str:
    """Decodes Base45 text."""
    return base45.b45decode(encoded_text.encode('utf-8')).decode('utf-8')

def base58_encode(text: str) -> str:
    """Encodes text to Base58."""
    return base58.b58encode(text.encode('utf-8')).decode('utf-8')

def base58_decode(encoded_text: str) -> str:
    """Decodes Base58 text."""
    return base58.b58decode(encoded_text.encode('utf-8')).decode('utf-8')

BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def _base62_encode_helper(num, alphabet=BASE62):
    """Encode a positive number into Base X and return the string."""
    if num == 0:
        return alphabet[0]
    arr = []
    base = len(alphabet)
    while num:
        num, rem = divmod(num, base)
        arr.append(alphabet[rem])
    arr.reverse()
    return ''.join(arr)

def _base62_decode_helper(string, alphabet=BASE62):
    """Decode a Base X encoded string into the number"""
    base = len(alphabet)
    strlen = len(string)
    num = 0
    idx = 0
    for char in string:
        power = (strlen - (idx + 1))
        num += alphabet.index(char) * (base ** power)
        idx += 1
    return num

def base62_encode(text: str) -> str:
    """Encodes text to Base62."""
    if not text:
        return ""
    num = int.from_bytes(text.encode('utf-8'), 'big')
    return _base62_encode_helper(num)

def base62_decode(encoded_text: str) -> str:
    """Decodes Base62 text."""
    if not encoded_text:
        return ""
    num = _base62_decode_helper(encoded_text)
    byte_length = (num.bit_length() + 7) // 8 or 1
    return num.to_bytes(byte_length, 'big').decode('utf-8')

def base85_encode(text: str) -> str:
    """Encodes text to Base85."""
    return base64.a85encode(text.encode('utf-8')).decode('utf-8')

def base85_decode(encoded_text: str) -> str:
    """Decodes Base85 text."""
    return base64.a85decode(encoded_text.encode('utf-8')).decode('utf-8')

# ##################################################################################
#  Number Systems
# ##################################################################################

def text_to_decimal(text: str) -> str:
    """Converts text to a space-separated decimal string."""
    return ' '.join(str(ord(c)) for c in text)

def decimal_to_text(decimal_str: str) -> str:
    """Converts a space-separated decimal string to text."""
    return ''.join(chr(int(i)) for i in decimal_str.split())

def text_to_binary(text: str) -> str:
    """Converts text to a space-separated binary string."""
    return ' '.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary_str: str) -> str:
    """Converts a space-separated binary string to text."""
    return ''.join(chr(int(i, 2)) for i in binary_str.split())

def text_to_octal(text: str) -> str:
    """Converts text to a space-separated octal string."""
    return ' '.join(format(ord(c), 'o') for c in text)

def octal_to_text(octal_str: str) -> str:
    """Converts a space-separated octal string to text."""
    return ''.join(chr(int(i, 8)) for i in octal_str.split())

# ##################################################################################
#  Simple Ciphers
# ##################################################################################

def rot13_cipher(text: str) -> str:
    """Applies the ROT13 cipher to text."""
    return codecs.encode(text, 'rot_13')

def xor_cipher(text: str, key: str) -> str:
    """Applies a repeating-key XOR cipher to text."""
    encoded_chars = []
    for i in range(len(text)):
        key_c = key[i % len(key)]
        encoded_c = chr(ord(text[i]) ^ ord(key_c))
        encoded_chars.append(encoded_c)
    return "".join(encoded_chars)

def xor_decipher(encoded_text: str, key: str) -> str:
    """Deciphers a repeating-key XOR cipher."""
    # XOR is symmetric, so encryption and decryption are the same.
    return xor_cipher(encoded_text, key)

# ##################################################################################
#  Symmetric Ciphers
# ##################################################################################

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def _get_cipher_algorithm(cipher_name, key):
    """Returns a cipher algorithm instance."""
    if cipher_name == 'AES':
        return algorithms.AES(key)
    elif cipher_name == 'TripleDES':
        return decrepit_algorithms.TripleDES(key)
    elif cipher_name == 'Blowfish':
        return decrepit_algorithms.Blowfish(key)
    elif cipher_name == 'RC4':
        return decrepit_algorithms.ARC4(key)
    else:
        raise ValueError(f"Unsupported cipher: {cipher_name}")

def _get_cipher_mode(mode_name, iv):
    """Returns a cipher mode instance."""
    if mode_name == 'CBC':
        return modes.CBC(iv)
    elif mode_name == 'ECB':
        return modes.ECB()
    elif mode_name == 'CFB':
        return modes.CFB(iv)
    elif mode_name == 'OFB':
        return modes.OFB(iv)
    else:
        raise ValueError(f"Unsupported mode: {mode_name}")

def symmetric_encrypt(cipher_name, mode_name, key_hex, iv_hex, plaintext):
    """Encrypts plaintext using a symmetric cipher."""
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex) if iv_hex else None

    algorithm = _get_cipher_algorithm(cipher_name, key)

    # RC4 is a stream cipher and doesn't use modes or padding
    if isinstance(algorithm, decrepit_algorithms.ARC4):
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

    mode = _get_cipher_mode(mode_name, iv)
    cipher = Cipher(algorithm, mode, backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithm.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    return encryptor.update(padded_data) + encryptor.finalize()

def symmetric_decrypt(cipher_name, mode_name, key_hex, iv_hex, ciphertext):
    """Decrypts ciphertext using a symmetric cipher."""
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex) if iv_hex else None

    algorithm = _get_cipher_algorithm(cipher_name, key)

    # RC4 handling
    if isinstance(algorithm, decrepit_algorithms.ARC4):
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    mode = _get_cipher_mode(mode_name, iv)
    cipher = Cipher(algorithm, mode, backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithm.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return unpadded_data.decode('utf-8')

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
 
def caesar_enc(letter: str, k: int = 3) -> str:
    if not "A" <= letter <= "Z":
        raise ValueError("Invalid letter")
    return ALPHABET[(ord(letter) - ord("A") + k) % len(ALPHABET)]

def caesar_dec(letter: str, k: int = 3) -> str:
    if not "A" <= letter <= "Z":
        raise ValueError("Invalid letter")
    return ALPHABET[(ord(letter) - ord("A") - k) % len(ALPHABET)]

def caesar_enc_string(plaintext: str, k: int = 3) -> str:
    cipher = ""
    for letter in plaintext:
        cipher += caesar_enc(letter, k)
    return cipher

def caesar_dec_string(ciphertext: str, k: int = 3) -> str:
    plain = ""
    for letter in ciphertext:
        plain += caesar_dec(letter, k)
    return plain
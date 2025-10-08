import utils
from caesar import *

def ex1():
    C1 = "010101100110000101101100011010000110000101101100011011000110000100100001"
    C2 = "526f636b2c2050617065722c2053636973736f727321"
    C3 = "WW91IGRvbid0IG5lZWQgYSBrZXkgdG8gZW5jb2RlIGRhdGEu"
    #-------------------------------------------------
    C11 = utils.bin_2_str(C1)
    C22 = utils.hex_2_str(C2)
    C33 = utils.b64decode(C3)
    #-------------------------------------------------
    print(C11)
    print(C22)
    print(C33)

def ex2():
    C1 = "000100010001000000001100000000110001011100000111000010100000100100011101000001010001100100000101"
    C2 = "02030F07100A061C060B1909"
    key = "abcdefghijkl"
    #-------------------------------------------------
    C11 = utils.strxor(utils.bin_2_str(C1), key)
    C22 = utils.strxor(utils.hex_2_str(C2), key)
    #-------------------------------------------------
    print(C11)
    print(C22)

def ex3():
    print(ALPHABET)
    print(len(ALPHABET))
    print(ALPHABET[0])
    print(ord("A"))
    print(ord("D") - ord("A"))
    print(26 % 26)
    print(28 % 26)
    print(-1 % 26)
    #-------------------------------------------------
    print(caesar_enc("D"))
    print(caesar_enc("Z"))
    print(caesar_enc("B"))
    #-------------------------------------------------
    print(caesar_dec("G"))
    print(caesar_dec("C"))
    print(caesar_dec("E"))
    #-------------------------------------------------
    test = "HELLO"
    test += "WORLD"
    print(caesar_enc_string(test))
    print(caesar_dec_string(caesar_enc_string(test)))
    #-------------------------------------------------
    
if __name__ == '__main__':
    ex = int(input("Ce ex: "))
    if ex == 1:
        ex1()
    elif ex == 2:
        ex2()
    elif ex == 3:
        ex3()
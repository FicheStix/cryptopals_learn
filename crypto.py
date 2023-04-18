"""Crypto functions for use within Cryptopals challenges"""

import binascii


# function to convert string of hex values into base64
def hex2base64(hexstring: bytes) -> bytes:
    """returns a string of base64 encoded hex characters"""

    hexbytes = binascii.unhexlify(hexstring)
    return binascii.b2a_base64(hexbytes, newline=False)


# return xor'd result of two strings of hex
def fixedxor(buffstring1: str, buffstring2: str) -> bytes:
    """returns the output of two xor'd strings"""
    bytestring1 = binascii.unhexlify(buffstring1)
    bytestring2 = binascii.unhexlify(buffstring2)
    xorarray = bytearray()

    if (len(bytestring1) != len(bytestring2)):
        raise ValueError('The values provided differ in length.')

    i = 0
    while (i < len(bytestring1)):
        xorarray.append(bytestring1[i] ^ bytestring2[i])
        i += 1

    return xorarray


# score a string based on alpha frequency
def alphascore(binstring: bytes) -> int:
    """scores a string based upon frequency of alpha characters"""
    stringlength = len(binstring)
    alphacount = 0

    for char in binstring:
        if char >= 65 and char <= 90:
            alphacount += 1
        elif char >= 97 and char <= 122:
            alphacount += 1
        elif char == 32:
            alphacount += 1
        elif char == 39:
            alphacount += 1

    return alphacount


# decrypt xor cipher without key
def xordecode(ciphertext: str) -> str:
    """ return output of cracking xor'd buffer, as bytes"""

    highestscore = 0
    output = ''
    ALPHABET = b'abcdefghijklmnopqrstufwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    binaryciphertext = binascii.unhexlify(ciphertext)
   
    for char in ALPHABET:
        binarray = bytearray()

        for x in binaryciphertext:
            binarray.append(char ^ x)

        score = alphascore(binarray)
        if score > highestscore:
            highestscore = score
            output = binarray.decode()

    return output

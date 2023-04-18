import binascii
import crypto
import unittest

class TestCryptofunctions(unittest.TestCase):

    def test_hex2base64(self):
        hexstring = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected_output = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(crypto.hex2base64(hexstring), expected_output)

    def test_fixedxor(self):
        hex1 = '1c0111001f010100061a024b53535009181c'
        hex2 = '686974207468652062756c6c277320657965'
        expected_output = binascii.unhexlify('746865206b696420646f6e277420706c6179')
        self.assertEqual(crypto.fixedxor(hex1, hex2), expected_output)

    def test_xordecode(self):
        ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        self.assertEqual(crypto.xordecode(ciphertext), "Cooking MC's like a pound of bacon")

if __name__ == '__main__':
    unittest.main()
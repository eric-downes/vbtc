import sys, os
import binascii
import hashlib
from typing import *

if sys.version_info.major == 3:
    string_types = (str)
    string_or_bytes_types = (str, bytes)
    int_types = (int, float)
    # Base switching
    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
        256: ''.join([chr(x) for x in range(256)])
    }

    def bin_dbl_sha256(s):
        bytes_to_hash = from_string_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg

    def get_code_string(base):
        if base in code_strings:
            return code_strings[base]
        else:
            raise ValueError("Invalid base!")

    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        return encode(decode(string, frm), to, minlen)

    def bin_to_b58check(inp, magicbyte=0):
        if magicbyte == 0:
            inp = from_int_to_byte(0) + inp
        while magicbyte > 0:
            inp = from_int_to_byte(magicbyte % 256) + inp
            magicbyte //= 256

        leadingzbytes = 0
        for x in inp:
            if x != 0:
                break
            leadingzbytes += 1

        checksum = bin_dbl_sha256(inp)[:4]
        return '1' * leadingzbytes + changebase(inp+checksum, 256, 58)

    def bytes_to_hex_string(b):
        if isinstance(b, str):
            return b

        return ''.join('{:02x}'.format(y) for y in b)

    def safe_from_hex(s):
        return bytes.fromhex(s)

    def from_int_representation_to_bytes(a):
        return bytes(str(a), 'utf-8')

    def from_int_to_byte(a):
        return bytes([a])

    def from_byte_to_int(a):
        return a

    def from_string_to_bytes(a):
        return a if isinstance(a, bytes) else bytes(a, 'utf-8')

    def safe_hexlify(a):
        return str(binascii.hexlify(a), 'utf-8')

    def encode(val:int, base:int, minlen:int = 0) -> Union[bytes, str]:        
        code_string = get_code_string(base)
        def padding(pad_size:int, base:int) -> bytes:
            if not pad_size: return b''
            pad_element = bytes([ord(code_string[0])])
            return pad_element * pad_size
        
        result_bytes = bytes()
        while val:
            curcode = code_string[val % base]
            result_bytes = bytes([ord(curcode)]) + result_bytes
            val //= base
        pad_size = max(0, minlen - len(result_bytes))
        result_bytes = padding(pad_size, base) + result_bytes
        return result_bytes if base == 256 else ''.join([chr(y) for y in result_bytes])

    def decode(string, base):
        if base == 256 and isinstance(string, str):
            string = bytes(bytearray.fromhex(string))
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 256:
            def extract(d, cs):
                return d
        else:
            def extract(d, cs):
                return cs.find(d if isinstance(d, str) else chr(d))

        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += extract(string[0], code_string)
            string = string[1:]
        return result

    def random_string(x):
        return str(os.urandom(x))

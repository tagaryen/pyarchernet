SBOX = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
]

FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

def generate_ck():
    CK = []
    for i in range(32):
        ck_i = 0
        for j in range(4):
            byte_val = ((4 * i + j) * 7) & 0xFF
            ck_i = (ck_i << 8) | byte_val
        CK.append(ck_i)
    return CK

CK = generate_ck()

def rotl_32(x, n):
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def bytes_to_words(data):
    return [
        int.from_bytes(data[0:4], 'big'),
        int.from_bytes(data[4:8], 'big'),
        int.from_bytes(data[8:12], 'big'),
        int.from_bytes(data[12:16], 'big')
    ]


def words_to_bytes(words):
    result = bytearray()
    for word in words:
        result.extend(word.to_bytes(4, 'big'))
    return bytes(result)

def tau(a):
    return (SBOX[(a >> 24) & 0xFF] << 24) | \
           (SBOX[(a >> 16) & 0xFF] << 16) | \
           (SBOX[(a >> 8) & 0xFF] << 8) | \
           (SBOX[a & 0xFF])


def linear_l(b):
    return b ^ rotl_32(b, 2) ^ rotl_32(b, 10) ^ rotl_32(b, 18) ^ rotl_32(b, 24)


def linear_l_prime(b):
    return b ^ rotl_32(b, 13) ^ rotl_32(b, 23)


def t(b):
    return linear_l(tau(b))


def t_prime(b):
    return linear_l_prime(tau(b))

def expand_key(key_bytes):
    if len(key_bytes) != 16:
        raise ValueError("Invalid key length")
    MK = bytes_to_words(key_bytes)
    K = [MK[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        k_next = K[i] ^ t_prime(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i])
        K.append(k_next)
        rk.append(k_next)
    
    return rk

def sm4_encrypt_block(plaintext_bytes, rk):
    if len(plaintext_bytes) != 16:
        raise ValueError("Block size must be 16")
    X = bytes_to_words(plaintext_bytes)
    for i in range(32):
        X_next = X[i] ^ t(X[i+1] ^ X[i+2] ^ X[i+3] ^ rk[i])
        X.append(X_next)
    Y = [X[35], X[34], X[33], X[32]]
    return words_to_bytes(Y)


def sm4_decrypt_block(ciphertext_bytes, rk):
    if len(ciphertext_bytes) != 16:
        raise ValueError("Block size must be 16")
    rk_rev = rk[::-1]
    return sm4_encrypt_block(ciphertext_bytes, rk_rev)

def pkcs7_pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data):
    if not data:
        return data
    padding_len = data[-1]
    if padding_len > len(data) or padding_len > 16:
        raise ValueError("Invalid PKCS7")
    return data[:-padding_len]


def sm4_encrypt_ecb(key_bytes, plaintext_bytes):
    rk = expand_key(key_bytes)
    plaintext_bytes = pkcs7_pad(plaintext_bytes)
    ciphertext = bytearray()
    for i in range(0, len(plaintext_bytes), 16):
        block = plaintext_bytes[i:i+16]
        ciphertext.extend(sm4_encrypt_block(block, rk))
    
    return bytes(ciphertext)


def sm4_decrypt_ecb(key_bytes, ciphertext_bytes):
    rk = expand_key(key_bytes)
    
    if len(ciphertext_bytes) % 16 != 0:
        raise ValueError("Invalid cipher text")
    
    plaintext = bytearray()
    for i in range(0, len(ciphertext_bytes), 16):
        block = ciphertext_bytes[i:i+16]
        plaintext.extend(sm4_decrypt_block(block, rk))
    return pkcs7_unpad(bytes(plaintext))

def sm4_encrypt_cbc(key_bytes, iv_bytes, plaintext_bytes):
    if len(iv_bytes) != 16:
        raise ValueError("IV长度必须为16字节")
    
    rk = expand_key(key_bytes)
    
    plaintext_bytes = pkcs7_pad(plaintext_bytes)
    
    ciphertext = bytearray()
    prev_block = iv_bytes
    
    for i in range(0, len(plaintext_bytes), 16):
        block = plaintext_bytes[i:i+16]
        xored = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted = sm4_encrypt_block(xored, rk)
        ciphertext.extend(encrypted)
        prev_block = encrypted
    
    return bytes(ciphertext)


def sm4_decrypt_cbc(key_bytes, iv_bytes, ciphertext_bytes):
    if len(iv_bytes) != 16:
        raise ValueError("Invalid iv length")
    
    rk = expand_key(key_bytes)
    
    if len(ciphertext_bytes) % 16 != 0:
        raise ValueError("Invalid cipher length")
    
    plaintext = bytearray()
    prev_block = iv_bytes
    
    for i in range(0, len(ciphertext_bytes), 16):
        block = ciphertext_bytes[i:i+16]
        decrypted = sm4_decrypt_block(block, rk)
        xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
        plaintext.extend(xored)
        prev_block = block
    
    return pkcs7_unpad(bytes(plaintext))

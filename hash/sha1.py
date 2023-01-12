import os



H = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]



def ROTL(n, x, w=32):
    return ((x << n) | (x >> w - n))



def padding(message: bytes) -> bytes:
    """
    Padding Message to a multiple of 512 bits (multiple of 64 Bytes)
    
    Input:
        (bytes) b"hello"
    
    Output:
        (bytes) b'hello\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00('
    """

    """
    EXPLAINATION:
    l + len("10000000") + n_zeros + last_64bits mod 64 == 0
        l (bytes)
        len("1000000") == 1
        last_64bits == 128bits == 16Bytes
    """

    l = len(message) # bytes
    lhex = hex(l*8)[2:].rjust(16, "0")
    last_64bits = [int(lhex[i:i+2], 16) for i in range(0, 16, 2)]

    n_zeros = (55 - l) % 64
    if not n_zeros:
        n_zeros = 64

    message += bytes([0b10000000])
    message += bytes(n_zeros)
    message += bytes(last_64bits)

    return message



def prepare(message: bytes) -> list:
    """
    divide message after padding to n 512-bits-blocks M1, M2, ..., Mn
    
    Input:
        (bytes) b'hello\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00('
    
    Output:
        (list)(int) [[1751477356, 1870659584, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40]]
    """
    M = []
    n_blocks = len(message) // 64

    for i in range(n_blocks):  # 64 Bytes per Block
        m = []
        for j in range(16):  # 16 Words per Block
            n = 0
            for k in range(4):  # 4 Bytes per Word
                n <<= 8
                n += message[i*64 + j*4 + k]
            m.append(n)
        M.append(m)
    return M



def process_block(block):
    """
    process each block
    """
    MODULO = 2**32-1

    W = block
    for t in range(16, 80):
        W.append(ROTL(1, (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])) & MODULO)

    a, b, c, d, e = H

    for t in range(80):
        if t <= 19:
            K = 0x5a827999
            f = (b & c) ^ (~b & d)
        elif t <= 39:
            K = 0x6ed9eba1
            f = b ^ c ^ d
        elif t <= 59:
            K = 0x8f1bbcdc
            f = (b & c) ^ (b & d) ^ (c & d)
        else:
            K = 0xca62c1d6
            f = b ^ c ^ d

        T = ((ROTL(5, a) + f + e + K + W[t]) & MODULO)
        e = d
        d = c
        c = ROTL(30, b) & MODULO
        b = a
        a = T

    H[0] = (a + H[0]) & MODULO
    H[1] = (b + H[1]) & MODULO
    H[2] = (c + H[2]) & MODULO
    H[3] = (d + H[3]) & MODULO
    H[4] = (e + H[4]) & MODULO



def hash(message: str) -> str:
    """
    input:
        (str) "hello"
    output:
        (str) "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    """
    message = bytes(message, "utf-8")

    message = padding(message)

    message = prepare(message)

    for block in message:
        process_block(block)
    result = ''
    for h in H:
        result += (hex(h)[2:]).rjust(8, '0')
    return result



if __name__ == "__main__":
    os.system("cls")
    message = "hello"
    result = hash(message)
    print(message)
    print(result)

import sys

K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]

H_INIT = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]


def rotr_int(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def ch(x, y, z):
    return (x & y) ^ (~x & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def sigma0_int(x):
    return rotr_int(x, 2) ^ rotr_int(x, 13) ^ rotr_int(x, 22)


def sigma1_int(x):
    return rotr_int(x, 6) ^ rotr_int(x, 11) ^ rotr_int(x, 25)


def rotr(bits, nb):
    if not bits:
        return ""
    n = int(bits, 2)
    mask = (1 << len(bits)) - 1
    nb = nb % len(bits)
    rotated = (n >> nb) | ((n & ((1 << nb) - 1)) << (len(bits) - nb))
    return format(rotated & mask, f"0{len(bits)}b")


def shiftr(bits, nb):
    if not bits:
        return ""
    return "0" * nb + bits[:-nb] if nb < len(bits) else "0" * len(bits)


def xor(bits1, bits2):
    return "".join("1" if bit1 != bit2 else "0" for bit1, bit2 in zip(bits1, bits2))


def sigma0(bits):
    return xor(xor(rotr(bits, 7), rotr(bits, 18)), shiftr(bits, 3))


def sigma1(bits):
    return xor(xor(rotr(bits, 17), rotr(bits, 19)), shiftr(bits, 10))


def conversionBinaire(message):
    return "".join(["{0:08b}".format(x) for x in message.encode("utf-8")])


def remplissage(message):
    bits = conversionBinaire(message)
    message_size = format(len(message.encode("utf-8")) * 8, "064b")
    bits += "1"
    bits += "0" * ((512 - 64) - len(bits) % 512)
    bits += message_size
    return bits


def décomposition(bits):
    return [bits[i : i + 32] for i in range(0, len(bits), 32)]


def newMot(bits, t):
    s1 = int(sigma1(bits[t - 2]), 2)
    w7 = int(bits[t - 7], 2)
    s0 = int(sigma0(bits[t - 15]), 2)
    w16 = int(bits[t - 16], 2)
    result = (s1 + w7 + s0 + w16) % (2**32)
    return format(result, "032b")


def genererListMot(word):
    for i in range(16, 64):
        word.append(newMot(word, i))
    return word


def iterateHash(word, H):
    S = H.copy()
    for i in range(64):
        w_int = int(word[i], 2)
        T1 = (
            S[7] + sigma1_int(S[4]) + ch(S[4], S[5], S[6]) + K[i] + w_int
        ) & 0xFFFFFFFF
        T2 = (sigma0_int(S[0]) + maj(S[0], S[1], S[2])) & 0xFFFFFFFF
        S[7] = S[6]
        S[6] = S[5]
        S[5] = S[4]
        S[4] = (S[3] + T1) & 0xFFFFFFFF
        S[3] = S[2]
        S[2] = S[1]
        S[1] = S[0]
        S[0] = (T1 + T2) & 0xFFFFFFFF
    for i in range(8):
        H[i] = (H[i] + S[i]) & 0xFFFFFFFF
    return H


def sha256(message):
    H = H_INIT.copy()
    bin_str = remplissage(message)

    for i in range(0, len(bin_str), 512):
        block = bin_str[i : i + 512]
        word = genererListMot(décomposition(block))
        H = iterateHash(word, H)

    result = ""
    for h in H:
        result += format(h, "08x")
    return result


if __name__ == "__main__":
    message = sys.argv[1]
    result = sha256(message)

    print(f"SHA-256 de '{message}': {result}")


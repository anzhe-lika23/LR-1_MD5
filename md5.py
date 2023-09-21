import math

# Функції для MD5
def F(X, Y, Z):
    return (X & Y) | (~X & Z)

def G(X, Y, Z):
    return (X & Z) | (Y & ~Z)

def H(X, Y, Z):
    return X ^ Y ^ Z

def I(X, Y, Z):
    return Y ^ (X | ~Z)

# Змінні для констант
H0 = 0x67452301
H1 = 0xEFCDAB89
H2 = 0x98BADCFE
H3 = 0x10325476

# Функція для обчислення MD5 хеша
def md5(data):
    # Попередні обчислені значення y
    y = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    # Масиви для порядку та бітових зсувів
    z = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
        5, 8, 11, 4, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
        0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
    ]

    s = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ]

    # Додати біт "1" до даних
    data += b'\x80'

    # Визначити довжину
    data_len = len(data) * 8

    # Доповнити до 448 бітів
    while len(data) % 64 != 56:
        data += b'\x00'

    # Додати довжину в кінці у вигляді 64-бітного числа
    data += data_len.to_bytes(8, byteorder='little')

    # Ініціалізація змінних
    A, B, C, D = H0, H1, H2, H3

    # Розділити дані на блоки по 512 бітів
    for i in range(0, len(data), 64):
        chunk = data[i:i + 64]
        X = [int.from_bytes(chunk[j:j + 4], byteorder='little') for j in range(0, 64, 4)]

        AA, BB, CC, DD = A, B, C, D

        # Головний цикл обчислення хеша MD5
        for j in range(64):
            if j < 16:
                F_result = F(B, C, D)
                g = j
            elif j < 32:
                F_result = G(B, C, D)
                g = (5 * j + 1) % 16
            elif j < 48:
                F_result = H(B, C, D)
                g = (3 * j + 5) % 16
            else:
                F_result = I(B, C, D)
                g = (7 * j) % 16

            T = (A + F_result + X[g] + y[j]) & 0xFFFFFFFF
            A = D
            D = C
            C = B
            B = (B + ((T << s[j]) | (T >> (32 - s[j]))) & 0xFFFFFFFF) & 0xFFFFFFFF

        # Додати результат до попередніх значень
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    # Об'єднати 4 змінні в одну 128-бітну змінну
    result = (A | (B << 32) | (C << 64) | (D << 96)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

    return result.to_bytes(16, byteorder='little')


# Приклад використання
if __name__ == "__main__":
    data = b'hello world'
    md5_hash = md5(data)
    print("MD5 Hash:", md5_hash.hex())

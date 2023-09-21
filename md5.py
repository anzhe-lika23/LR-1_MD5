import struct
from enum import Enum
from math import (
    floor,
    sin,
)

from bitarray import bitarray


class MD5Buffer(Enum):
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476


class MD5(object):
    _string = None
    _buffers = {
        MD5Buffer.A: None,
        MD5Buffer.B: None,
        MD5Buffer.C: None,
        MD5Buffer.D: None,
    }

    @classmethod
    def hash(cls, string):
        cls._string = string

        preprocessed_bit_array = cls._step_2(cls._step_1())
        cls._step_3()
        cls._step_4(preprocessed_bit_array)
        return cls._step_5()

    @classmethod
    def _step_1(cls):
        # Convert the string to a bit array.
        bit_array = bitarray(endian="big")
        bit_array.frombytes(cls._string.encode("utf-8"))

        # Pad the string with a 1 bit and as many 0 bits required such that
        # the length of the bit array becomes congruent to 448 modulo 512.
        # Note that padding is always performed, even if the string's bit
        # length is already conguent to 448 modulo 512, which leads to a
        # new 512-bit message block.
        bit_array.append(1)
        while len(bit_array) % 512 != 448:
            bit_array.append(0)

        # For the remainder of the MD5 algorithm, all values are in
        # little endian, so transform the bit array to little endian.
        return bitarray(bit_array, endian="little")

    @classmethod
    def _step_2(cls, step_1_result):
        # Extend the result from step 1 with a 64-bit little endian
        # representation of the original message length (modulo 2^64).
        length = (len(cls._string) * 8) % pow(2, 64)
        length_bit_array = bitarray(endian="little")
        length_bit_array.frombytes(struct.pack("<Q", length))

        result = step_1_result.copy()
        result.extend(length_bit_array)
        return result

    @classmethod
    def _step_3(cls):
        # Initialize the buffers to their default values.
        for buffer_type in cls._buffers.keys():
            cls._buffers[buffer_type] = buffer_type.value

    @classmethod
    def _step_4(cls, step_2_result):
        # Define the four auxiliary functions that produce one 32-bit word.
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & z) | (y & ~z)
        H = lambda x, y, z: x ^ y ^ z
        I = lambda x, y, z: y ^ (x | ~z)

        # Define the left rotation function, which rotates `x` left `n` bits.
        rotate_left = lambda x, n: (x << n) | (x >> (32 - n))

        # Define a function for modular addition.
        modular_add = lambda a, b: (a + b) % pow(2, 32)

        # Compute the T table from the sine function. Note that the
        # RFC starts at index 1, but we start at index 0.
        T = [floor(pow(2, 32) * abs(sin(i + 1))) for i in range(64)]

        # The total number of 32-bit words to process, N, is always a
        # multiple of 16.
        N = len(step_2_result) // 32

        # Process chunks of 512 bits.
        for chunk_index in range(N // 16):
            # Break the chunk into 16 words of 32 bits in list X.
            start = chunk_index * 512
            X = [step_2_result[start + (x * 32) : start + (x * 32) + 32] for x in range(16)]

            # Convert the `bitarray` objects to integers.
            X = [int.from_bytes(word.tobytes(), byteorder="little") for word in X]

            # Make shorthands for the buffers A, B, C and D.
            A = cls._buffers[MD5Buffer.A]
            B = cls._buffers[MD5Buffer.B]
            C = cls._buffers[MD5Buffer.C]
            D = cls._buffers[MD5Buffer.D]

            # Execute the four rounds with 16 operations each.
            for i in range(4 * 16):
                if 0 <= i <= 15:
                    k = i
                    s = [7, 12, 17, 22]
                    temp = F(B, C, D)
                elif 16 <= i <= 31:
                    k = ((5 * i) + 1) % 16
                    s = [5, 9, 14, 20]
                    temp = G(B, C, D)
                elif 32 <= i <= 47:
                    k = ((3 * i) + 5) % 16
                    s = [4, 11, 16, 23]
                    temp = H(B, C, D)
                elif 48 <= i <= 63:
                    k = (7 * i) % 16
                    s = [6, 10, 15, 21]
                    temp = I(B, C, D)

                # The MD5 algorithm uses modular addition. Note that we need a
                # temporary variable here. If we would put the result in `A`, then
                # the expression `A = D` below would overwrite it. We also cannot
                # move `A = D` lower because the original `D` would already have
                # been overwritten by the `D = C` expression.
                temp = modular_add(temp, X[k])
                temp = modular_add(temp, T[i])
                temp = modular_add(temp, A)
                temp = rotate_left(temp, s[i % 4])
                temp = modular_add(temp, B)

                # Swap the registers for the next operation.
                A = D
                D = C
                C = B
                B = temp

            # Update the buffers with the results from this chunk.
            cls._buffers[MD5Buffer.A] = modular_add(cls._buffers[MD5Buffer.A], A)
            cls._buffers[MD5Buffer.B] = modular_add(cls._buffers[MD5Buffer.B], B)
            cls._buffers[MD5Buffer.C] = modular_add(cls._buffers[MD5Buffer.C], C)
            cls._buffers[MD5Buffer.D] = modular_add(cls._buffers[MD5Buffer.D], D)

    @classmethod
    def _step_5(cls):
        # Convert the buffers to little-endian.
        A = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.A]))[0]
        B = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.B]))[0]
        C = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.C]))[0]
        D = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.D]))[0]

        # Output the buffers in lower-case hexadecimal format.
        return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}"

a = MD5()
print(a.hash('hello'))
# import math
#
# # Функції для MD5
# def F(X, Y, Z):
#     return (X & Y) | (~X & Z)
#
# def G(X, Y, Z):
#     return (X & Z) | (Y & ~Z)
#
# def H(X, Y, Z):
#     return X ^ Y ^ Z
#
# def I(X, Y, Z):
#     return Y ^ (X | ~Z)
#
# # Змінні для констант
# H0 = 0x67452301
# H1 = 0xEFCDAB89
# H2 = 0x98BADCFE
# H3 = 0x10325476
#
# # Функція для обчислення MD5 хеша
# def md5(data):
#     # Попередні обчислені значення y
#     y = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
#
#     # Масиви для порядку та бітових зсувів
#     z = [
#         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
#         1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
#         5, 8, 11, 4, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
#         0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
#     ]
#
#     s = [
#         7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
#         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
#         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
#         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
#     ]
#
#     # Додати біт "1" до даних
#     data += b'\x80'
#
#     # Визначити довжину
#     data_len = len(data) * 8
#
#     # Доповнити до 448 бітів
#     while len(data) % 64 != 56:
#         data += b'\x00'
#
#     # Додати довжину в кінці у вигляді 64-бітного числа
#     data += data_len.to_bytes(8, byteorder='little')
#
#     # Ініціалізація змінних
#     A, B, C, D = H0, H1, H2, H3
#
#     # Розділити дані на блоки по 512 бітів
#     for i in range(0, len(data), 64):
#         chunk = data[i:i + 64]
#         X = [int.from_bytes(chunk[j:j + 4], byteorder='little') for j in range(0, 64, 4)]
#
#         AA, BB, CC, DD = A, B, C, D
#
#         # Головний цикл обчислення хеша MD5
#         for j in range(64):
#             if j < 16:
#                 F_result = F(B, C, D)
#                 g = j
#             elif j < 32:
#                 F_result = G(B, C, D)
#                 g = (5 * j + 1) % 16
#             elif j < 48:
#                 F_result = H(B, C, D)
#                 g = (3 * j + 5) % 16
#             else:
#                 F_result = I(B, C, D)
#                 g = (7 * j) % 16
#
#             T = (A + F_result + X[g] + y[j]) & 0xFFFFFFFF
#             A = D
#             D = C
#             C = B
#             B = (B + ((T << s[j]) | (T >> (32 - s[j]))) & 0xFFFFFFFF) & 0xFFFFFFFF
#
#         # Додати результат до попередніх значень
#         A = (A + AA) & 0xFFFFFFFF
#         B = (B + BB) & 0xFFFFFFFF
#         C = (C + CC) & 0xFFFFFFFF
#         D = (D + DD) & 0xFFFFFFFF
#
#     # Об'єднати 4 змінні в одну 128-бітну змінну
#     result = (A | (B << 32) | (C << 64) | (D << 96)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
#
#     return result.to_bytes(16, byteorder='little')
#
#
# # Приклад використання
# if __name__ == "__main__":
#     data = b'hello world'
#     md5_hash = md5(data)
#     print("MD5 Hash:", md5_hash.hex())

# https://perso.crans.org/besson/publis/notebooks/Manual_implementation_of_some_hash_functions.html

import math


# This list maintains the amount by which to rotate the buffers during processing stage
rotate_by = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
             5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
             4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
             6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

# This list maintains the additive constant to be added in each processing step.
constants = [int(abs(math.sin(i + 1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]


# STEP 1: append padding bits s.t. the length is congruent to 448 modulo 512
# which is equivalent to saying 56 modulo 64.
# padding before adding the length of the original message is conventionally done as:
# pad a one followed by zeros to become congruent to 448 modulo 512(or 56 modulo 64).
def pad(msg):
    msg_len_in_bits = (8 * len(msg)) & 0xffffffffffffffff
    msg.append(0x80)

    while len(msg) % 64 != 56:
        msg.append(0)

    # STEP 2: append a 64-bit version of the length of the length of the original message
    # in the unlikely event that the length of the message is greater than 2^64,
    # only the lower order 64 bits of the length are used.

    # sys.byteorder -> 'little'
    msg += msg_len_in_bits.to_bytes(8, byteorder='little')  # little endian convention
    # to_bytes(8...) will return the lower order 64 bits(8 bytes) of the length.

    return msg


# STEP 3: initialise message digest buffer.
# MD buffer is 4 words A, B, C and D each of 32-bits.

init_MDBuffer = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


# UTILITY/HELPER FUNCTION:
def leftRotate(x, amount):
    x &= 0xFFFFFFFF
    return (x << amount | x >> (32 - amount)) & 0xFFFFFFFF


# STEP 4: process the message in 16-word blocks
# Message block stored in buffers is processed in the follg general manner:
# A = B + rotate left by some amount<-(A + func(B, C, D) + additive constant + 1 of the 16 32-bit(4 byte) blocks converted to int form)

def processMessage(msg):
    init_temp = init_MDBuffer[
                :]  # create copy of the buffer init constants to preserve them for when message has multiple 512-bit blocks

    # message length is a multiple of 512bits, but the processing is to be done separately for every 512-bit block.
    for offset in range(0, len(msg), 64):
        A, B, C, D = init_temp  # have to initialise MD Buffer for every block
        block = msg[offset: offset + 64]  # create block to be processed
        # msg is processed as chunks of 16-words, hence, 16 such 32-bit chunks
        for i in range(64):  # 1 pass through the loop processes some 32 bits out of the 512-bit block.
            if i < 16:
                # Round 1
                func = lambda b, c, d: (b & c) | (~b & d)
                # if b is true then ans is c, else d.
                index_func = lambda i: i

            elif i >= 16 and i < 32:
                # Round 2
                func = lambda b, c, d: (d & b) | (~d & c)
                # if d is true then ans is b, else c.
                index_func = lambda i: (5 * i + 1) % 16

            elif i >= 32 and i < 48:
                # Round 3
                func = lambda b, c, d: b ^ c ^ d
                # Parity of b, c, d
                index_func = lambda i: (3 * i + 5) % 16

            elif i >= 48 and i < 64:
                # Round 4
                func = lambda b, c, d: c ^ (b | ~d)
                index_func = lambda i: (7 * i) % 16

            F = func(B, C, D)  # operate on MD Buffers B, C, D
            G = index_func(
                i)  # select one of the 32-bit words from the 512-bit block of the original message to operate on.

            to_rotate = A + F + constants[i] + int.from_bytes(block[4 * G: 4 * G + 4], byteorder='little')
            newB = (B + leftRotate(to_rotate, rotate_by[i])) & 0xFFFFFFFF

            A, B, C, D = D, newB, B, C
        # rotate the contents of the 4 MD buffers by one every pass through the loop

        # Add the final output of the above stage to initial buffer states
        for i, val in enumerate([A, B, C, D]):
            init_temp[i] += val
            init_temp[i] &= 0xFFFFFFFF
    # The init_temp list now holds the MD(in the form of the 4 buffers A, B, C, D) of the 512-bit block of the message fed.

    # The same process is to be performed for every 512-bit block to get the final MD(message digest).

    # Construct the final message from the final states of the MD Buffers
    return sum(buffer_content << (32 * i) for i, buffer_content in enumerate(init_temp))


def MD_to_hex(digest):
    # takes MD from the processing stage, change its endian-ness and return it as 128-bit hex hash
    raw = digest.to_bytes(16, byteorder='little')
    return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))


def md5(msg):
    msg = bytearray(msg, 'ascii')  # create a copy of the original message in form of a sequence of integers [0, 256)
    msg = pad(msg)
    processed_msg = processMessage(msg)
    # processed_msg contains the integer value of the hash
    message_hash = MD_to_hex(processed_msg)
    print("Message Hash: ", message_hash)


if __name__ == '__main__':
    message = input()
    md5(message)



# import math
#
# rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
#                   5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
#                   4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
#                   6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
#
# constants = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
#
# init_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
#
# functions = 16*[lambda b, c, d: (b & c) | (~b & d)] + \
#             16*[lambda b, c, d: (d & b) | (~d & c)] + \
#             16*[lambda b, c, d: b ^ c ^ d] + \
#             16*[lambda b, c, d: c ^ (b | ~d)]
#
# index_functions = 16*[lambda i: i] + \
#                   16*[lambda i: (5*i + 1)%16] + \
#                   16*[lambda i: (3*i + 5)%16] + \
#                   16*[lambda i: (7*i)%16]
#
# def left_rotate(x, amount):
#     x &= 0xFFFFFFFF
#     return ((x<<amount) | (x>>(32-amount))) & 0xFFFFFFFF
#
# def md5(message):
#
#     message = bytearray(message) #copy our input into a mutable buffer
#     orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
#     message.append(0x80)
#     while len(message)%64 != 56:
#         message.append(0)
#     message += orig_len_in_bits.to_bytes(8, byteorder='little')
#
#     hash_pieces = init_values[:]
#
#     for chunk_ofst in range(0, len(message), 64):
#         a, b, c, d = hash_pieces
#         chunk = message[chunk_ofst:chunk_ofst+64]
#         for i in range(64):
#             f = functions[i](b, c, d)
#             g = index_functions[i](i)
#             to_rotate = a + f + constants[i] + int.from_bytes(chunk[4*g:4*g+4], byteorder='little')
#             new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
#             a, b, c, d = d, new_b, b, c
#         for i, val in enumerate([a, b, c, d]):
#             hash_pieces[i] += val
#             hash_pieces[i] &= 0xFFFFFFFF
#
#     return sum(x<<(32*i) for i, x in enumerate(hash_pieces))
#
# def md5_to_hex(digest):
#     raw = digest.to_bytes(16, byteorder='little')
#     return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))
#
# if __name__=='__main__':
#     demo = [b"", b"a", b"abc", b"message digest", b"abcdefghijklmnopqrstuvwxyz",
#             b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
#             b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"]
#     for message in demo:
#         print(md5_to_hex(md5(message)),' <= "',message.decode('ascii'),'"', sep='')













# import struct
# from enum import Enum
# from math import (
#     floor,
#     sin,
# )
#
# from bitarray import bitarray
#
#
# class MD5Buffer(Enum):
#     A = 0x67452301
#     B = 0xEFCDAB89
#     C = 0x98BADCFE
#     D = 0x10325476
#
#
# class MD5(object):
#     _string = None
#     _buffers = {
#         MD5Buffer.A: None,
#         MD5Buffer.B: None,
#         MD5Buffer.C: None,
#         MD5Buffer.D: None,
#     }
#
#     @classmethod
#     def hash(cls, string):
#         cls._string = string
#
#         preprocessed_bit_array = cls._step_2(cls._step_1())
#         cls._step_3()
#         cls._step_4(preprocessed_bit_array)
#         return cls._step_5()
#
#     @classmethod
#     def _step_1(cls):
#         # Convert the string to a bit array.
#         bit_array = bitarray(endian="big")
#         bit_array.frombytes(cls._string.encode("utf-8"))
#
#         # Pad the string with a 1 bit and as many 0 bits required such that
#         # the length of the bit array becomes congruent to 448 modulo 512.
#         # Note that padding is always performed, even if the string's bit
#         # length is already conguent to 448 modulo 512, which leads to a
#         # new 512-bit message block.
#         bit_array.append(1)
#         while len(bit_array) % 512 != 448:
#             bit_array.append(0)
#
#         # For the remainder of the MD5 algorithm, all values are in
#         # little endian, so transform the bit array to little endian.
#         return bitarray(bit_array, endian="little")
#
#     @classmethod
#     def _step_2(cls, step_1_result):
#         # Extend the result from step 1 with a 64-bit little endian
#         # representation of the original message length (modulo 2^64).
#         length = (len(cls._string) * 8) % pow(2, 64)
#         length_bit_array = bitarray(endian="little")
#         length_bit_array.frombytes(struct.pack("<Q", length))
#
#         result = step_1_result.copy()
#         result.extend(length_bit_array)
#         return result
#
#     @classmethod
#     def _step_3(cls):
#         # Initialize the buffers to their default values.
#         for buffer_type in cls._buffers.keys():
#             cls._buffers[buffer_type] = buffer_type.value
#
#     @classmethod
#     def _step_4(cls, step_2_result):
#         # Define the four auxiliary functions that produce one 32-bit word.
#         F = lambda x, y, z: (x & y) | (~x & z)
#         G = lambda x, y, z: (x & z) | (y & ~z)
#         H = lambda x, y, z: x ^ y ^ z
#         I = lambda x, y, z: y ^ (x | ~z)
#
#         # Define the left rotation function, which rotates `x` left `n` bits.
#         rotate_left = lambda x, n: (x << n) | (x >> (32 - n))
#
#         # Define a function for modular addition.
#         modular_add = lambda a, b: (a + b) % pow(2, 32)
#
#         # Compute the T table from the sine function. Note that the
#         # RFC starts at index 1, but we start at index 0.
#         T = [floor(pow(2, 32) * abs(sin(i + 1))) for i in range(64)]
#
#         # The total number of 32-bit words to process, N, is always a
#         # multiple of 16.
#         N = len(step_2_result) // 32
#
#         # Process chunks of 512 bits.
#         for chunk_index in range(N // 16):
#             # Break the chunk into 16 words of 32 bits in list X.
#             start = chunk_index * 512
#             X = [step_2_result[start + (x * 32): start + (x * 32) + 32] for x in range(16)]
#
#             # Convert the `bitarray` objects to integers.
#             X = [int.from_bytes(word.tobytes(), byteorder="little") for word in X]
#
#             # Make shorthands for the buffers A, B, C and D.
#             A = cls._buffers[MD5Buffer.A]
#             B = cls._buffers[MD5Buffer.B]
#             C = cls._buffers[MD5Buffer.C]
#             D = cls._buffers[MD5Buffer.D]
#
#             # Execute the four rounds with 16 operations each.
#             for i in range(4 * 16):
#                 if 0 <= i <= 15:
#                     k = i
#                     s = [7, 12, 17, 22]
#                     temp = F(B, C, D)
#                 elif 16 <= i <= 31:
#                     k = ((5 * i) + 1) % 16
#                     s = [5, 9, 14, 20]
#                     temp = G(B, C, D)
#                 elif 32 <= i <= 47:
#                     k = ((3 * i) + 5) % 16
#                     s = [4, 11, 16, 23]
#                     temp = H(B, C, D)
#                 elif 48 <= i <= 63:
#                     k = (7 * i) % 16
#                     s = [6, 10, 15, 21]
#                     temp = I(B, C, D)
#
#                 # The MD5 algorithm uses modular addition. Note that we need a
#                 # temporary variable here. If we would put the result in `A`, then
#                 # the expression `A = D` below would overwrite it. We also cannot
#                 # move `A = D` lower because the original `D` would already have
#                 # been overwritten by the `D = C` expression.
#                 temp = modular_add(temp, X[k])
#                 temp = modular_add(temp, T[i])
#                 temp = modular_add(temp, A)
#                 temp = rotate_left(temp, s[i % 4])
#                 temp = modular_add(temp, B)
#
#                 # Swap the registers for the next operation.
#                 A = D
#                 D = C
#                 C = B
#                 B = temp
#
#             # Update the buffers with the results from this chunk.
#             cls._buffers[MD5Buffer.A] = modular_add(cls._buffers[MD5Buffer.A], A)
#             cls._buffers[MD5Buffer.B] = modular_add(cls._buffers[MD5Buffer.B], B)
#             cls._buffers[MD5Buffer.C] = modular_add(cls._buffers[MD5Buffer.C], C)
#             cls._buffers[MD5Buffer.D] = modular_add(cls._buffers[MD5Buffer.D], D)
#
#     @classmethod
#     def _step_5(cls):
#         # Convert the buffers to little-endian.
#         A = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.A]))[0]
#         B = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.B]))[0]
#         C = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.C]))[0]
#         D = struct.unpack("<I", struct.pack(">I", cls._buffers[MD5Buffer.D]))[0]
#
#         # Output the buffers in lower-case hexadecimal format.
#         return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}"
#
#
# if __name__ == "__main__":
#     input_string = "Cybersecurity"
#     md5_instance = MD5()
#     md5_hash = md5_instance.hash(input_string)
#     print(f"MD5 Hash of '{input_string}': {md5_hash}")
#
# # import math
# #
# # # Функції для MD5
# # def F(X, Y, Z):
# #     return (X & Y) | (~X & Z)
# #
# # def G(X, Y, Z):
# #     return (X & Z) | (Y & ~Z)
# #
# # def H(X, Y, Z):
# #     return X ^ Y ^ Z
# #
# # def I(X, Y, Z):
# #     return Y ^ (X | ~Z)
# #
# # # Змінні для констант
# # H0 = 0x67452301
# # H1 = 0xEFCDAB89
# # H2 = 0x98BADCFE
# # H3 = 0x10325476
# #
# # # Функція для обчислення MD5 хеша
# # def md5(data):
# #     # Попередні обчислені значення y
# #     y = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
# #
# #     # Масиви для порядку та бітових зсувів
# #     z = [
# #         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
# #         1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
# #         5, 8, 11, 4, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
# #         0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
# #     ]
# #
# #     s = [
# #         7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
# #         5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
# #         4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
# #         6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
# #     ]
# #
# #     # Додати біт "1" до даних
# #     data += b'\x80'
# #
# #     # Визначити довжину
# #     data_len = len(data) * 8
# #
# #     # Доповнити до 448 бітів
# #     while len(data) % 64 != 56:
# #         data += b'\x00'
# #
# #     # Додати довжину в кінці у вигляді 64-бітного числа
# #     data += data_len.to_bytes(8, byteorder='little')
# #
# #     # Ініціалізація змінних
# #     A, B, C, D = H0, H1, H2, H3
# #
# #     # Розділити дані на блоки по 512 бітів
# #     for i in range(0, len(data), 64):
# #         chunk = data[i:i + 64]
# #         X = [int.from_bytes(chunk[j:j + 4], byteorder='little') for j in range(0, 64, 4)]
# #
# #         AA, BB, CC, DD = A, B, C, D
# #
# #         # Головний цикл обчислення хеша MD5
# #         for j in range(64):
# #             if j < 16:
# #                 F_result = F(B, C, D)
# #                 g = j
# #             elif j < 32:
# #                 F_result = G(B, C, D)
# #                 g = (5 * j + 1) % 16
# #             elif j < 48:
# #                 F_result = H(B, C, D)
# #                 g = (3 * j + 5) % 16
# #             else:
# #                 F_result = I(B, C, D)
# #                 g = (7 * j) % 16
# #
# #             T = (A + F_result + X[g] + y[j]) & 0xFFFFFFFF
# #             A = D
# #             D = C
# #             C = B
# #             B = (B + ((T << s[j]) | (T >> (32 - s[j]))) & 0xFFFFFFFF) & 0xFFFFFFFF
# #
# #         # Додати результат до попередніх значень
# #         A = (A + AA) & 0xFFFFFFFF
# #         B = (B + BB) & 0xFFFFFFFF
# #         C = (C + CC) & 0xFFFFFFFF
# #         D = (D + DD) & 0xFFFFFFFF
# #
# #     # Об'єднати 4 змінні в одну 128-бітну змінну
# #     result = (A | (B << 32) | (C << 64) | (D << 96)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
# #
# #     return result.to_bytes(16, byteorder='little')
# #
# #
# # # Приклад використання
# # if __name__ == "__main__":
# #     data = b'hello world'
# #     md5_hash = md5(data)
# #     print("MD5 Hash:", md5_hash.hex())

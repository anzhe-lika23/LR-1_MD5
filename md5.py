import math
import time

rotation_constants = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

constants = [int(abs(math.sin(i + 1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]


def pad_message(msg):
    msg_len_in_bits = (8 * len(msg)) & 0xffffffffffffffff
    msg.append(0x80)

    while len(msg) % 64 != 56:
        msg.append(0)
    msg += msg_len_in_bits.to_bytes(8, byteorder='little')
    return msg


initial_buffer = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return (x << amount | x >> (32 - amount)) & 0xFFFFFFFF


def process_message(msg):
    init_temp = initial_buffer[:]

    for offset in range(0, len(msg), 64):
        a, b, c, d = init_temp
        block = msg[offset: offset + 64]
        for i in range(64):
            func = None
            index_func = None
            local_b = b

            if i < 16:
                def func(b_inner, c_inner, d_inner):
                    return (b_inner & c_inner) | (~b_inner & d_inner)

                def index_func(i_inner):
                    return i_inner

            elif (i >= 16) and (i < 32):
                def func(b_inner, c_inner, d_inner):
                    return (d_inner & b_inner) | (~d_inner & c_inner)

                def index_func(i_inner):
                    return (5 * i_inner + 1) % 16

            elif (i >= 32) and (i < 48):
                def func(b_inner, c_inner, d_inner):
                    return b_inner ^ c_inner ^ d_inner

                def index_func(i_inner):
                    return (3 * i_inner + 5) % 16

            elif (i >= 48) and (i < 64):
                def func(b_inner, c_inner, d_inner):
                    return c_inner ^ (b_inner | ~d_inner)

                def index_func(i_inner):
                    return (7 * i_inner) % 16

            f = func(local_b, c, d)
            g = index_func(i)

            to_rotate = a + f + constants[i] + int.from_bytes(block[4 * g: 4 * g + 4], byteorder='little')
            new_b = (b + left_rotate(to_rotate, rotation_constants[i])) & 0xFFFFFFFF

            a, b, c, d = d, new_b, b, c

        for i, val in enumerate([a, b, c, d]):
            init_temp[i] += val
            init_temp[i] &= 0xFFFFFFFF
    return sum(buffer_content << (32 * i) for i, buffer_content in enumerate(init_temp))


def digest_to_hex(digest):
    raw = digest.to_bytes(16, byteorder='little')
    return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))


def count_changed_bits(hash1, hash2):
    # Підрахунок кількості різних бітів між двома хешами
    xor_result = int(hash1, 16) ^ int(hash2, 16)
    return bin(xor_result).count('1')


def md5_hash(msg):
    msg = bytearray(msg, 'utf-8')
    msg = pad_message(msg)

    start_time = time.time()
    processed_msg = process_message(msg)
    message_hash = digest_to_hex(processed_msg)
    end_time = time.time()
    execution_time = end_time - start_time

    return message_hash, execution_time


if __name__ == '__main__':
    print(f"{'=' * 30}\n{' ' * 5}Hash-functions MD-5\n{'=' * 30}")
    message = input("Message input -> ")

    original_hash, original_execution_time = md5_hash(message)
    print(f"Message hash (origin) -> {original_hash}")
    print(f"Execution Time (origin): {original_execution_time:.6f} seconds")

    # Змінюємо один біт в тексті повідомлення
    modified_message = message[:1] + "a" + message[2:]
    modified_hash, modified_execution_time = md5_hash(modified_message)
    print(f"Modified message -> {modified_message}")
    print(f"Message hash (modified) -> {modified_hash}")

    # К-сть змінених біт
    changed_bits_count = count_changed_bits(original_hash, modified_hash)
    print(f"Number of Changed Bits: {changed_bits_count}")

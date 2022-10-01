def remaining_length_bytes(remaining_length):
    """Given the int value of remaining length, create the appropriate remaining length field value as per MQTT v5"""
    rem_length_bytes = []
    if remaining_length <= 127:  # 1 byte required for rem. length field
        rem_length_bytes.append(remaining_length)
    elif remaining_length <= 16383:  # 2 bytes required for rem. length field
        rem_length_bytes.append(remaining_length & 0x7F | 0x80)
        rem_length_bytes.append(remaining_length >> 7)
    elif remaining_length <= 2097151:  # 3 bytes required for rem. length field
        rem_length_bytes.append(remaining_length & 0x7F | 0x80)
        rem_length_bytes.append((remaining_length >> 7) & 0x7F | 0x80)
        rem_length_bytes.append(remaining_length >> 14)
    elif remaining_length <= 268435455:  # 4 bytes required for rem. length field
        rem_length_bytes.append(remaining_length & 0x7F | 0x80)
        rem_length_bytes.append((remaining_length >> 7) & 0x7F | 0x80)
        rem_length_bytes.append((remaining_length >> 14) & 0x7F | 0x80)
        rem_length_bytes.append((remaining_length >> 21))
    else:
        raise Exception("packet exceeds maximum size of 268435455 bytes")
    return rem_length_bytes


def get_remaining_length_int(data):
    """Extract remaining length from MQTT v5 connect packet. Removes fixed header from data"""
    if data[1] >> 7 == 0:
        rem_length = data[1] & 0x7F
        data_minus_fixed_header = data[2:]
    elif data[2] >> 7 == 0:
        rem_length = (data[1] & 0x7F) + (data[2] & 0x7F) * 128
        data_minus_fixed_header = data[3:]
    elif data[3] >> 7 == 0:
        rem_length = (data[1] & 0x7F) + (data[2] & 0x7F) * 128 + (data[3] & 0x7F) * 128 ** 2
        data_minus_fixed_header = data[4:]
    else:
        rem_length = (data[1] & 0x7F) + (data[2] & 0x7F) * 128 + (data[3] & 0x7F) * 128 ** 2 + (
                    data[4] & 0x7F) * 128 ** 3
        data_minus_fixed_header = data[5:]
    return data_minus_fixed_header, rem_length


def check_protocol_name_signature(protocol_name):
    return protocol_name[0] == ord('S') \
           and protocol_name[1] == ord('I') \
           and protocol_name[2] == ord('G') \
           and protocol_name[3] == ord('N') \
           and protocol_name[4] == ord('A') \
           and protocol_name[5] == ord('T')


"""This module contains validation of the configuration file and incoming RTEs"""

import socket
from kem.custom_errors import *


def get_parameter(data, config_option):
    """Returns the value of the given config_option, or raises an error if it does not exist in your config file."""
    try:
        return data[config_option]
    except KeyError:
        raise MissingParameterError(f"{config_option} does not exist in your config file.")


def check_valid_port(data, data_key):
    """Checks if the value at the given key in data is a valid port number
       A valid port number is a positive integer between 1024 and 64000"""
    port = get_parameter(data, data_key)
    if not isinstance(port, int):
        raise InvalidParameterError(f'{data_key} must be a positive integer. \n'
                                    f'The type given was {type(port)}')
    if port < 1024 or port > 64000:
        raise InvalidParameterError(f'{data_key} must be between 1024 and 64000. \n'
                                    f'The value given was {port}')
    return port


def check_valid_ip(data, data_key):
    """Checks if the value at the given key in data is a valid IP address"""
    ip = get_parameter(data, data_key)
    if not isinstance(ip, str):
        raise InvalidParameterError(f'{data_key} must be a string. \n'
                                    f'The type given was {type(ip)}')
    return ip


def check_client_id(data):
    """Check that client_id exists and is a string with length between 1 and 65535."""
    client_id = get_parameter(data, 'client_id')
    if not isinstance(client_id, str):
        raise InvalidParameterError(f'client_id must be a string. \n'
                                    f'The client_id type in the config file was: {type(client_id)}')
    if len(client_id) < 1 or len(client_id) > 65535:
        raise InvalidParameterError(f'client_id must be between 1 and 65535. \n'
                                    f'The client_id value in the config file was: {client_id}')
    return client_id


def check_packet_length(data):
    """Checks that the byte array is length 4 + 20n where n is an integer >= 0 and <= 25"""
    length = len(data)
    max_length = 504
    if length < 4:
        print("Packet is too short")
        return False
    if (length - 4) % 20 != 0:
        print("Packet length should be 4 + 20n where n is an integer")
        return False
    if length > max_length:
        print("Packet is too long. There must be no more than 25 RIP entries")
        return False
    return True


def check_cert_file_name(data, cert_file_name):
    """Ensures the cert_file_name is a string"""
    cert_file_name = get_parameter(data, cert_file_name)
    if not isinstance(cert_file_name, str):
        raise InvalidParameterError(f'cert_file_name must be a string. \n'
                                    f'The cert_file_name type in the config file was: {type(cert_file_name)}')
    return cert_file_name



def check_header(header):
    """Checks values in header list.
    Header list format: [command, version, router_id] """
    if len(header) != 3:
        print("Packet header has the wrong length")
        return False

    command = header[0]
    version = header[1]
    router_id = header[2]

    if command != 2:
        print(f"Command value of incoming packet is {command}, but should be 2")
        return False
    if version != 2:
        print(f"Version value of incoming packet is {version}, but should be 2")
        return False
    if router_id < 1 or router_id > 64000:  # TODO: discuss adding to config neighbours if not already there
        print(f"Router ID of incoming packet is {router_id}, but should be between 1 and 64000")
        return False

    return True


def check_rip_entry(rip_entry):
    """Checks the value in the RIP entry list.
    RIP entry list format: [af_inet, zeros_1, address, zeros_2, zeros_3, metric]"""
    if len(rip_entry) != 6:
        print("The following rip entry list has the wrong length:\n" + str(rip_entry))
        return False

    af_inet = rip_entry[0]
    zeros_1 = rip_entry[1]
    address = rip_entry[2]
    zeros_2 = rip_entry[3]
    zeros_3 = rip_entry[4]
    metric = rip_entry[5]

    if af_inet != socket.AF_INET:
        print(f"AFI value of incoming packet is {af_inet}, but should be {socket.AF_INET}")
        return False
    if zeros_1 != 0:
        print(f"The first zero section of the incoming packet was {zeros_1} not zero")
        return False

    if address < 1 or address > 64000:
        print(f"Address router ID of incoming RIP entry is {address}, but should be between 1 and 64000")
        return False

    if zeros_2 != 0:
        print(f"The second zero section of the incoming packet was {zeros_2} not zero")
        return False

    if zeros_3 != 0:
        print(f"The third zero section of the incoming packet was {zeros_3} not zero")
        return False

    if metric < 1 or metric > 16:
        print(f"Metric of incoming RIP entry is {metric}, but should be between 1 and 16")
        return False

    return True




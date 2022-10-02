import hashlib
import hmac
import random

import broker_config
import validate
import json
import select
from pqcrypto.kem.kyber512 import decrypt

from hkdf_interface import hkdf_expand, hkdf_extract
from signature_based.client.mqtt_client import KEY_LEN
from signature_based.packet_types import *
from signature_based.broker import validate
from signature_based import keys

from signature_based.custom_errors import *
from signature_based.util import remaining_length_bytes, get_remaining_length_int, check_protocol_name_signature

REASON_CODE = {
    "success": 0x00,
    "authFailed": 0x86
}


class MqttBroker:

    def __init__(self):
        """Checks that data provided in the config json is valid as according to assignment specifications"""
        self.socket_list = []
        self.client_records = []
        self.buffer_size = 1024
        self.secure = True
        with open('kem/broker/config_files/config.json') as json_file:
            data = json.load(json_file)
            input_ip = validate.check_valid_ip(data, "input_ip")
            input_port = validate.check_valid_port(data, "input_port")
            ca_cert_file_name = validate.check_ca_cert_file_name(data)
            self.config = broker_config.BrokerConfig(input_ip, input_port, [], ca_cert_file_name)
        ES = hkdf_extract(None, "")
        self.dES = hkdf_extract(ES, "derived")
        # these variables will be set following interactions with a client
        self.r_c = None
        self.r_s = None
        self.premaster_secret = None
        self.client_hello = None
        self.server_hello = None
        self.client_kem_ciphtertext = None
        self.client_finished = None
        self.dHS = None
        self.fk_s = None
        self.fk_c = None

    def monitor(self):
        """Monitors for incoming packets from clients and handles them appropriatley"""
        self.socket_list.append(self.config.listen_socket)
        while True:
            read_sockets, write_sockets, error_sockets = select.select(self.socket_list, [], [])

            if len(read_sockets) > 0:
                for read_socket in read_sockets:

                    if read_socket is self.config.listen_socket:
                        client_socket, address = read_socket.accept()
                        self.socket_list.append(client_socket)
                        print('connect from:', address)

                    else:
                        data = read_socket.recv(self.buffer_size)
                        if data:
                            self.handle_packet(read_socket, data)
                        else:
                            read_socket.close()
                            self.socket_list.remove(read_socket)

    def handle_packet(self, sock, data):
        packet_type = data[0] >> 4
        protocol_name = data[0:6]
        if packet_type == 1:
            self.handle_connect_packet(sock, data)
        elif check_protocol_name_signature(protocol_name):
            self.handle_signature_packet(sock, data)
        else:
            sock.close()
            raise Exception(f"MQTT control packet type {packet_type} is not yet supported")

    def handle_signature_packet(self, sock, data):
        packet_type = data[6]
        if packet_type == SIGNATURE_CLIENT_HELLO:
            self.handle_signature_client_hello(sock, data)
        elif packet_type == SIGNATURE_CLIENT_KEM_CIPHERTEXT:
            self.handle_signature_client_premaster_secret(data)
        elif packet_type == SIGNATURE_CLIENT_FINISHED:
            self.handle_signature_client_finished(sock, data)
        else:
            raise InvalidParameterError("Packet type did not match any of the expected values")

    def handle_signature_client_hello(self, sock, data):
        self.client_hello = data
        self.r_c = data[39:]
        self.r_s = random.getrandbits(256)
        self.send_signature_server_hello(sock)

    def handle_signature_client_premaster_secret(self, data):
        self.client_kem_ciphtertext = data
        premaster_ciphertext = data[7:]
        self.premaster_secret = decrypt(keys.broker_secret_key, premaster_ciphertext)
        HS = hkdf_extract(self.premaster_secret, self.dES)
        CHTS = hkdf_expand(HS, "c hs traffic", KEY_LEN)
        SHTS = hkdf_expand(HS, "s hs traffic", KEY_LEN)
        self.dHS = hkdf_expand(HS, "derived")
        AHS = hkdf_extract(self.premaster_secret, self.dHS)
        CAHTS = hkdf_expand(AHS, "c ahs traffic", KEY_LEN)
        SAHTS = hkdf_expand(AHS, "s ahs traffic", KEY_LEN)
        dAHS = hkdf_expand(AHS, "derived")
        MS = hkdf_extract(dAHS, None)

        self.fk_c = hkdf_expand(MS, "c finished", KEY_LEN)
        self.fk_s = hkdf_expand(MS, "s finished", KEY_LEN)



    def handle_signature_client_finished(self, sock, data):
        self.client_finished = data
        hmac_msg = self.client_hello + self.server_hello + self.client_kem_ciphtertext
        hmac_obj = hmac.new(self.fk_c, hmac_msg, hashlib.sha3_256)
        client_hmac = data[7:]
        hmacs_equal = hmac.compare_digest(hmac_obj.digest(), client_hmac)
        if not hmacs_equal:
            raise Exception("HMACs not equal, something went wrong")
        self.send_signature_server_finished(sock, data)

    def send_signature_server_hello(self, sock):
        protocol_name = [ord('S'), ord('I'), ord('G'), ord('N'), ord('A'), ord('T')]
        packet_type = [SIGNATURE_SERVER_HELLO]
        self.server_hello = bytearray(protocol_name + packet_type) \
                            + self.r_s.to_bytes(32, 'big') \
                            + keys.broker_public_key \
                            + keys.ca_signature
        sock.sendall(self.server_hello)

    def send_signature_server_finished(self, sock, data):
        protocol_name = [ord('S'), ord('I'), ord('G'), ord('N'), ord('A'), ord('T')]
        packet_type = [SIGNATURE_SERVER_FINISHED]
        hmac_msg = self.client_hello + self.server_hello + self.client_kem_ciphtertext + self.client_finished

        hmac_obj = hmac.new(self.fk_s, hmac_msg, hashlib.sha3_256)
        server_finished = bytearray(protocol_name + packet_type) + bytearray.fromhex(hmac_obj.hexdigest())
        sock.sendall(server_finished)

    def handle_connect_packet(self, sock, data):
        """Validates incoming connect packet and responds as appropriate"""
        flags = data[0] & 0x0F
        if flags != 0:
            raise InvalidParameterError("Flags must be 0 in connect packet")

        data, remaining_length = get_remaining_length_int(data)
        if remaining_length > 268435455:  # max MQTT packet size
            raise InvalidParameterError("remaining length is too large")

        while len(data) < remaining_length:
            data += sock.recv(self.buffer_size)

        # check protocol name
        if data[0] != 0x00 \
                or data[1] != 0x04 \
                or data[2] != ord('M') \
                or data[3] != ord('Q') \
                or data[4] != ord('T') \
                or data[5] != ord('T'):
            raise InvalidParameterError("Protocol name field is not equal to MQTT")

        protocol_level = data[6]
        if protocol_level != 5:
            raise InvalidParameterError(f"Protocol level is {protocol_level}, should be 5")

        connect_flags = data[7]
        if connect_flags != 0x02:
            raise NotImplementedError("Flag configurations other than 0x02 are not implemented")

        keep_alive = (data[8] << 8) | data[9]
        if keep_alive != 0x00:
            raise NotImplementedError("Keep alive has not been implemented. It must be zero")

        properties_len = data[10]
        if properties_len:
            raise NotImplementedError("Handling of optional properties has not yet been implemented")

        payload = data[11 + properties_len:]
        id_length = (payload[0] << 8) | payload[1]
        client_id = ''.join([chr(num) for num in payload[2:2 + id_length]])

        self.connack(sock, 0x00)

    def connack(self, sock, reason_code):
        """Send MQTT CONNACK in response to valid CONNECT packet"""

        # variable header
        session_present = 0
        connack_flags = 0x01 & session_present
        maximum_qos = [0x24, 0]
        retain_available = [0x25, 0]
        wildcard_subscriptions_available = [0x28, 0]
        subscription_identifiers_available = [0x29, 0]
        shared_subscription_available = [0x2A, 0]
        keep_alive = [0x13, 0]
        properties = maximum_qos + retain_available + wildcard_subscriptions_available + \
                     subscription_identifiers_available + shared_subscription_available + keep_alive

        variable_header = [connack_flags, reason_code, len(properties)] + properties

        payload = bytearray()

        # fixed header
        packet_type = MQTT_CONNACK
        variable_header_length = len(variable_header)
        remaining_length = variable_header_length + len(payload)
        fixed_header = [packet_type << 4]
        fixed_header += remaining_length_bytes(remaining_length)

        # send packet
        packet = bytearray(fixed_header + variable_header) + payload
        sock.send(packet)

import hashlib
import random

import select

import kem.client.client_config
import validate
import json
import hmac
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
from hkdf.hkdf import hkdf_expand, hkdf_extract

from kem.packet_types import *
from kem.custom_errors import InvalidParameterError
from kem.util import remaining_length_bytes, get_remaining_length_int, check_protocol_name_kemtls
from kem.client import validate, client_config

KEY_LEN = 256


class MqttClient:

    def __init__(self):
        """Checks that data provided in the config json is valid as according to assignment specifications"""
        with open('config_files/config.json') as json_file:
            data = json.load(json_file)
            client_id = validate.check_client_id(data)
            input_ip = validate.check_valid_ip(data, "input_ip")
            input_port = validate.check_valid_port(data, "input_port")
            broker_ip = validate.check_valid_ip(data, "broker_ip")
            broker_port = validate.check_valid_port(data, "broker_port")
            cert = validate.check_cert_file_name(data, 'cert_file_name')
            post_quantum_cert = validate.check_cert_file_name(data, 'post_quantum_cert_file_name')
            self.config = client_config.Config(client_id, input_ip, input_port, broker_ip, broker_port, cert, post_quantum_cert)
        self.socket_list = []
        self.rand_c = random.getrandbits(256)
        self.pub_key, self.secret_key = generate_keypair()
        ES = hkdf_extract(None, "")
        self.dES = hkdf_extract(ES, "derived")
        # below variables will be set when required info is received from server
        self.rand_s = None
        self.shared_secret = None
        self.dHS = None
        self.fk_s = None
        self.client_hello = None
        self.server_hello = None
        self.client_kem_ciphtertext = None
        self.client_finished = None
        self.server_finished = None

    def kemtls_client_hello(self):
        protocol_name = [ord('K'), ord('E'), ord('M'), ord('T'), ord('L'), ord('S')]
        packet_type = [KEMTLS_CLIENT_HELLO]
        rand_bits = self.rand_c.to_bytes(32, 'big')
        print(self.rand_c)
        print(rand_bits)
        self.client_hello = bytearray(protocol_name + packet_type) + rand_bits + bytes(self.pub_key)
        self.config.sock.sendall(self.client_hello)
        print("Sent KEMTLS Hello")
        self.monitor()

    def handle_server_hello(self):
        protocol_name = self.server_hello[0:6]
        if protocol_name[0] != ord('K') \
                or protocol_name[1] != ord('E') \
                or protocol_name[2] != ord('M') \
                or protocol_name[3] != ord('T') \
                or protocol_name[4] != ord('L') \
                or protocol_name[5] != ord('S'):
            raise InvalidParameterError("Protocol name field is not equal to KEMTLS")

        packet_type = self.server_hello[6]
        if packet_type != KEMTLS_SERVER_HELLO:
            raise InvalidParameterError("Packet type should be SERVER HELLO")

        self.rand_s = int.from_bytes(self.server_hello[7:39], "big")  # read the next 32 bytes (256 bits) into rand_s
        cipher_text_ephemeral = int.from_bytes(self.server_hello[39:], "big")  # read the remaining bits into cte
        self.shared_secret = decrypt(self.secret_key, cipher_text_ephemeral)
        self.client_kem_ciphtertext()
        self.send_client_finished()

    def send_client_kem_ciphertext(self):
        HS = hkdf_extract(self.shared_secret, self.dES)
        # CHTS = hkdf_expand(HS, "c hs traffic", KEY_LEN)
        # SHTS = hkdf_expand(HS, "s hs traffic", KEY_LEN)
        self.dHS = hkdf_expand(HS, "derived")

        public_key_server = "ABC123"  # TODO extract this from certificate
        cipher_text_s, self.shared_secret = encrypt(public_key_server)

        protocol_name = [ord('K'), ord('E'), ord('M'), ord('T'), ord('L'), ord('S')]
        packet_type = [KEMTLS_CLIENT_KEM_CIPHERTEXT]
        self.client_kem_ciphtertext = bytearray(protocol_name + packet_type + [cipher_text_s])
        self.config.sock.sendall(self.client_kem_ciphtertext)
        print("sent KEMTLS client KEM ciphertext")

    def send_client_finished(self):
        AHS = hkdf_extract(self.shared_secret, self.dHS)
        # CAHTS = hkdf_expand("c ahs traffic", AHS, KEY_LEN)
        # SAHTS = hkdf_expand("s ahs traffic", AHS, KEY_LEN)
        dAHS = hkdf_expand("derived", AHS)
        MS = hkdf_extract(None, dAHS)
        fk_c = hkdf_expand("c finished", MS, KEY_LEN)
        self.fk_s = hkdf_expand("s finished", MS, KEY_LEN)

        hmac_msg = self.client_hello + self.server_hello + self.client_kem_ciphtertext
        hmac_obj = hmac.new(fk_c, hmac_msg, hashlib.sha3_256)

        protocol_name = [ord('K'), ord('E'), ord('M'), ord('T'), ord('L'), ord('S')]
        packet_type = [KEMTLS_CLIENT_FINISHED]
        self.client_finished = bytearray(protocol_name + packet_type) + bytearray.fromhex(hmac_obj.hexdigest())
        self.config.sock.sendall(self.client_finished)

        # CATS = hkdf_expand("c ap traffic", MS, KEY_LEN)
        print("sent KEMTLS client finished")

    def handle_server_finished(self):
        server_hmac = self.server_finished
        hmac_msg = self.client_hello + self.server_hello + self.client_kem_ciphtertext + self.client_finished
        own_hmac = hmac.new(self.fk_s, hmac_msg, hashlib.sha3_256)
        hmacs_equal = hmac.compare_digest(own_hmac.digest(), server_hmac)
        if not hmacs_equal:
            raise Exception("HMACs not equal, something went wrong")
        self.connect()

    def connect(self):
        """Sends a connect message. Returns the size of the packet"""

        # variable header
        protocol_name = [0x00, 0x04, ord('M'), ord('Q'), ord('T'), ord('T')]
        protocol_level = [0x05]
        connect_flags = [0x02]
        keep_alive = [0x00, 0x00]
        properties_len = [0, ]
        variable_header = protocol_name + protocol_level + connect_flags + keep_alive + properties_len

        # payload
        id_length = [len(self.config.client_id) >> 8, len(self.config.client_id) & 0xFF]
        client_id = [ord(char) for char in list(self.config.client_id)]
        payload = bytearray(id_length + client_id)

        # fixed header
        packet_type = MQTT_CONNECT
        variable_header_length = len(variable_header)
        remaining_length = variable_header_length + len(payload)
        fixed_header = [packet_type << 4]
        fixed_header += remaining_length_bytes(remaining_length)

        # send packet
        packet = bytearray(fixed_header + variable_header) + payload
        self.config.sock.sendall(packet)

        # receive CONNACK
        connack_packet = self.config.sock.recv(4096)
        self.handle_connack(connack_packet)

        print("sent MQTT connect")
        return len(packet)

    def handle_connack(self, connack_packet):
        """Handle the incoming CONNACK packet"""
        if connack_packet[0] >> 4 != MQTT_CONNACK:
            raise Exception("Control packet type must be 0x02 (CONNACK)")

        data, remaining_length = get_remaining_length_int(connack_packet)

        if remaining_length > 268435455:  # max MQTT packet size
            raise InvalidParameterError("remaining length is too large")

        session_present = data[0]
        if session_present == 1:
            raise NotImplementedError("Sessions are not yet implemented")

        reason_code = data[1]
        if reason_code != 0x00:
            raise NotImplementedError("Handling for unsuccessful error codes not yet implemented")

        properties_length = data[2]

        payload = data[3 + properties_length:]

    def monitor(self):
        """monitor for incoming messages"""
        while True:
            read_sockets, write_sockets, error_sockets = select.select([self.config.sock], [], [])
            if len(read_sockets) > 0:
                for read_socket in read_sockets:
                    data = read_socket.recv(4096)
                    print(data)
                    self.handle_packet(data)

    def handle_packet(self, data):
        packet_type = data[0] >> 4
        protocol_name = self.server_hello[0:6]
        if packet_type == MQTT_CONNACK:
            self.handle_connack(data)
        elif check_protocol_name_kemtls(protocol_name):
            self.handle_kemtls_packet(data)
        else:
            self.config.sock.close()
            raise Exception(f"MQTT control packet type {packet_type} is not yet supported")

    def handle_kemtls_packet(self, data):
        packet_type = data[6]
        if packet_type == KEMTLS_SERVER_HELLO:
            print("Received KEMTLS Server Hello")
            self.server_hello = data
            self.handle_server_hello()
        elif packet_type == KEMTLS_SERVER_FINISHED:
            print("Received KEMTLS Server Finished")
            self.server_finished = data
            self.handle_server_finished()
        else:
            raise InvalidParameterError("KEMTLS Packet type did not match any of the expected values")
import select

import client_config
import x509.security_level as security_level
import x509.client.validate as validate
import json

from x509.custom_errors import InvalidParameterError
from x509.util import remaining_length_bytes, get_remaining_length_int
from environment import home_path


class MqttClient:

    def __init__(self, security):
        """Checks that data provided in the config json is valid as according to assignment specifications"""
        self.security_level = security
        with open(home_path + 'x509/client/config_files/config.json') as json_file:
            data = json.load(json_file)
            client_id = validate.check_client_id(data)
            input_ip = validate.check_valid_ip(data, "input_ip")
            input_port = validate.check_valid_port(data, "input_port")
            broker_ip = validate.check_valid_ip(data, "broker_ip")
            broker_port = validate.check_valid_port(data, "broker_port")
            cert = validate.get_certificate_filename(data, self.security_level)
            # post_quantum_cert = validate.check_cert_file_name(data, 'post_quantum_cert_file_name')
            self.config = client_config.Config(client_id, input_ip, input_port, broker_ip, broker_port, cert)
        self.socket_list = []

    def connect(self):
        """Sends a connect message. Returns the size of the packet"""

        # variable header
        protocol_name = [0x00, 0x04, 0x4D, 0x51, 0x54, 0x54]
        protocol_level = [0x05]
        connect_flags = [0x02]
        keep_alive = [0x00, 0x00]
        properties_len = [0, ]
        variable_header = protocol_name + protocol_level + connect_flags + keep_alive + properties_len

        # payload
        id_length = [len(self.config.client_id) >> 8, len(self.config.client_id) & 0xFF]
        client_id = [ord(char) for char in list(self.config.client_id)]
        payload = bytearray(id_length + client_id)
        if self.security_level == security_level.CONVENTIONAL or self.security_level == security_level.POST_QUANTUM:
            with open(home_path + 'x509/client/config_files/' + self.config.cert_file_name, 'rb') as f:
                x509_certificate = f.read()
                payload += x509_certificate

        # fixed header
        packet_type = 0x01
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

        return len(packet)

    def monitor(self):
        """monitor for incoming messages"""
        while True:
            read_sockets, write_sockets, error_sockets = select.select([self.config.sock], [], [])
            if len(read_sockets) > 0:
                for read_socket in read_sockets:
                    data = read_socket.recv(4096)
                    self.handle_packet(data)

    def handle_connack(self, connack_packet):
        """Handle the incoming CONNACK packet"""
        if connack_packet[0] >> 4 != 0x02:
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

    def handle_packet(self, data):
        pass



    # def subscribe(self):









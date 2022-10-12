import subprocess

import broker_config
import insecure_mqtt.client.validate as validate
import json
import select
import insecure_mqtt.security_level as security_level
from insecure_mqtt.custom_errors import *
from insecure_mqtt.util import remaining_length_bytes, get_remaining_length_int
from environment import home_path


REASON_CODE = {
    "success": 0x00,
    "authFailed": 0x86
}


class MqttBroker:

    def __init__(self, security):
        """Checks that data provided in the config json is valid as according to assignment specifications"""
        self.socket_list = []
        self.client_records = []
        self.buffer_size = 1024
        self.secure = security
        with open(home_path + 'insecure_mqtt/broker/config_files/config.json') as json_file:
            data = json.load(json_file)
            input_ip = validate.check_valid_ip(data, "input_ip")
            input_port = validate.check_valid_port(data, "input_port")
            ca_cert_file_name = validate.get_parameter(data, 'ca_cert_file_name')
            self.config = broker_config.BrokerConfig(input_ip, input_port, [], ca_cert_file_name)

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
        if packet_type == 1:
            self.handle_connect_packet(sock, data)
        else:
            sock.close()
            raise Exception(f"MQTT control packet type {packet_type} is not yet supported")

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
        if self.secure:
            insecure_mqtt_certificate = payload[2 + id_length:]
            print(insecure_mqtt_certificate)
            cert_file_name = 'config_files/certificate-' + client_id + '.pem'
            ca_file_name = 'config_files/' + self.config.ca_cert_file_name
            with open(cert_file_name, 'w') as cert_file:
                cert_file.write(insecure_mqtt_certificate.decode('utf-8'))

            process = subprocess.run(['openssl', 'verify', '-CAfile', ca_file_name, cert_file_name],
                                     stdout=subprocess.PIPE,
                                     universal_newlines=True)
            if process.stdout.strip() != cert_file_name + ": OK":
                print("X.509 authentication failed")
                self.connack(sock, REASON_CODE["authFailed"])
                return
            else:
                print("X.509 authentication succeeded")

        # TODO store client details
        self.connack(sock, REASON_CODE["success"])

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
        if self.secure:
            # TODO add certificate
            pass

        # fixed header
        packet_type = 0x02
        variable_header_length = len(variable_header)
        remaining_length = variable_header_length + len(payload)
        fixed_header = [packet_type << 4]
        fixed_header += remaining_length_bytes(remaining_length)

        # send packet
        packet = bytearray(fixed_header + variable_header) + payload
        sock.send(packet)

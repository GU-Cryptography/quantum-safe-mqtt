import socket


class BrokerConfig:
    """Represents router configuration from config.json file"""

    def __init__(self, input_ip, input_port, clients, ca_cert_file_name):
        self.input_ip = input_ip
        self.input_port = input_port
        self.clients = clients
        self.ca_cert_file_name = ca_cert_file_name
        self.listen_socket = None
        self.add_socket_to_config()

    def add_socket_to_config(self):
        """Creates TCP socket and binds to input_port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.input_ip, self.input_port))
        sock.listen(1)
        self.listen_socket = sock

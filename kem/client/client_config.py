import socket


class Config:
    """Represents router configuration from config.json file"""

    def __init__(self, client_id, input_ip, input_port, broker_ip, broker_port, cert_file_name, post_quantum_cert_file):
        self.client_id = client_id
        self.input_ip = input_ip
        self.input_port = input_port
        self.broker_ip = broker_ip
        self.broker_port = broker_port
        self.cert_file_name = cert_file_name
        self.post_quantum_cert_file = post_quantum_cert_file
        self.sock = None
        self.listen_socket = None
        self.add_socket_to_config()

    def add_socket_to_config(self):
        """Creates TCP socket and binds to input_port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.broker_ip, self.broker_port))
        self.sock = sock

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.bind((self.input_ip, self.input_port))
        listen_sock.listen(1)
        self.listen_socket = listen_sock

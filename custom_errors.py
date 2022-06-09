"""File for custom exception classes"""


class MissingParameterError(Exception):
    """Exception for a missing config parameter"""
    pass


class InvalidParameterError(Exception):
    """Exception for a parameter that exists, but is not valid"""
    pass


class IncorrectPacketLength(Exception):
    """Received a packet with incorrect length. Length should be 4 + 20n where n is an integer"""
    pass

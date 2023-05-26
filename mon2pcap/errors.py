""" Custom exceptions definition
"""

class IgnoredPacket(Exception):
    """ Ignored packets due to parsing errors
    """

class FilteredPacket(Exception):
    """ Filtered packet
    """

class IENotFound(Exception):
    """ Information element not found exception
    """

class HexdumpValidationError(Exception):
    """ Hexdump did not pass sanity check
    """
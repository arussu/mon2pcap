"""
Library to convert StarOS "monitor subscriber" or "monitor protocol" ASCII dump to PCAP
"""

import logging

from .mon2pcap import Mon2Pcap

__all__ = ["Mon2Pcap"]

logging.getLogger(__name__).addHandler(logging.NullHandler())

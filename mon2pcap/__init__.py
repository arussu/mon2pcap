"""
Library to convert StarOS "monitor subscriber" or "monitor protocol" ASCII dump to PCAP
"""

import logging

__all__ = tuple("Mon2Pcap")

logging.getLogger(__name__).addHandler(logging.NullHandler())

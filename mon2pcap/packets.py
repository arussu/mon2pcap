"""packets.py — Packet class hierarchy for mon2pcap.

Each class represents one StarOS monitor-subscriber protocol and is
responsible for:

1. Locating its IP-version indicator in the raw text.
2. Parsing Layer-3 / Layer-4 fields (addresses, ports, payload length).
3. Extracting the hex dump and validating its integrity.
4. Constructing a Scapy packet that PCAP writers can consume.
"""

import datetime
import ipaddress
import logging
import re
import time
from abc import ABC, abstractmethod
from struct import pack
from typing import List, Optional, Tuple

from scapy.all import IP, SCTP, UDP, Ether, IPv6, SCTPChunkData

from .constants import RE_HEXDUMP, RE_HEXDUMP_ASCII
from .errors import HexdumpValidationError, IENotFound, IgnoredPacket

mon2pcap_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Null MAC address used for all generated Ethernet headers
NULL_MAC = "00:00:00:00:00:00"

# Pre-compiled regex for hexdump content validation (only hex chars)
_RE_HEX_CHARS = re.compile(r"^[a-f0-9]+$", re.IGNORECASE)

# Matches the StarOS "L{length}" token in Diameter header lines, e.g. "L612".
# The word-boundary anchors prevent false matches on tokens like "L2TP".
_RE_DIAMETER_LENGTH = re.compile(r"\bL(\d+)\b")


def get_gprs_ns_header(bvci):
    """

    :param bvci:

    """
    pdu_type = 0x0  # 1 byte,  struct 'B'
    ns_control_bits = 0x0  # 1 byte,  struct 'B'
    # bvci                              # 2 bytes, struct 'H'
    data = (pdu_type, ns_control_bits, bvci)
    return pack(">BBH", *data)


def get_m3ua_header(length, src, dst):
    """

    :param length:
    :param src:
    :param dst:

    """
    m3ua_version = 1  # 1 byte,  struct 'B'
    m3ua_reserved = 0  # 1 byte,  struct 'B'
    m3ua_class = 1  # 1 byte,  struct 'B'
    m3ua_msg_type = 1  # 1 byte,  struct 'B'
    m3ua_msg_length = length + 8  # 4 bytes, struct 'I', recalc
    proto_data = 528  # 2 bytes, struct 'H'
    proto_data_len = length  # 2 bytes, struct 'H'
    opc = src  # 4 bytes, struct 'I'
    dpc = dst  # 4 bytes, struct 'I'
    si = 3  # 1 byte,  struct 'B'
    ni = 3  # 1 byte,  structdef  'B'
    mp = 0  # 1 byte,  struct 'B'
    sls = 0  # 1 byte,  struct 'B'
    data = (
        m3ua_version,
        m3ua_reserved,
        m3ua_class,
        m3ua_msg_type,
        m3ua_msg_length,
        proto_data,
        proto_data_len,
        opc,
        dpc,
        si,
        ni,
        mp,
        sls,
    )
    return pack(">BBBBIHHIIBBBB", *data)


def get_sccp_header(length, sccp_called_party_sub, sccp_calling_party_sub):
    """

    :param length:
    :param sccp_called_party_sub:
    :param sccp_calling_party_sub:

    """
    sccp_msg_type = 0x13  # 1 byte,  struct 'B'
    sccp_class_msg_handling = 0  # 1 byte,  struct 'B'
    sccp_hop_counter = 0  # 1 byte,  struct 'B'
    sccp_pointer_one = 0x0700  # 2 bytes, struct 'H'
    sccp_pointer_two = 0x0A00  # 2 bytes, struct 'H'
    sccp_pointer_three = 0x0D00  # 2 bytes, struct 'H'
    sccp_pointer_optional = 0  # 2 bytes, struct 'H'
    sccp_called_party_len = 4  # 1 byte,  struct 'B'
    sccp_called_party_addr_ind = 3  # 1 byte,  struct 'B'
    sccp_called_party_pc = 0x0100  # 2 bytes, struct 'H'
    # sccp_called_party_sub                             # 1 byte,  struct 'B'
    sccp_calling_party_len = 4  # 1 byte,  struct 'B'
    sccp_calling_party_addr_ind = 3  # 1 byte,  struct 'B'
    sccp_calling_party_pc = 0x0100  # 2 bytes, struct 'H'
    # sccp_calling_party_sub                            # 1 byte,  struct 'B'
    payload_length = length  # 2 bytes, struct 'H'
    data = (
        sccp_msg_type,
        sccp_class_msg_handling,
        sccp_hop_counter,
        sccp_pointer_one,
        sccp_pointer_two,
        sccp_pointer_three,
        sccp_pointer_optional,
        sccp_called_party_len,
        sccp_called_party_addr_ind,
        sccp_called_party_pc,
        sccp_called_party_sub,
        sccp_calling_party_len,
        sccp_calling_party_addr_ind,
        sccp_calling_party_pc,
        sccp_calling_party_sub,
        payload_length,
    )

    return pack(">BBBHHHHBBHBBBHBH", *data)


class Packet(ABC):
    """Abstract base class for all monitor-subscriber packet types.

    Subclasses implement three abstract methods:

    * ``_detect_ip_version()`` — return 4 or 6 (override class attributes
      ``_IP_VER_LINE`` / ``_IP_VER_WORD`` to change the probe location, or
      override the method entirely for fixed-version protocols).
    * ``_get_l3_l4_data()`` — parse and return
      ``(ip_src, ip_dst, sport, dport, length)``.
    * ``_get_scapy_packet()`` — build and return the Scapy packet object.

    The base ``__init__`` acts as a **template method**: it initialises all
    shared attributes, validates the raw text, then calls ``_build()`` which
    runs the parsing pipeline in a fixed order.  Subclasses with non-standard
    field layout (e.g. ``Bssgp``, ``Ppp``) override ``_build()`` instead.
    """

    # ---------------------------------------------------------------------------
    # Class-level defaults for IP-version probing.
    # Most protocols keep the IP address at raw_text[2], word index 4.
    # Subclasses override these to point to the right location.
    # ---------------------------------------------------------------------------
    _IP_VER_LINE: int = 2
    _IP_VER_WORD: int = 4

    def __init__(self, raw_text: List[str]) -> None:
        self.raw_text: List[str] = self._clean_packet_trail(raw_text)

        # Shared packet attributes — all initialised to None/False so that
        # callers always see a well-defined object even on parse failure.
        self.eventid: Optional[str] = None
        self.protocol: Optional[str] = None
        self.ip_version: Optional[int] = None
        self.ip_src: Optional[str] = None
        self.ip_dst: Optional[str] = None
        self.sport: Optional[int] = None
        self.dport: Optional[int] = None
        # length and hexdump are set by _build(); initialised to sentinel values
        # so their types are int and str (not Optional) and callers can use them
        # in arithmetic / string operations without type-checker complaints.
        self.length: int = 0
        self.arrive_time: Optional[float] = None
        self.direction: Optional[str] = None
        self.hexdump: str = ""
        self.ignore: bool = False
        self.scapy_packet = None

        self._validate_content()
        self._build()

    # ------------------------------------------------------------------
    # Template method
    # ------------------------------------------------------------------

    def _build(self) -> None:
        """Parse all packet fields in the correct dependency order.

        Override in subclasses that have a non-standard field layout.
        """
        self.ip_version = self._detect_ip_version()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = (
            self._get_l3_l4_data()
        )
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    # ------------------------------------------------------------------
    # Abstract methods — must be implemented by every subclass
    # ------------------------------------------------------------------

    @abstractmethod
    def _get_l3_l4_data(self) -> Tuple:
        """Parse and return ``(ip_src, ip_dst, sport, dport, length)``."""

    @abstractmethod
    def _get_scapy_packet(self):
        """Build and return the Scapy packet for this protocol."""

    # ------------------------------------------------------------------
    # IP-version detection — concrete default, override as needed
    # ------------------------------------------------------------------

    def _detect_ip_version(self) -> int:
        """Probe the IP version from the raw text using class-level indices.

        Override ``_IP_VER_LINE`` and ``_IP_VER_WORD`` on the subclass to
        point to the correct token, or override this method entirely for
        protocols that always use a fixed IP version.
        """
        addr = self.raw_text[self._IP_VER_LINE].split()[self._IP_VER_WORD]
        return self._probe_ip_ver(addr)

    # ------------------------------------------------------------------
    # Shared parsing helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"{self.arrive_time!s}, {self.direction!s}, "
            f"{self.ip_src}:{self.sport} > {self.ip_dst}:{self.dport} "
            f"len: {self.length})"
        )

    def details(self) -> str:
        """Return a human-readable multi-line summary of the packet."""
        hexdump = self.hexdump or ""
        return (
            f"{self.__class__.__name__}("
            f"Ignore: {self.ignore}  Eventid: {self.eventid!s:>6}  Protocol: {self.protocol!s}\n"
            f" ---------------------------------\n"
            f"Arrive Time: {self.arrive_time}  Direction: {self.direction}\n"
            f" ---------------------------------\n"
            f"IPv{self.ip_version} {self.ip_src}:{self.sport} > {self.ip_dst}:{self.dport} "
            f"len: {self.length}\n"
            f" ---------------------------------\n"
            f"Hexdump len = {len(hexdump)}  {hexdump[:30]}...)"
        )

    def _get_arrive_time(self) -> float:
        """Parse the packet arrival timestamp and return it as a UNIX float."""
        date_str = " ".join(self.raw_text[0].strip().split()[1:])
        time_str = self.raw_text[1].split("Eventid")[0].split()[-1]
        parsed = datetime.datetime.strptime(
            f"{date_str} {time_str}", "%B %d %Y %H:%M:%S:%f"
        )
        return time.mktime(parsed.timetuple()) + (parsed.microsecond / 1_000_000.0)

    def _get_direction(self) -> str:
        """Extract the traffic direction (INBOUND / OUTBOUND) from the header."""
        direction = self.raw_text[1].split(" ")[0]
        if ">" in direction:
            return direction[:7]
        return direction[4:]

    def _probe_ip_ver(self, token: str) -> int:
        """Infer the IP version (4 or 6) from an address/port token.

        Handles the various StarOS address formats::

            240b:c0e0:201:2003:301:1:0:f01.34271  # IPv6 with dot-delimited port
            240b:c0e0:201:2004:601:1:0:d01:8805   # IPv6 with colon-delimited port
            2a00:1fa0:145b:69b2:0:66:cd75:b101    # bare IPv6
            ::                                     # unspecified IPv6
            172.19.204.11:2123                     # IPv4 with colon-delimited port
            8.8.8.8.53                             # IPv4 with dot-delimited port

        :param token: The raw address (possibly including port suffix).
        :returns: 4 or 6.
        :raises ValueError: If the address cannot be parsed.
        """
        # Try the token as-is first
        try:
            return ipaddress.ip_address(token).version
        except ValueError:
            pass

        ip_candidate = token

        # IPv4 with dot-delimited port: "a.b.c.d.port"
        if len(token.split(".")) == 5:
            ip_candidate = ".".join(token.split(".")[:-1])

        # IPv6 with any port suffix: strip the last colon-segment
        elif ":" in token and token != "::":
            ip_candidate = token.split(":")[0]

        try:
            return ipaddress.ip_address(ip_candidate).version
        except ValueError:
            pass

        # Last resort: strip the final segment
        if len(token.split(".")) == 2:
            ip_candidate = token.split(".")[0]
        else:
            ip_candidate = ":".join(token.split(":")[:-1])

        return ipaddress.ip_address(ip_candidate).version

    def _clean_packet_trail(self, text: List[str]) -> List[str]:
        """Strip trailing non-hexdump lines from the raw packet text.

        Iterates from the end; as soon as a hexdump line is found, stops.
        Lines after the last hexdump line are discarded.
        """
        trailing = 0
        for line in reversed(text):
            stripped = line.strip()
            if RE_HEXDUMP.match(stripped) or RE_HEXDUMP_ASCII.match(stripped):
                break
            trailing += 1

        return text[:-trailing] if trailing else text

    def _validate_content(self) -> None:
        """Raise ``IgnoredPacket`` if the raw text is empty after cleaning."""
        if not self.raw_text:
            raise IgnoredPacket("No hexdump found in packet")

    def _get_hexdump(self, pkt_len: int) -> str:  # type: ignore[return]  # always returns str at runtime
        """Extract and concatenate hex bytes from the tail of the raw text.

        Handles both plain hexdump and ``0x``-prefixed formats.

        :param pkt_len: Expected payload length in bytes.
        :returns: Continuous lowercase hex string.
        """
        lines_needed = pkt_len // 16 + (1 if pkt_len % 16 else 0)
        lines = self.raw_text[-lines_needed:]

        if "0x" in lines[0]:
            # Strip the "0xNNNN" offset prefix (always 6 chars: "0x" + 4 hex digits)
            # plus any following whitespace (StarOS uses 3 spaces, i.e. 9 chars total,
            # but we lstrip to be robust), then take at most 39 chars which covers
            # 8 hex groups × 4 chars + 7 separating spaces — never reaching the
            # ASCII annotation column that starts at position ~56.
            dump = "".join("".join(line[6:].lstrip()[:39].split()) for line in lines)
        else:
            dump = "".join("".join(line.split()) for line in lines)

        return dump

    def _hexdump_sanity_check(self, hexdump: str, pkt_len: int) -> None:
        """Validate hex-dump content and length.

        :param hexdump: The extracted hex string.
        :param pkt_len: Expected packet length in bytes.
        :raises HexdumpValidationError: If the dump is malformed or the wrong size.
        """
        if len(hexdump) != pkt_len * 2 or not _RE_HEX_CHARS.match(hexdump):
            raise HexdumpValidationError("Packet did not pass hexdump sanity check")


class Gtpc(Packet):
    """GTPCv1 (GPRS Tunnelling Protocol Control) packet.  IPv4 only."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[4].split(":")[0]
        ip_dst = line[6].split(":")[0]
        sport = int(line[4].split(":")[1])
        dport = int(line[6].split(":")[1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


class GtpcV2(Packet):
    """GTPCv2 (GTP Control Plane version 2) packet.  IPv4 and IPv6."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(":")[0]
            ip_dst = line[6].split(":")[0]
            sport = int(line[4].split(":")[1])
            dport = int(line[6].split(":")[1])
        else:
            ip_src = ":".join(line[4].split(":")[:-1])
            ip_dst = ":".join(line[6].split(":")[:-1])
            sport = int(line[4].split(":")[-1])
            dport = int(line[6].split(":")[-1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        if self.ip_version == 4:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
                / IP(src=self.ip_src, dst=self.ip_dst)
                / UDP(sport=self.sport, dport=self.dport)
                / bytes.fromhex(self.hexdump)
            )
        else:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x86DD)
                / IPv6(src=self.ip_src, dst=self.ip_dst)
                / UDP(sport=self.sport, dport=self.dport)
                / bytes.fromhex(self.hexdump)
            )
        pkt.time = self.arrive_time
        return pkt


class Gtpu(Packet):
    """GTP-U (GPRS Tunnelling Protocol User plane) packet.  IPv4 and IPv6."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(":")[0]
            ip_dst = line[6].split(":")[0]
            sport = int(line[4].split(":")[1])
            dport = int(line[6].split(":")[1])
        else:
            ip_src = ":".join(line[4].split(":")[:-1])
            ip_dst = ":".join(line[6].split(":")[:-1])
            sport = int(line[4].split(":")[-1])
            dport = int(line[6].split(":")[-1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        if self.ip_version == 4:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
                / IP(src=self.ip_src, dst=self.ip_dst)
                / UDP(sport=self.sport, dport=self.dport)
                / bytes.fromhex(self.hexdump)
            )
        else:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x86DD)
                / IPv6(src=self.ip_src, dst=self.ip_dst)
                / UDP(sport=self.sport, dport=self.dport)
                / bytes.fromhex(self.hexdump)
            )
        pkt.time = self.arrive_time
        return pkt


class Radius(Packet):
    """RADIUS Authentication / Accounting packet.  IPv4 only."""

    # IP address is at word index 5 on line 2 (not the default 4)
    _IP_VER_WORD = 5

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[5].split(":")[0]
        ip_dst = line[7].split(":")[0]
        sport = int(line[5].split(":")[1])
        dport = int(line[7].split(":")[1])
        length = int(line[8].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


class UserL3(Packet):
    """User Layer-3 packet (encapsulated subscriber data).  IPv4 and IPv6."""

    # IP probe is on line 3, word 0
    _IP_VER_LINE = 3
    _IP_VER_WORD = 0

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[3].split()
        length: Optional[int] = None
        if self.ip_version == 4:
            if "icmp" not in line:
                ip_src = ".".join(line[0].split(".")[:-1])
                ip_dst = ".".join(line[2].split(".")[:-1])
                sport = int(line[0].split(".")[-1])
                dport = int(line[2].split(".")[-1][:-1])
            else:
                ip_src = line[0]
                ip_dst = line[2][:-1]
                sport = 0
                dport = 0
            for text_line in self.raw_text:
                if ", len" in text_line:
                    length = int(
                        text_line.split(", len")[-1].split(")")[0].split(",")[0]
                    )
                    break
        else:  # IPv6
            if "icmp6" not in line:
                ip_src = line[0].split(".")[0]
                ip_dst = line[2].split(".")[0]
                try:
                    sport = int(line[0].split(".")[1])
                    dport = int(line[2].split(".")[1][:-1])
                except IndexError:
                    sport = 0
                    dport = 0
            else:
                ip_src = line[0]
                ip_dst = line[2]
                sport = 0
                dport = 0
            for text_line in self.raw_text:
                if "(len " in text_line:
                    try:
                        length = int(text_line.split("len ")[1].split(",")[0])
                    except ValueError:
                        length = int(text_line.split("len ")[1][:-2])
                    length += 40  # IPv6 fixed header
                    break
        if length is None:
            raise IENotFound("Could not determine packet length from UserL3 text")
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        ether_type = 0x0800 if self.ip_version == 4 else 0x86DD
        pkt = Ether(src=NULL_MAC, dst=NULL_MAC, type=ether_type) / bytes.fromhex(
            self.hexdump
        )
        pkt.time = self.arrive_time
        return pkt


class Css(Packet):
    """CSS (Content Service Switch) data packet.  IPv4 and IPv6."""

    # IP probe is on line 3, word 0
    _IP_VER_LINE = 3
    _IP_VER_WORD = 0

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[3].split()
        length: Optional[int] = None
        if all(t not in line for t in {"icmp", "icmp6:"}):
            if self.ip_version == 4:
                ip_src = ".".join(line[0].split(".")[:-1])
                ip_dst = ".".join(line[2].split(".")[:-1])
                sport = int(line[0].split(".")[-1])
                dport = int(line[2].split(".")[-1][:-1])
            else:
                ip_src = line[0].split(".")[0]
                ip_dst = line[2].split(".")[0]
                sport = None
                dport = None
        elif "icmp6:" in line:
            ip_src = line[0]
            ip_dst = line[2]
            sport = 0
            dport = 0
        else:  # "icmp" in line
            ip_src = line[0]
            ip_dst = line[2][:-1]
            sport = 0
            dport = 0

        if self.ip_version == 4:
            for l_val in self.raw_text[3:]:
                if ", len" in l_val:
                    length = int(l_val.split(", len")[-1].split(")")[0].split(",")[0])
                    break
        else:  # IPv6
            for l_val in self.raw_text[3:]:
                if "(len " in l_val:
                    length = (
                        int(l_val.split("len ")[1].split(",")[0].split(")")[0]) + 40
                    )
                    break

        if length is None:
            raise IENotFound("Could not determine packet length from CSS text")
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        ether_type = 0x0800 if self.ip_version == 4 else 0x86DD
        pkt = Ether(src=NULL_MAC, dst=NULL_MAC, type=ether_type) / bytes.fromhex(
            self.hexdump
        )
        pkt.time = self.arrive_time
        return pkt


class Diameter(Packet):
    """Diameter (RFC 6733) packet over SCTP.  IPv4 and IPv6."""

    # IP address is at word index 3 on line 2
    _IP_VER_WORD = 3

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[3].split(":")[0]
            ip_dst = line[5].split(":")[0]
            sport = int(line[3].split(":")[1])
            dport = int(line[5].split(":")[1])
        else:
            ip_src = line[3].split(".")[0]
            ip_dst = line[5].split(".")[0]
            sport = int(line[3].split(".")[1])
            dport = int(line[5].split(".")[1])

        length = self._extract_diameter_length()
        if length is None:
            raise IENotFound("Could not determine Diameter message length")
        return ip_src, ip_dst, sport, dport, length

    def _extract_diameter_length(self) -> Optional[int]:
        """Locate the Diameter message length from the raw packet text.

        StarOS log lines carry the length as an ``L{n}`` token, e.g.::

            Diameter-EAP-Request Diameter STa v1 L612 REQ PXY

        Some verbose/decoded formats instead write ``Message Length: 612``.

        Returns ``None`` when no length can be found so the caller can decide
        how to handle it (``_get_l3_l4_data`` raises ``IENotFound``).

        .. note::
            The previous approach of calling ``split("REQ")`` on the header
            line broke for messages whose *type name* contains "REQ" (e.g.
            ``Diameter-EAP-Request``).  The regex ``\\bL(\\d+)\\b`` correctly
            identifies the standalone length token without splitting on "REQ".
        """
        # Primary: StarOS compact format — find the standalone L{n} token.
        # Search header lines only (skip day/eventid/address lines at [0..2]).
        for text_line in self.raw_text[3:]:
            m = _RE_DIAMETER_LENGTH.search(text_line)
            if m:
                return int(m.group(1))

        # Fallback: verbose decoded format — "Message Length: 612" or
        # "Message Length: 612(0x264)".
        for text_line in self.raw_text:
            if "Message Length" not in text_line:
                continue
            parts = text_line.strip().split(": ", 1)
            if len(parts) < 2:
                continue
            value = parts[1]
            try:
                return int(value)
            except ValueError:
                pass
            try:
                return int(value.split("(")[0].strip())
            except (IndexError, ValueError):
                pass

        return None

    def _get_scapy_packet(self):
        if self.ip_version == 4:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
                / IP(src=self.ip_src, dst=self.ip_dst)
                / SCTP(sport=self.sport, dport=self.dport)
                / SCTPChunkData(
                    ending=True,
                    beginning=True,
                    proto_id=46,
                    data=bytes.fromhex(self.hexdump),
                )
            )
        else:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x86DD)
                / IPv6(src=self.ip_src, dst=self.ip_dst, nh=132)
                / SCTP(sport=self.sport, dport=self.dport)
                / SCTPChunkData(
                    ending=True,
                    beginning=True,
                    proto_id=46,
                    data=bytes.fromhex(self.hexdump),
                )
            )
        pkt.time = self.arrive_time
        return pkt


class Ranap(Packet):
    """RANAP (Radio Access Network Application Part) packet.  IPv4 only."""

    def _detect_ip_version(self) -> int:
        return 4

    def _get_l3_l4_data(self) -> Tuple:
        ip_src = "0.0.0.0"
        ip_dst = "0.0.0.0"
        sport, dport = (3006, 2905) if self.direction == "INBOUND" else (2905, 3006)
        length = int(self.raw_text[2][0].split(" ")[7].split("(")[1].split()[0])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        # 23 bytes SCCP header + 16 bytes M3UA header wrap the RANAP payload
        sccp_header = get_sccp_header(self.length, 142, 142)
        m3ua_header = get_m3ua_header(self.length + 23 + 16, 0, 0)
        data = m3ua_header + sccp_header + bytes.fromhex(self.hexdump)
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / SCTP(sport=self.sport, dport=self.dport)
            / SCTPChunkData(ending=True, beginning=True, proto_id=3, data=data)
        )
        pkt.time = self.arrive_time
        return pkt


class Rua(Packet):
    """RUA (HNBAP RUA) packet.  IPv4 only."""

    def _detect_ip_version(self) -> int:
        return 4

    def _get_l3_l4_data(self) -> Tuple:
        ip_src = "0.0.0.0"
        ip_dst = "0.0.0.0"
        sport, dport = (3005, 2905) if self.direction == "INBOUND" else (2905, 3005)
        length = int(self.raw_text[2].split(" ")[5].split("(")[1].split()[0])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / SCTP(sport=self.sport, dport=self.dport)
            / SCTPChunkData(
                ending=True,
                beginning=True,
                proto_id=19,
                data=bytes.fromhex(self.hexdump),
            )
        )
        pkt.time = self.arrive_time
        return pkt


class S1Ap(Packet):
    """S1AP (S1 Application Protocol) packet over SCTP.  IPv4 and IPv6."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(":")[0]
            ip_dst = line[6].split(":")[0]
            sport = int(line[4].split(":")[1])
            dport = int(line[6].split(":")[1])
        else:
            ip_src = ":".join(line[4].split(":")[:-1])
            ip_dst = ":".join(line[6].split(":")[:-1])
            sport = int(line[4].split(":")[-1])
            dport = int(line[6].split(":")[-1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        if self.ip_version == 4:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
                / IP(src=self.ip_src, dst=self.ip_dst)
                / SCTP(sport=self.sport, dport=self.dport)
                / SCTPChunkData(
                    ending=True,
                    beginning=True,
                    proto_id=18,
                    data=bytes.fromhex(self.hexdump),
                )
            )
        else:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x86DD)
                / IPv6(src=self.ip_src, dst=self.ip_dst)
                / SCTP(sport=self.sport, dport=self.dport)
                / SCTPChunkData(
                    ending=True,
                    beginning=True,
                    proto_id=18,
                    data=bytes.fromhex(self.hexdump),
                )
            )
        pkt.time = self.arrive_time
        return pkt


class SGs(Packet):
    """SGs (MME–MSC) interface packet over SCTP.  IPv4 only."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[4].split(":")[0]
        ip_dst = line[6].split(":")[0]
        sport = int(line[4].split(":")[1])
        dport = int(line[6].split(":")[1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / SCTP(sport=self.sport, dport=self.dport)
            / SCTPChunkData(
                ending=True,
                beginning=True,
                proto_id=0,
                data=bytes.fromhex(self.hexdump),
            )
        )
        pkt.time = self.arrive_time
        return pkt


class Bssgp(Packet):
    """BSSGP (Base Station Subsystem GPRS Protocol) packet.  IPv4 only.

    Carries an extra ``bvci`` attribute (BVCI identifier) extracted alongside
    the standard L3/L4 fields.  Overrides ``_build()`` to capture it.
    """

    def _detect_ip_version(self) -> int:
        return 4

    def _build(self) -> None:
        """Extended build: captures ``bvci`` from ``_get_l3_l4_data()``."""
        self.bvci: int = 0
        self.ip_version = self._detect_ip_version()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        ip_src, ip_dst, sport, dport, length, self.bvci = self._get_l3_l4_data()
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.sport = sport
        self.dport = dport
        self.length = length
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self) -> Tuple:
        ip_src = "0.0.0.0"
        ip_dst = "0.0.0.0"
        sport, dport = (3005, 2157) if self.direction == "INBOUND" else (2157, 3005)
        bvci = int(self.raw_text[3].split("-")[2])
        length = int(self.raw_text[2].split()[2].split("(")[1].split()[0])
        return ip_src, ip_dst, sport, dport, length, bvci

    def _get_scapy_packet(self):
        ns_header = get_gprs_ns_header(self.bvci)
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / ns_header
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


class Tcap(Packet):
    """TCAP (Transaction Capabilities Application Part) packet.  IPv4 only."""

    def _detect_ip_version(self) -> int:
        return 4

    def _get_l3_l4_data(self) -> Tuple:
        ip_src = "0.0.0.0"
        ip_dst = "0.0.0.0"
        sport, dport = (3005, 2905) if self.direction == "INBOUND" else (2905, 3005)
        length = int(self.raw_text[2].split(" ")[7].split("(")[1].split()[0])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        # 23 bytes SCCP header + 16 bytes M3UA header wrap the TCAP payload
        sccp_header = get_sccp_header(self.length, 6, 149)
        m3ua_header = get_m3ua_header(self.length + 23 + 16, 0, 0)
        data = m3ua_header + sccp_header + bytes.fromhex(self.hexdump)
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / SCTP(sport=self.sport, dport=self.dport)
            / SCTPChunkData(ending=True, beginning=True, proto_id=3, data=data)
        )
        pkt.time = self.arrive_time
        return pkt


class Sccp(Packet):
    """SCCP (Signalling Connection Control Part) packet.  IPv4 only."""

    def _detect_ip_version(self) -> int:
        return 4

    def _get_l3_l4_data(self) -> Tuple:
        ip_src = "0.0.0.0"
        ip_dst = "0.0.0.0"
        sport, dport = (3005, 2905) if self.direction == "INBOUND" else (2905, 3005)
        length = int(self.raw_text[2].split()[6].split("(")[1].split()[0])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        m3ua_header = get_m3ua_header(self.length + 16, 0, 0)
        data = m3ua_header + bytes.fromhex(self.hexdump)
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / SCTP(sport=self.sport, dport=self.dport)
            / SCTPChunkData(ending=True, beginning=True, proto_id=3, data=data)
        )
        pkt.time = self.arrive_time
        return pkt


class IkeV2(Packet):
    """IKEv2 (Internet Key Exchange version 2) packet over UDP.  IPv4 only."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[4].split(":")[0]
        ip_dst = line[6].split(":")[0]
        sport = int(line[4].split(":")[1])
        dport = int(line[6].split(":")[1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


class L2tp(Packet):
    """L2TP (Layer 2 Tunnelling Protocol) packet over UDP.  IPv4 only."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[4].split(":")[0]
        ip_dst = line[6].split(":")[0]
        sport = int(line[4].split(":")[1])
        dport = int(line[6].split(":")[1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


class Ppp(Packet):
    """PPP (Point-to-Point Protocol) packet.

    PPP has no IP header so ``ip_version``, ``ip_src``, ``ip_dst``,
    ``sport`` and ``dport`` remain ``None``.  Overrides ``_build()``
    because the field layout is fundamentally different from all other
    protocol classes.
    """

    def _detect_ip_version(self) -> int:
        return 4  # placeholder — not meaningful for PPP

    def _build(self) -> None:
        """PPP-specific build: no IP-version probe, no L3/L4 tuple."""
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self) -> int:  # type: ignore[override]
        """Return the payload length only (PPP has no IP L3/L4 fields)."""
        return int(self.raw_text[2].split()[3].split("(")[1][:-1])

    def _get_scapy_packet(self):
        # Skip the first 4 bytes (PPP framing) from the hexdump
        pkt = Ether(src=NULL_MAC, dst=NULL_MAC, type=0xC021) / bytes.fromhex(
            self.hexdump[8:]
        )
        pkt.time = self.arrive_time
        return pkt


class Dns(Packet):
    """DNS (Domain Name System) packet over UDP.  IPv4 only."""

    # IP probe is on line 3, word 2
    _IP_VER_LINE = 3
    _IP_VER_WORD = 2

    def _get_l3_l4_data(self) -> Tuple:
        ip_src = self.raw_text[3].split()[2]
        ip_dst = self.raw_text[4].split()[2]
        sport = int(self.raw_text[3].split()[4])
        dport = int(self.raw_text[4].split()[4])
        length = int(self.raw_text[5].split()[2])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


class Dhcp(Packet):
    """DHCP (Dynamic Host Configuration Protocol) packet over UDP.  IPv4 only."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[4].split(":")[0]
        ip_dst = line[6].split(":")[0]
        sport = int(line[4].split(":")[1])
        dport = int(line[6].split(":")[1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


class L3Tunnel(Packet):
    """L3 Tunnel (GRE encapsulated) packet.  IPv4 only.

    The IP probe is at word 0 of line 2 (not the default word 4).
    """

    # IP address is the first token on line 2
    _IP_VER_WORD = 0

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[0]
        ip_dst = line[2]
        sport = 0
        dport = 0
        length = None

        for text_line in self.raw_text:
            if ", len " in text_line:
                # Add 38 bytes for GRE + IP + Ethernet headers
                length = int(text_line.split()[-1][:-1]) + 38
                break

        if length is None:
            raise IENotFound("Could not determine the length of packet")

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800) / bytes.fromhex(
            self.hexdump
        )
        pkt.time = self.arrive_time
        return pkt


class Pfcp(Packet):
    """PFCP (Packet Forwarding Control Protocol) packet over UDP.  IPv4 and IPv6."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(":")[0]
            ip_dst = line[6].split(":")[0]
            sport = int(line[4].split(":")[1])
            dport = int(line[6].split(":")[1])
        else:
            ip_src = ":".join(line[4].split(":")[:-1])
            ip_dst = ":".join(line[6].split(":")[:-1])
            sport = int(line[4].split(":")[-1])
            dport = int(line[6].split(":")[-1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        if self.ip_version == 4:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
                / IP(src=self.ip_src, dst=self.ip_dst)
                / UDP(sport=self.sport, dport=self.dport)
                / bytes.fromhex(self.hexdump)
            )
        else:
            pkt = (
                Ether(src=NULL_MAC, dst=NULL_MAC, type=0x86DD)
                / IPv6(src=self.ip_src, dst=self.ip_dst)
                / UDP(sport=self.sport, dport=self.dport)
                / bytes.fromhex(self.hexdump)
            )
        pkt.time = self.arrive_time
        return pkt


class Gtpp(Packet):
    """GTP' (GTP Prime / CDR) charging packet over UDP.  IPv4 only."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[4].split(":")[0]
        ip_dst = line[6].split(":")[0]
        sport = int(line[4].split(":")[1])
        dport = int(line[6].split(":")[1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


class Sls(Packet):
    """SLS (Sls interface) packet over SCTP.  IPv4 only."""

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = line[4].split(":")[0]
        ip_dst = line[6].split(":")[0]
        sport = int(line[4].split(":")[1])
        dport = int(line[6].split(":")[1])
        length = int(line[7].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / SCTP(sport=self.sport, dport=self.dport)
            / SCTPChunkData(
                ending=True,
                beginning=True,
                proto_id=0,
                data=bytes.fromhex(self.hexdump),
            )
        )
        pkt.time = self.arrive_time
        return pkt


class Sctp(Packet):
    """Raw SCTP packet (no application-layer framing).  IPv4 only.

    Sample header::

        <<<<OUTBOUND  From mmemgr:1 mmemgr_sctp.c:3472 12:08:29:896 Eventid:87302(12)
        ===> Stream Control Transmission Protocol (SCTP) (32 bytes)
          src IP: 10.1.33.1 : 29118 > dst IP: 10.2.34.1 : 29118
    """

    # IP probe is on line 3, word 2
    _IP_VER_LINE = 3
    _IP_VER_WORD = 2

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[3].split()
        ip_src = line[2]
        ip_dst = line[8]
        sport = int(line[4])
        dport = int(line[10])
        # Raw SCTP length + 20 bytes for the IP header
        length = int(self.raw_text[2].split()[-2][1:]) + 20
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800) / bytes.fromhex(
            self.hexdump
        )
        pkt.time = self.arrive_time
        return pkt


class Lmisf(Packet):
    """LMISF packet (StarOS cannot fully decode this protocol).

    StarOS emits no IP/transport header for LMISF so placeholder addresses
    and well-known ports (UDP 9201 → 9200) are inserted.

    TODO: parse real IP/transport fields once a decoder is available.
    """

    def _detect_ip_version(self) -> int:
        return 4

    def _get_l3_l4_data(self) -> Tuple:
        line = self.raw_text[2].split()
        ip_src = "0.0.0.0"
        ip_dst = "0.0.0.0"
        sport = 9201
        dport = 9200
        length = int(line[-1].split("(")[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        pkt = (
            Ether(src=NULL_MAC, dst=NULL_MAC, type=0x0800)
            / IP(src=self.ip_src, dst=self.ip_dst)
            / UDP(sport=self.sport, dport=self.dport)
            / bytes.fromhex(self.hexdump)
        )
        pkt.time = self.arrive_time
        return pkt


PARSERS = {
    "GTPC": Gtpc,
    "GTPCv2": GtpcV2,
    "GTPU": Gtpu,
    "RADIUS": Radius,
    "USERL3": UserL3,
    "USERL3_IPV6": UserL3,
    "CSS": Css,
    "DIAMETER": Diameter,
    "RANAP": Ranap,
    "RUA": Rua,
    "S1AP": S1Ap,
    "SGS": SGs,
    "BSSGP": Bssgp,
    "TCAP": Tcap,
    "SCCP": Sccp,
    "IKEv2": IkeV2,
    "L2TP": L2tp,
    "PPP": Ppp,
    "DNS": Dns,
    "PFCP": Pfcp,
    "DHCP": Dhcp,
    "L3_TUNNEL": L3Tunnel,
    "GTPP": Gtpp,
    "SLS": Sls,
    "SCTP": Sctp,
    "LMISF": Lmisf,
}

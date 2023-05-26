""" packets.py 
Packets definition file
"""
import re
import time
import datetime
import ipaddress
import logging

from struct import pack
from scapy.all import Ether,IP,IPv6,UDP,SCTP,SCTPChunkData

from .constants import RE_HEXDUMP, RE_HEXDUMP_ASCII
from .errors import IENotFound, HexdumpValidationError

mon2pcap_log = logging.getLogger(__name__)

def get_gprs_ns_header(bvci):
    """

    :param bvci: 

    """
    pdu_type = 0x0                      # 1 byte,  struct 'B'
    ns_control_bits = 0x0               # 1 byte,  struct 'B'
    # bvci                              # 2 bytes, struct 'H'
    data = (pdu_type, ns_control_bits, bvci)
    return pack('>BBH', *data)


def get_m3ua_header(length, src, dst):
    """

    :param length: 
    :param src: 
    :param dst: 

    """
    m3ua_version = 1                    # 1 byte,  struct 'B'
    m3ua_reserved = 0                   # 1 byte,  struct 'B'
    m3ua_class = 1                      # 1 byte,  struct 'B'
    m3ua_msg_type = 1                   # 1 byte,  struct 'B'
    m3ua_msg_length = length+8          # 4 bytes, struct 'I', recalc
    proto_data = 528                    # 2 bytes, struct 'H'
    proto_data_len = length             # 2 bytes, struct 'H'
    opc = src                           # 4 bytes, struct 'I'
    dpc = dst                           # 4 bytes, struct 'I'
    si = 3                              # 1 byte,  struct 'B'
    ni = 3                              # 1 byte,  structdef  'B'
    mp = 0                              # 1 byte,  struct 'B'
    sls = 0                             # 1 byte,  struct 'B'
    data = (m3ua_version, m3ua_reserved, m3ua_class, m3ua_msg_type, m3ua_msg_length,
        proto_data, proto_data_len, opc, dpc, si, ni, mp, sls)
    return pack('>BBBBIHHIIBBBB', *data)


def get_sccp_header(length, sccp_called_party_sub, sccp_calling_party_sub):
    """

    :param length: 
    :param sccp_called_party_sub: 
    :param sccp_calling_party_sub: 

    """
    sccp_msg_type = 0x13                                # 1 byte,  struct 'B'
    sccp_class_msg_handling = 0                         # 1 byte,  struct 'B'
    sccp_hop_counter = 0                                # 1 byte,  struct 'B'
    sccp_pointer_one = 0x0700                           # 2 bytes, struct 'H'
    sccp_pointer_two = 0x0a00                           # 2 bytes, struct 'H'
    sccp_pointer_three = 0x0d00                         # 2 bytes, struct 'H'
    sccp_pointer_optional = 0                           # 2 bytes, struct 'H'
    sccp_called_party_len = 4                           # 1 byte,  struct 'B'
    sccp_called_party_addr_ind = 3                      # 1 byte,  struct 'B'
    sccp_called_party_pc = 0x0100                       # 2 bytes, struct 'H'
    # sccp_called_party_sub                             # 1 byte,  struct 'B'
    sccp_calling_party_len = 4                          # 1 byte,  struct 'B'
    sccp_calling_party_addr_ind = 3                     # 1 byte,  struct 'B'
    sccp_calling_party_pc =0x0100                       # 2 bytes, struct 'H'
    # sccp_calling_party_sub                            # 1 byte,  struct 'B'
    payload_length = length                             # 2 bytes, struct 'H'
    data = (sccp_msg_type, sccp_class_msg_handling, sccp_hop_counter, sccp_pointer_one,
        sccp_pointer_two, sccp_pointer_three, sccp_pointer_optional, sccp_called_party_len,
        sccp_called_party_addr_ind, sccp_called_party_pc, sccp_called_party_sub,
        sccp_calling_party_len, sccp_calling_party_addr_ind, sccp_calling_party_pc,
        sccp_calling_party_sub, payload_length)

    return pack('>BBBHHHHBBHBBBHBH', *data)


class Packet():
    """Common methods for all child classes."""
    def __init__(self, raw_text:list) -> None:
        self.raw_text     = self._clean_packet_trail(raw_text)
        self.eventid      = None
        self.protocol     = None
        self.ip_version   = None
        self.ip_src       = None
        self.ip_dst       = None
        self.sport        = None
        self.dport        = None
        self.length       = None
        self.arrive_time  = None
        self.direction    = None
        self.hexdump      = None
        self.ignore       = False
        self.scapy_packet = None

    def __repr__(self):
        fmt = "{class_name}({arrive_time!s}, {direction!s}, {ip_src}:{sport} > {ip_dst}:{dport} len: {length})"
        return fmt.format(
            class_name  = self.__class__.__name__,
            protocol    = self.protocol,
            direction   = self.direction,
            arrive_time = self.arrive_time,
            ip_ver      = self.ip_version,
            ip_src      = self.ip_src,
            ip_dst      = self.ip_dst,
            sport       = self.sport,
            dport       = self.dport,
            length      = self.length,
        )

    def details(self):
        """ Get detailed view of the packet
        """
        fmt = """{class_name}(Ignore: {ignore} Eventid: {eventid!s:6} Protocol: {protocol!s}
 ---------------------------------
Arrive Time: {arrive_time} Direction: {direction} 
 ---------------------------------
IPv{ip_ver} {ip_src}:{sport} > {ip_dst}:{dport} len: {legth}
 ---------------------------------
Hexdump len = {hexdump_len} {hexdump}... )
        """
        return fmt.format(
            class_name = self.__class__.__name__,
            ignore     = self.ignore,
            eventid    = self.eventid,
            protocol   = self.protocol,
            direction  = self.direction,
            arrive_time = self.arrive_time,
            ip_ver      = self.ip_version,
            ip_src      = self.ip_src,
            ip_dst      = self.ip_dst,
            sport       = self.sport,
            dport       = self.dport,
            legth       = self.length,
            hexdump_len = len(self.hexdump),
            hexdump     = self.hexdump[:30]
        )

    def _get_arrive_time(self) -> 'time':
        """Extract packet arrival time"""
        date_str = ' '.join(self.raw_text[0].strip().split()[1:])
        time_str = self.raw_text[1].split('Eventid')[0].split()[-1]
        arrive_time = datetime.datetime.strptime(f'{date_str} {time_str}', "%B %d %Y %H:%M:%S:%f")
        arrive_time = time.mktime(arrive_time.timetuple()) + (arrive_time.microsecond / 1000000.0)
        return arrive_time

    def _get_direction(self) -> str:
        """ """
        direction = self.raw_text[1].split(' ')[0]
        if '>' in direction:
            direction = direction.split(' ')[0][:7]
        else:
            direction = direction.split(' ')[0][4:]
        return direction

    def _probe_ip_ver(self, line) -> 'ipaddress':
        """Determine if we have ipv4 or ipv6 packet.
         SAMPLES:
          240b:c0e0:201:2003:301:1:0:f01.34271 # with dot delimited port
          240b:c0e0:201:2004:601:1:0:d01:8805  # with colon delimited port
          2a00:1fa0:145b:69b2:0:66:cd75:b101   # no port
          ::
          172.19.204.11:2123
          8.8.8.8.53

        :param text: str: an ip address text from packet
        :param line: 

        """
        ip_addr_text = text = line
        try:
            res = ipaddress.ip_address(ip_addr_text).version
            return res
        except ValueError:
            pass

        if len(text.split('.')) == 5:
            ip_addr_text = '.'.join(text.split('.')[:-1])

        if ":" in text and not text == "::":
            ip_addr_text = text.split(':')[0]

        try:
            res = ipaddress.ip_address(ip_addr_text).version
            return res
        except ValueError:
            pass

        if len(text.split('.')) == 2:
            ip_addr_text = text.split('.')[0]
        else:
            ip_addr_text = ":".join(text.split(':')[:-1])

        res = ipaddress.ip_address(ip_addr_text).version
        return res

    def _clean_packet_trail(self, text) -> list:
        """ Remove garbage that can follow the hexdump of a packet.
        :text: (list) lines of the packet in list

        Match the ascii or regular hexdump starting from end of packet text.
        If we have match, exit.
        If not, keep track, remove afterwards.
        """
        num_lines_to_remove = 0
        for line in reversed(text):
            if bool(RE_HEXDUMP.match(line.strip())) or bool(RE_HEXDUMP_ASCII.match(line.strip())):
                break
            num_lines_to_remove +=1

        if num_lines_to_remove:
            #tex_to_remove = "".join(text[-num_lines_to_remove:])
            return text[:-num_lines_to_remove]

        return text

    def _get_hexdump(self, pkt_len:int) -> str:
        """Get hexdump only from packet

        :param pkt_len: int: Packet length
        :param pkt_len:int: 

        """
        if pkt_len % 16:
            lines_to_split = pkt_len // 16 + 1
        else:
            lines_to_split = pkt_len // 16

        text = self.raw_text[-lines_to_split:]

        if '0x' in text[0]:
            # removing leading 0x1234 and any whitespace that could be there.
            text = [x[7:].lstrip(' ') for x in text]
            magic = lambda y: ''.join(y[:39].split())
            dump = ''.join([magic(x) for x in text])
        else:
            dump = ''.join([''.join(x.split()) for x in text])
        return dump

    def _hexdump_sanity_check(self, hexdump:str, pkt_len:int) -> bool:
        """ Return True if there are only hexadecimal characters and
        if hexdump length matches calculated length

        :param hexdump: str: the hexdumpt to validate
        :param pkt_len: int: packet length
        :param hexdump:str: 
        :param pkt_len:int: 

        """

        searchstring = r'^[a-f0-9]{' + str(pkt_len * 2) + r'}$'
        if not bool(re.match(searchstring, hexdump, re.IGNORECASE)):
            raise HexdumpValidationError('Packet did not pass hexdump sanity check')

    def _get_l3_l4_data(self):
        """ """
        raise NotImplementedError

    def _get_scapy_packet(self):
        """ """
        raise NotImplementedError


class Gtpc(Packet):
    """GTPC packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            # IP header + UDP = 28
            # UDP is protocol number 17
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport,dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class GtpcV2(Packet):
    """GTPCv2 packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        if self.ip_version == 6:
            ip_src = ":".join(line[4].split(':')[:-1])
            ip_dst = ":".join(line[6].split(':')[:-1])
            sport = int(line[4].split(':')[-1])
            dport = int(line[6].split(':')[-1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport,dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        if self.ip_version == 6:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x86dd) /\
                           IPv6(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport,dport=self.dport) /\
                           bytes.fromhex(self.hexdump)
        scapy_packet.time = self.arrive_time
        return scapy_packet


class Gtpu(Packet):
    """GTPU packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        if self.ip_version == 6:
            ip_src = ":".join(line[4].split(':')[:-1])
            ip_dst = ":".join(line[6].split(':')[:-1])
            sport = int(line[4].split(':')[-1])
            dport = int(line[6].split(':')[-1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport,dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        if self.ip_version == 6:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x86dd) /\
                           IPv6(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport, dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Radius(Packet):
    """RADIUS packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[5]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[5].split(':')[0]
            ip_dst = line[7].split(':')[0]
            sport = int(line[5].split(':')[1])
            dport = int(line[7].split(':')[1])
            length = int(line[8].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport,dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class UserL3(Packet):
    """UserL3 packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[3].split()[0]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[3].split()
        if self.ip_version == 4:
            if 'icmp' not in line:
                ip_src = '.'.join(line[0].split('.')[:-1])
                ip_dst = '.'.join(line[2].split('.')[:-1])
                sport = int(line[0].split('.')[-1])
                dport = int(line[2].split('.')[-1][:-1])
            else:
                ip_src = line[0]
                ip_dst = line[2][:-1]
                sport = 0
                dport = 0

            for l in self.raw_text:
                if ', len' in l:
                    length = int(l.split(', len')[len(l.split(', len'))-1].split(')')[0].split(',')[0])
                    break

        if self.ip_version == 6:
            if 'icmp6' not in line:
                ip_src = line[0].split('.')[0]
                ip_dst = line[2].split('.')[0]
                try:
                    sport = int(line[0].split('.')[1])
                    dport = int(line[2].split('.')[1][:-1])
                except IndexError:
                    sport = 0
                    dport = 0
            else:
                ip_src = line[0]
                ip_dst = line[2]
                sport = 0
                dport = 0

            for l in self.raw_text:
                if '(len ' in l:
                    try:
                        length = int(l.split('len ')[1].split(',')[0])
                    except ValueError:
                        length = int(l.split('len ')[1][:-2])
                    # ipv6 Add 40 bytes to the len
                    length = length + 40
                    break

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           bytes.fromhex(self.hexdump)

        if self.ip_version == 6:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x86dd) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Css(Packet):
    """CSS packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[3].split()[0]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()
    
    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[3].split()
        if all(t not in line for t in {'icmp', 'icmp6:'}):
            if self.ip_version == 4:
                ip_src = '.'.join(line[0].split('.')[:-1])
                ip_dst = '.'.join(line[2].split('.')[:-1])
                sport = int(line[0].split('.')[-1])
                dport = int(line[2].split('.')[-1][:-1])

            if self.ip_version == 6:
                ip_src = line[0].split('.')[0]
                ip_dst = line[2].split('.')[0]
                sport = None
                dport = None

        elif 'icmp6:' in line:
            ip_src = line[0]
            ip_dst = line[2]
            sport = 0
            dport = 0

        elif 'icmp' in line:
            ip_src = line[0]
            ip_dst = line[2][:-1]
            sport = 0
            dport = 0

        if self.ip_version == 4:
            for l_val in self.raw_text[3:]:
                if ', len' in l_val:
                    length = int(l_val.split(', len')[len(l_val.split(', len'))-1].split(')')[0].split(',')[0])
                    break

        if self.ip_version == 6:
            for l_val in self.raw_text[3:]:
                if '(len ' in l_val:
                    # ipv6 Add 40 bytes to the len
                    length = int(l_val.split('len ')[1].split(',')[0].split(")")[0]) + 40 
                    break

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           bytes.fromhex(self.hexdump)

        if self.ip_version == 6:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x86dd) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Diameter(Packet):
    """DIAMETER packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[3]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[3].split(':')[0]
            ip_dst = line[5].split(':')[0]
            sport = int(line[3].split(':')[1])
            dport = int(line[5].split(':')[1])
        if self.ip_version == 6:
            ip_src = line[3].split('.')[0]
            ip_dst = line[5].split('.')[0]
            sport = int(line[3].split('.')[1])
            dport = int(line[5].split('.')[1])

        try:
            length = int(self.raw_text[4].split('REQ')[0].split()[3][1:])
        except IndexError:        
            for l in self.raw_text:
                if 'Message Length' in l:
                    try:
                        length = int(l.strip().split(': ')[1])
                    except (IndexError, ValueError):
                        pass
                    try:
                        length = int(l.strip().split(': ')[1].split('(')[1][:-1])
                    except (IndexError, ValueError):
                        pass

                    if length:
                        break

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) / \
                           SCTPChunkData(
                            ending=True,beginning=True,proto_id=46, 
                            data=bytes.fromhex(self.hexdump)
                            )

        if self.ip_version == 6:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x86dd) /\
                           IPv6(src=self.ip_src, dst=self.ip_dst, nh=132) /\
                           SCTP(sport=self.sport, dport=self.dport) /\
                           SCTPChunkData(ending=True,beginning=True,proto_id=46, data=bytes.fromhex(self.hexdump))

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Ranap(Packet):
    """RANAP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        self.ip_version = 4
        self.arrive_time = self._get_arrive_time()
        self.direction = self._get_direction()
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        ip_src = '0.0.0.0'
        ip_dst = '0.0.0.0'
        if self.direction == 'INBOUND':
            sport = 3006
            dport = 2905
        else:
            sport = 2905
            dport = 3006
        length = int(self.raw_text[2][0].split(' ')[7].split('(')[1].split()[0])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            # 23 bytes sccp header and 16 bytes m3ua
            sccp_header = get_sccp_header(self.length, 142, 142)
            m3ua_header = get_m3ua_header(self.length + 23 + 16, 0, 0)
            data = m3ua_header+sccp_header+bytes.fromhex(self.hexdump)
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) / \
                           SCTPChunkData(ending=True, beginning=True, proto_id=3, data=data)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Rua(Packet):
    """RUA packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        self.ip_version = 4
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        ip_src = '0.0.0.0'
        ip_dst = '0.0.0.0'
        if self.direction == 'INBOUND':
            sport = 3005
            dport = 2905
        else:
            sport = 2905
            dport = 3005
        length = int(self.raw_text[2].split(' ')[5].split('(')[1].split()[0])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) / \
                           SCTPChunkData(
                            ending=True, beginning=True, proto_id=19, 
                            data=bytes.fromhex(self.hexdump)
                            )

        scapy_packet.time = self.arrive_time
        return scapy_packet


class S1Ap(Packet):
    """S1AP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport  = int(line[4].split(':')[1])
            dport  = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        if self.ip_version == 6:
            ip_src = ":".join(line[4].split(':')[:-1])
            ip_dst = ":".join(line[6].split(':')[:-1])
            sport  = int(line[4].split(':')[-1])
            dport  = int(line[6].split(':')[-1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) /\
                           SCTPChunkData(
                            ending=True, beginning=True, proto_id=18,
                            data=bytes.fromhex(self.hexdump)
                            )

        if self.ip_version == 6:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x86dd) /\
                           IPv6(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) /\
                           SCTPChunkData(
                            ending=True, beginning=True, proto_id=18,
                            data=bytes.fromhex(self.hexdump)
                            )
        scapy_packet.time = self.arrive_time
        return scapy_packet


class SGs(Packet):
    """SGs packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) / \
                           SCTPChunkData(
                            ending=True, beginning=True, proto_id=0, 
                            data=bytes.fromhex(self.hexdump)
                           )

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Bssgp(Packet):
    """BSSGP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        self.ip_version = 4
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length, self.bvci = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        ip_src = '0.0.0.0'
        ip_dst = '0.0.0.0'
        if self.direction == 'INBOUND':
            sport = 3005
            dport = 2157
        else:
            sport = 2157
            dport = 3005
        bvci = int(self.raw_text[3].split('-')[2])
        length = int(self.raw_text[2].split()[2].split('(')[1].split()[0])
        return ip_src, ip_dst, sport, dport, length, bvci

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            ns_header = get_gprs_ns_header(self.bvci)
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport, dport=self.dport) /\
                           ns_header /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Tcap(Packet):
    """TCAP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        self.ip_version = 4
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        ip_src = '0.0.0.0'
        ip_dst = '0.0.0.0'
        if self.direction == 'INBOUND':
            sport = 3005
            dport = 2905
        else:
            sport = 2905
            dport = 3005
        length = int(self.raw_text[2].split(' ')[7].split('(')[1].split()[0])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            # 23bytes sccp header and 16 bytes m3ua
            sccp_header = get_sccp_header(self.length, 6, 149)
            m3ua_header = get_m3ua_header(self.length + 23 + 16, 0, 0)
            data = m3ua_header+sccp_header+bytes.fromhex(self.hexdump)
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) / \
                           SCTPChunkData(ending=True, beginning=True, proto_id=3, data=data)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Sccp(Packet):
    """SCCP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        self.ip_version = 4
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        ip_src = '0.0.0.0'
        ip_dst = '0.0.0.0'
        if self.direction == 'INBOUND':
            sport = 3005
            dport = 2905
        else:
            sport = 2905
            dport = 3005
        length = int(self.raw_text[2].split()[6].split('(')[1].split()[0])
        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            m3ua_header = get_m3ua_header(self.length + 16, 0, 0)
            data = m3ua_header+bytes.fromhex(self.hexdump)
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) / \
                           SCTPChunkData(ending=True, beginning=True, proto_id=3, data=data)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class IkeV2(Packet):
    """IKEV2 packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport, dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class L2tp(Packet):
    """L2TP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport, dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Ppp(Packet):
    """PPP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        return int(line[3].split('(')[1][:-1])

    def _get_scapy_packet(self):       
        """ """
        scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0xc021) /\
                   bytes.fromhex(self.hexdump[8:])

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Dns(Packet):
    """DNS packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[3].split()[2]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        if self.ip_version == 4:
            ip_src = self.raw_text[3].split()[2]
            ip_dst = self.raw_text[4].split()[2]
            sport = int(self.raw_text[3].split()[4])
            dport = int(self.raw_text[4].split()[4])
            length = int(self.raw_text[5].split()[2])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport, dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Dhcp(Packet):
    """DHCP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()
    
    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport, dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class L3Tunnel(Packet):
    """L3 Tunnel packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[0]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[0]
            ip_dst = line[2]
            sport = 0
            dport = 0

            for l in self.raw_text:
                if ", len " in l:
                    # adding here 38 bytes for GRE + IP + Ethernet headers
                    length = int(l.split()[-1][:-1]) + 38

            if not length:
                raise IENotFound('Could not determine the length of packet')

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Pfcp(Packet):
    """PFCP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        if self.ip_version == 6:
            ip_src = ":".join(line[4].split(':')[:-1])
            ip_dst = ":".join(line[6].split(':')[:-1])
            sport = int(line[4].split(':')[-1])
            dport = int(line[6].split(':')[-1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport,dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        if self.ip_version == 6:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x86dd) /\
                           IPv6(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport,dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Gtpp(Packet):
    """GTPP packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           UDP(sport=self.sport,dport=self.dport) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Sls(Packet):
    """SLS packet

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[2].split()[4]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()        
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[2].split()
        if self.ip_version == 4:
            ip_src = line[4].split(':')[0]
            ip_dst = line[6].split(':')[0]
            sport = int(line[4].split(':')[1])
            dport = int(line[6].split(':')[1])
            length = int(line[7].split('(')[1][:-1])

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):       
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           IP(src=self.ip_src, dst=self.ip_dst) /\
                           SCTP(sport=self.sport, dport=self.dport) / \
                           SCTPChunkData(ending=True, beginning=True, proto_id=0, data=bytes.fromhex(self.hexdump))

        scapy_packet.time = self.arrive_time
        return scapy_packet


class Sctp(Packet):
    """SCTP packet
    SAMPLE:
      <<<<OUTBOUND  From mmemgr:1 mmemgr_sctp.c:3472 12:08:29:896 Eventid:87302(12)
      ===> Stream Control Transmission Protocol (SCTP) (32 bytes)
        src IP: 10.1.33.1 : 29118 > dst IP: 10.2.34.1 : 29118
        Verification Tag: 0x1f07aa55
        Checksum: 0xfe869832
          1)[HB REQ]
            Chunk Type: 0x04
            Chunk Flags: 0x0

    :param raw_text: list: Lines in list of packet text

    """
    def __init__(self, raw_text: list):
        super().__init__(raw_text)
        an_ip_address = self.raw_text[3].split()[2]
        self.ip_version = self._probe_ip_ver(an_ip_address)
        self.direction = self._get_direction()
        self.arrive_time = self._get_arrive_time()
        self.ip_src, self.ip_dst, self.sport, self.dport, self.length = self._get_l3_l4_data()
        self.hexdump = self._get_hexdump(self.length)
        self._hexdump_sanity_check(self.hexdump, self.length)
        self.scapy_packet = self._get_scapy_packet()

    def _get_l3_l4_data(self):
        """ """
        line = self.raw_text[3].split()
        if self.ip_version == 4:
            ip_src = line[2]
            ip_dst = line[8]
            sport = int(line[4])
            dport = int(line[10])
            length = int(self.raw_text[2].split()[-2][1:]) + 20 # IP Header

        return ip_src, ip_dst, sport, dport, length

    def _get_scapy_packet(self):
        """ """
        if self.ip_version == 4:
            scapy_packet = Ether(src='00:00:00:00:00:00', dst='00:00:00:00:00:00', type=0x0800) /\
                           bytes.fromhex(self.hexdump)

        scapy_packet.time = self.arrive_time
        return scapy_packet

PARSERS = {
    'GTPC'          : Gtpc,
    'GTPCv2'        : GtpcV2,
    'GTPU'          : Gtpu,
    'RADIUS'        : Radius,
    'USERL3'        : UserL3,
    'USERL3_IPV6'   : UserL3,
    'CSS'           : Css,
    'DIAMETER'      : Diameter,
    'RANAP'         : Ranap,
    'RUA'           : Rua,
    'S1AP'          : S1Ap,
    'SGS'           : SGs,
    'BSSGP'         : Bssgp,
    'TCAP'          : Tcap,
    'SCCP'          : Sccp,
    'IKEv2'         : IkeV2,
    'L2TP'          : L2tp,
    'PPP'           : Ppp,
    'DNS'           : Dns,
    'DHCP'          : Dhcp,
    'L3_TUNNEL'     : L3Tunnel,
    'PFCP'          : Pfcp,
    'GTPP'          : Gtpp,
    'SLS'           : Sls,
    'SCTP'          : Sctp
}

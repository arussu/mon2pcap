""" mon2pcap.py """

from __future__ import annotations

import logging
from typing import Iterable
from pathlib import Path

from tqdm import tqdm

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
from scapy.all import PcapWriter

from .constants import STATS, protocol_mapping
from .errors import FilteredPacket, HexdumpValidationError, IgnoredPacket
from .helpers import chunk_packet_from_input, linecount
from .packets import PARSERS, Packet

# pylint: disable=logging-fstring-interpolation
mon2pcap_log = logging.getLogger(__name__)


class Mon2Pcap:
    """Read a "monitor subscriber" or "monitor protocol" dump and convert it to PCAP

    :param fin: The input ASCII monsub text file
    :param fout: The output file name, compted automatically if not provided.
    :param filter: Iterable[str]: Protocols to ignore
    :param skip_malformed: bool: Skip malformed packets and do not raise exceptions

    """

    def __init__(
        self,
        fin: str,
        fout: str = None,
        exclude: Iterable[str] = None,
        skip_malformed: bool = True,
    ):
        self._fin = fin
        self._fout = fout
        self._exclude = exclude
        self._skip_malformed = skip_malformed
        self.packets = []
        self._stats = STATS.copy()
        self._linecount = None
        self._progress = None

        assert self._exclude is None or isinstance(self._exclude, list)
        assert isinstance(self._skip_malformed, bool)

    @property
    def fout(self):
        if not self._fout:
            self._fout = str(Path(self._fin).with_suffix(".pcap"))
        return self._fout

    @property
    def linecount(self):
        """Read the number of lines in the file"""
        if not self._linecount:
            self._linecount = linecount(self._fin)
        return self._linecount

    @property
    def stats(self):
        return self._stats

    def _get_packets(self, show_progress: bool = False):
        """Yield parsed packets"""
        with open(self._fin, "r", encoding="utf-8", errors="ignore") as opened_file:
            if show_progress:
                self._progress = tqdm(opened_file, unit=" lines", total=self.linecount, leave=True)

            for pnum, packet_text in enumerate(chunk_packet_from_input(opened_file), 1):
                if show_progress:
                    self._progress.update(len(packet_text))

                try:
                    packet = self._parse_packet(packet_text)
                except IgnoredPacket as err:
                    self._stats["Ignored"] += 1
                    mon2pcap_log.debug(f"PACKET #{pnum:06} Could not parse: {repr(err)}")
                    continue
                except FilteredPacket:
                    mon2pcap_log.debug(f"PACKET #{pnum:06} Ignoring filtered packet")
                    self._stats["Filtered"] += 1
                    continue
                except HexdumpValidationError:
                    if self._skip_malformed:
                        mon2pcap_log.debug(f"PACKET #{pnum:06} did not pass hexdump validation, ignoring")
                        self._stats["Ignored"] += 1
                        continue

                    p_text = "".join(packet_text)
                    log_text = f"PACKET #{pnum:06} did not pass hexdump validation{chr(10)}{p_text}"
                    mon2pcap_log.critical(log_text, exc_info=True)
                    raise
                except Exception:
                    if self._skip_malformed:
                        timestamp = packet_text[1].split("Eventid")[0].split()[-1]
                        log_text = f"PACKET #{pnum:06} Failed to parse packet text received at {timestamp}"
                        mon2pcap_log.debug(log_text, exc_info=True)
                        continue
                    p_text = "".join(packet_text)
                    log_text = f"PACKET #{pnum:06} Failed to parse packet text:{chr(10)}{p_text}"
                    mon2pcap_log.error(log_text, exc_info=True)
                    raise

                if packet:
                    log_text = f"PACKET #{pnum:06} Parsed {packet}"
                    mon2pcap_log.debug(log_text)
                    yield packet

        # reset progress
        self._progress = None

    def _parse_packet(self, text) -> Packet:
        """Parse the packet text

        :param text:
        :return: Packet instance
        """

        eventid = self._get_event_id(text)

        if not (protocol := self._get_protocol(eventid)):
            raise IgnoredPacket(f'No matching protocol for Eventid "{eventid}"')

        if self._exclude and protocol in self._exclude:
            raise FilteredPacket(f"Filtered packet of {protocol} protocol")

        packet = PARSERS.get(protocol)
        packet = packet(text)
        packet.eventid = eventid
        packet.protocol = protocol

        self._stats[protocol] += 1
        return packet

    def _get_event_id(self, text) -> str:
        """Eventid is, usually, in the same spot, get it.

        :param text: packet text

        """
        try:
            eventid = text[1].split("Eventid:")[1].split("(")[0].strip()
        except IndexError as exc:
            raise IgnoredPacket("Could not get EventId") from exc
        return eventid

    def _get_protocol(self, eventid) -> str:
        """Each evntid matches a specific protocol.
        Thsi function will return the protocol name as string

        :param eventid:
        :return: str: the protocol name
        """
        return protocol_mapping(eventid)

    def read_packets(self, count: int = 0, show_progress: bool = False):
        """Read parsed packets into `self.packets`

        :param count:  (Default value = 0)
        :param show_progress: bool: show progress as we parse the file
        """
        if count and show_progress:
            progress = tqdm(self._get_packets(), unit=" packets", total=count, leave=True)
            packets_generator = self._get_packets()
        else:
            packets_generator = self._get_packets(show_progress)

        for num, packet in enumerate(packets_generator, 1):
            if count and show_progress:
                progress.update(1)

            self.packets.append(packet)
            if num == count:
                break

    def write_packets(self, count: int = 0, packets_per_write: int = 0, show_progress: bool = False):
        """Write packets to file

        :param count: number of packets to write, '0' = ALL
        :param packets_per_write: how many packets to buffer before one write operation
        :param show_progress: bool: show progress as we parse the file
        """

        mon2pcap_log.warning('Setting the output fname as "%s"', self.fout)

        buffer = []
        append_to_file = False  # overwrite if existing

        for num, packet in enumerate(self._get_packets(show_progress)):
            buffer.append(packet.scapy_packet)

            if len(buffer) == packets_per_write:
                PcapWriter(self._fout, append=append_to_file, sync=True).write(buffer)
                buffer.clear()

                if num == packets_per_write:
                    append_to_file = True

            if count and (num == count - 1):
                # reset progress
                self._progress = None
                break

        if buffer:
            PcapWriter(self._fout, append=append_to_file, sync=True).write(buffer)

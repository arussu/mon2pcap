"""mon2pcap.py"""

import logging
from pathlib import Path
from typing import Iterable, List, Optional

from tqdm import tqdm

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
from scapy.all import PcapWriter

from .constants import STATS, protocol_mapping
from .errors import FilteredPacket, HexdumpValidationError, IgnoredPacket
from .helpers import chunk_packet_from_input, linecount
from .packets import PARSERS, Packet

mon2pcap_log = logging.getLogger(__name__)


class Mon2Pcap:
    """Read a *monitor subscriber* or *monitor protocol* dump and convert it to PCAP.

    :param fin: Path to the input ASCII mon-sub text file.
    :param fout: Path for the output PCAP file; derived from *fin* if not given.
    :param exclude: Protocols to skip (e.g. ``["GTPU", "DNS"]``).
    :param skip_malformed: When ``True`` (default), silently skip packets that
        cannot be parsed instead of raising an exception.
    """

    def __init__(
        self,
        fin: str,
        fout: Optional[str] = None,
        exclude: Optional[Iterable[str]] = None,
        skip_malformed: bool = True,
    ) -> None:
        if exclude is not None and not isinstance(exclude, list):
            raise TypeError("'exclude' must be a list or None")
        if not isinstance(skip_malformed, bool):
            raise TypeError("'skip_malformed' must be a bool")

        self._fin = fin
        self._fout = fout
        self._exclude: Optional[List[str]] = list(exclude) if exclude is not None else None
        self._skip_malformed = skip_malformed
        self.packets: List[Packet] = []
        self._stats = STATS.copy()
        self._linecount: Optional[int] = None
        self._progress = None

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
        """Yield parsed :class:`Packet` instances from the input file.

        :param show_progress: Display a tqdm progress bar while reading.
        """
        with open(self._fin, "r", encoding="utf-8", errors="ignore") as opened_file:
            if show_progress:
                self._progress = tqdm(opened_file, unit=" lines", total=self.linecount, leave=True)

            for pnum, packet_text in enumerate(chunk_packet_from_input(opened_file), 1):
                if show_progress and self._progress is not None:
                    self._progress.update(len(packet_text))

                try:
                    packet = self._parse_packet(packet_text)
                except IgnoredPacket as err:
                    self._stats["Ignored"] += 1
                    mon2pcap_log.debug("PACKET #%06d Could not parse: %r", pnum, err)
                    continue
                except FilteredPacket:
                    mon2pcap_log.debug("PACKET #%06d Ignoring filtered packet", pnum)
                    self._stats["Filtered"] += 1
                    continue
                except HexdumpValidationError:
                    if self._skip_malformed:
                        mon2pcap_log.debug("PACKET #%06d did not pass hexdump validation, ignoring", pnum)
                        self._stats["Ignored"] += 1
                        continue
                    p_text = "".join(packet_text)
                    mon2pcap_log.critical(
                        "PACKET #%06d did not pass hexdump validation\n%s", pnum, p_text, exc_info=True
                    )
                    raise
                except Exception:
                    if self._skip_malformed:
                        timestamp = packet_text[1].split("Eventid")[0].split()[-1]
                        mon2pcap_log.debug(
                            "PACKET #%06d Failed to parse packet text received at %s", pnum, timestamp, exc_info=True
                        )
                        continue
                    p_text = "".join(packet_text)
                    mon2pcap_log.error("PACKET #%06d Failed to parse packet text:\n%s", pnum, p_text, exc_info=True)
                    raise

                if packet:
                    mon2pcap_log.debug("PACKET #%06d Parsed %s", pnum, packet)
                    yield packet

        self._progress = None

    def _parse_packet(self, text: List[str]) -> Packet:
        """Parse one raw packet block and return the corresponding :class:`Packet`.

        :param text: Lines of the raw packet block.
        :raises IgnoredPacket: If the Eventid is unknown or missing.
        :raises FilteredPacket: If the protocol is in the exclusion list.
        """
        eventid = self._get_event_id(text)

        protocol = protocol_mapping(eventid)
        if not protocol:
            raise IgnoredPacket(f'No matching protocol for Eventid "{eventid}"')

        if self._exclude and protocol in self._exclude:
            raise FilteredPacket(f"Filtered packet of {protocol} protocol")

        parser_cls = PARSERS[protocol]
        packet = parser_cls(text)
        packet.eventid = eventid
        packet.protocol = protocol

        self._stats[protocol] += 1
        return packet

    def _get_event_id(self, text: List[str]) -> str:
        """Extract the Eventid string from the packet header.

        :param text: Lines of the raw packet block.
        :raises IgnoredPacket: If the Eventid field cannot be located.
        """
        try:
            return text[1].split("Eventid:")[1].split("(")[0].strip()
        except IndexError as exc:
            raise IgnoredPacket("Could not get EventId") from exc

    def read_packets(self, count: int = 0, show_progress: bool = False) -> None:
        """Parse packets from the input file into :attr:`packets`.

        :param count: Maximum number of packets to read; ``0`` means all.
        :param show_progress: Display a tqdm progress bar while reading.
        """
        if count and show_progress:
            # Use a count-based progress bar wrapping the generator
            progress = tqdm(self._get_packets(), unit=" packets", total=count, leave=True)
            for num, packet in enumerate(progress, 1):
                self.packets.append(packet)
                if num == count:
                    break
        else:
            for num, packet in enumerate(self._get_packets(show_progress), 1):
                self.packets.append(packet)
                if count and num == count:
                    break

    def write_packets(self, count: int = 0, packets_per_write: int = 0, show_progress: bool = False) -> None:
        """Stream packets directly to the output PCAP file.

        :param count: Maximum number of packets to write; ``0`` means all.
        :param packets_per_write: Flush to disk every *N* packets; ``0`` means
            accumulate all in memory then write once.
        :param show_progress: Display a tqdm progress bar while writing.
        """
        mon2pcap_log.warning('Setting the output filename as "%s"', self.fout)

        buffer = []
        append_to_file = False  # first write must truncate any existing file

        for num, packet in enumerate(self._get_packets(show_progress), 1):
            buffer.append(packet.scapy_packet)

            if packets_per_write and len(buffer) == packets_per_write:
                PcapWriter(self._fout, append=append_to_file, sync=True).write(buffer)
                buffer.clear()
                append_to_file = True  # subsequent writes must append

            if count and num == count:
                self._progress = None
                break

        if buffer:
            PcapWriter(self._fout, append=append_to_file, sync=True).write(buffer)

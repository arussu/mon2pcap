"""helpers.py"""

import logging
from typing import Generator, List

logger = logging.getLogger(__name__)

# Days used to detect the start of a new packet block in the dump file
_DAYS_OF_WEEK = {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}


def chunk_packet_from_input(file) -> Generator[List[str], None, None]:
    """Split a monitor-subscriber dump into per-packet chunks.

    Every packet block starts with a day-of-the-week header line.
    Yields one list of raw text lines per packet.

    :param file: An open text file object (iterable of lines).
    """
    chunk: List[str] = []
    in_packet = False

    for lnum, line in enumerate(file, 1):
        try:
            # Normalise tabs and strip NUL bytes seen in some StarOS files
            line = line.replace("\t", "    ").replace("\x00", "")

            if not line.strip():
                continue

            first_word = line.strip().split()[0]
            is_day_header = first_word in _DAYS_OF_WEEK

            if is_day_header and in_packet:
                # A new packet header signals the end of the previous chunk
                yield chunk
                chunk = []

            if is_day_header:
                in_packet = True

            if in_packet:
                chunk.append(line)

        except IndexError:
            chunk.append(line)
            logger.error(
                'Unexpected IndexError at line %s (len=%s). Accumulated chunk: "%s"',
                lnum,
                len(line),
                repr("".join(chunk)),
            )
            raise

    if chunk:
        yield chunk


def linecount(filename: str) -> int:
    """Count the total number of lines in *filename* as fast as possible.

    Reads the file in large binary chunks to avoid Python string overhead.

    :param filename: Path to the file.
    :returns: Total number of newline characters (i.e. lines).
    """
    buf_size = 1024 * 1024  # 1 MiB
    lines = 0
    with open(filename, "rb") as fh:
        buf = fh.raw.read(buf_size)
        while buf:
            lines += buf.count(b"\n")
            buf = fh.raw.read(buf_size)
    logger.debug("Total number of lines in file: %s", lines)
    return lines

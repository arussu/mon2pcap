""" helpers.py """

import logging

logger = logging.getLogger(__name__)


def chunk_packet_from_input(file):
    """Split the long file into separate packet data and focus on single chunk.
     Every packet starts with a day of the week.
     This function separates text between dates
     This is a generator

    :param file:

    """
    days_of_week = {
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    }
    chunk = []
    num = 0
    for lnum, line in enumerate(file, 1):
        try:
            line = line.replace("\t", "    ").replace(
                "\x00", ""
            )  # replace `NUL` character seen in some files
            if not line.strip():
                chunk.append(line)
                continue
            if line.strip().split()[0] in days_of_week and num > 2:
                num = 0
                yield chunk
                chunk.clear()
            if line.strip().split()[0] in days_of_week and num == 0:
                num += 1
            if not (chunk and num == 0):
                chunk.append(line)
                num += 1
        except IndexError:
            chunk.append(line)
            logger.error(
                'Failure in lnum = %s, len line = %s, chunk = "%s"',
                lnum,
                len(line),
                repr("".join(chunk)),
            )
            raise
    yield chunk


def linecount(filename):
    """
     Calculate the total number of lines in the file really quickly

    :param filename: str: path to file
    """
    with open(filename, "rb") as f:
        lines = 0
        buf_size = 1024 * 1024
        read_f = f.raw.read
        buf = read_f(buf_size)
        while buf:
            lines += buf.count(b"\n")
            buf = read_f(buf_size)
    f.close()
    logger.debug(f"Total number of lines in file: {lines}")
    return lines

#!/usr/bin/python
"""console.py — Command-line entry point for mon2pcap."""

import argparse
import logging
import sys
from typing import Dict

try:
    from importlib.metadata import version
except ImportError:
    from importlib_metadata import version  # type: ignore[no-redef]

from .constants import COLORS
from .mon2pcap import Mon2Pcap
from .packets import PARSERS

__version__ = version(__package__ or __name__)


def print_stats(stats: Dict[str, int]) -> None:
    """Print per-protocol packet counts to stdout.

    :param stats: Protocol-keyed counter dict (as returned by
        :attr:`Mon2Pcap.stats`).
    """
    total = sum(stats.values()) - (stats["Ignored"] + stats["Filtered"])
    lines = [
        f"\nFound #{COLORS['OKGREEN']}{total}{COLORS['ENDC']} valid packets",
        "========================",
    ]
    for key, value in stats.items():
        if value:
            lines.append(f" {key:<12} : {value}")
    print("\n".join(lines))


def run():
    """Script code for console execution"""
    parser = argparse.ArgumentParser(
        description='Convert StarOS "monitor subscriber" or "monitor protocol" ASCII dump to PCAP'
    )
    parser.add_argument(
        "-i",
        "--input",
        metavar="<infile>",
        dest="infile",
        type=str,
        help="input file",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="<outfile>",
        dest="outfile",
        type=str,
        help="output file",
    )
    parser.add_argument(
        "-e",
        nargs="+",
        type=str.upper,
        dest="exclude",
        choices=list(PARSERS.keys()),
        help="exclude one or more protocols",
    )
    parser.add_argument(
        "-s",
        "--do-not-skip-malformed",
        action="store_false",
        dest="skip_malformed",
        help="Skip malformed packets",
    )
    parser.add_argument("-v", "--version", action="version", version=f"{parser.prog} {__version__}")
    parser.add_argument("-d", "--debug", action="store_true", dest="debug", help="debug level logging")
    args = parser.parse_args()

    show_progress = True
    if args.debug:
        logging.basicConfig(
            stream=sys.stdout,
            level=logging.INFO,
            format="%(asctime)s.%(msecs)d - %(name)s (%(lineno)s) - %(levelname)s: %(message)s",
            datefmt="%Y/%m/%d %H:%M:%S",
        )
        logging.getLogger("mon2pcap").setLevel(logging.DEBUG)
        show_progress = False

    parsed_file = Mon2Pcap(
        fin=args.infile,
        fout=args.outfile,
        exclude=args.exclude,
        skip_malformed=args.skip_malformed,
    )

    parsed_file.write_packets(show_progress=show_progress)
    print(f'\nPCAP generated at "{parsed_file.fout}"')
    print_stats(parsed_file.stats)


if __name__ == "__main__":
    run()

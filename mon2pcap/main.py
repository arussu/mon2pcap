#!/usr/bin/python

import sys
import logging
import argparse
import jinja2

from .mon2pcap import Mon2Pcap, __version__
from .packets import PARSERS
from .constants import COLORS

def print_stats(stats:'collections.OrderedDict'):
    """ Print statistics nicely
    :param stats: Stats dict

    """
    total = sum(stats.values()) - (stats['Ignored'] + stats['Filtered'])
    environment = jinja2.Environment(autoescape=True)
    template = environment.from_string('''
Found #{{ [ COLORS["OKGREEN"], total, COLORS["ENDC"] ]|join }} valid packets
========================
    {%- for key, value in stats.items() %}
 {%- if value != 0 %}
 {{ "%-12s"|format(key) }} : {{ value }}
 {%- endif %}
    {%- endfor %}
    ''')
    rendered = template.render(COLORS=COLORS, stats=stats, total = total)
    print(rendered)


def main():
    """ Main
    """
    parser = argparse.ArgumentParser(
        description='Convert StarOS "monitor subscriber" or "monitor protocol" ASCII dump to PCAP')
    parser.add_argument('-i', '--input', metavar='<infile>', dest="infile", type=str,
                        help='input file', required=True)
    parser.add_argument('-o', '--output', metavar='<outfile>', dest="outfile", type=str,
                        help='output file')
    parser.add_argument('-e', nargs='+', type=str.upper, dest='exclude',
                        choices=list(PARSERS.keys()), help='exclude one or more protocols')
    parser.add_argument('-s', '--do-not-skip-malformed', action='store_false', dest='skip_malformed',
                        help='Skip malformed packets')
    parser.add_argument('-v', '--version', action='version', version=f'{parser.prog} {__version__}')
    parser.add_argument('-d', '--debug', action='store_true', dest='debug',
                        help='debug level logging')
    args = parser.parse_args()

    show_progress = True
    if args.debug:
        logging.basicConfig(stream=sys.stdout,
                        level=logging.INFO,
                        format="%(asctime)s.%(msecs)d - %(name)s (%(lineno)s) - %(levelname)s: %(message)s",
                        datefmt="%Y/%m/%d %H:%M:%S")
        logging.getLogger('mon2pcap').setLevel(logging.DEBUG)
        show_progress = False

    parsed_file = Mon2Pcap(fin=args.infile, fout=args.outfile, exclude=args.exclude,
            skip_malformed=args.skip_malformed)

    parsed_file.write_packets(show_progress=show_progress)
    print(f'{chr(10)}PCAP generated at "{parsed_file.fout}"')
    print_stats(parsed_file.stats)

if __name__ == "__main__":
    main()

""" constanst.py """

import re
from collections import OrderedDict

STATS = OrderedDict(
    [
        ("DNS", 0),
        ("GTPC", 0),
        ("GTPCv2", 0),
        ("DIAMETER", 0),
        ("GTPU", 0),
        ("RADIUS", 0),
        ("USERL3", 0),
        ("USERL3_IPV6", 0),
        ("CSS", 0),
        ("RANAP", 0),
        ("RUA", 0),
        ("S1AP", 0),
        ("SGS", 0),
        ("BSSGP", 0),
        ("SCCP", 0),
        ("TCAP", 0),
        ("IKEv2", 0),
        ("L2TP", 0),
        ("PPP", 0),
        ("DHCP", 0),
        ("L3_TUNNEL", 0),
        ("PFCP", 0),
        ("GTPP", 0),
        ("SLS", 0),
        ("SCTP", 0),
        ("LMISF", 0),
        ("Ignored", 0),
        ("Filtered", 0),
    ]
)

RE_HEXDUMP = re.compile(r"^([0-9a-f]{2,4}\s?){1,8}$", re.IGNORECASE)
RE_HEXDUMP_ASCII = re.compile(
    r"^0x[0-9a-f]{4}\s+([0-9a-f]{1,4}\s?){1,8}", re.IGNORECASE
)
COLORS = {
    "HEADER": "\033[95m",
    "OKBLUE": "\033[94m",
    "OKGREEN": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m",
    "UNDERLINE": "\033[4m",
}


def protocol_mapping(eventid: str) -> str | None:
    """Match the eventid to the protocol name as str

    :param eventid: The packet `eventid`
    :param eventid: str:

    """
    table = {
        "47000": "GTPC",
        "47001": "GTPC",
        "157265": "GTPC",
        "141004": "GTPCv2",
        "141005": "GTPCv2",
        "141023": "GTPCv2",
        "116003": "GTPCv2",
        "116004": "GTPCv2",
        "142004": "GTPU",
        "142005": "GTPU",
        "86903": "GTPU",
        "86904": "GTPU",
        "23900": "RADIUS",
        "23901": "RADIUS",
        "24900": "RADIUS",
        "24901": "RADIUS",
        "70901": "RADIUS",
        "70902": "RADIUS",
        "51000": "USERL3",
        "51004": "USERL3",
        "77000": "CSS",
        "77001": "CSS",
        "77002": "CSS",
        "77003": "CSS",
        "87730": "RANAP",
        "87731": "RANAP",
        "152002": "RUA",
        "152001": "RUA",
        "155212": "S1AP",
        "155213": "S1AP",
        "81990": "DIAMETER",
        "81991": "DIAMETER",
        "92801": "DIAMETER",
        "92800": "DIAMETER",
        "92810": "DIAMETER",
        "92811": "DIAMETER",
        "92820": "DIAMETER",
        "92821": "DIAMETER",
        "92870": "DIAMETER",
        "92871": "DIAMETER",
        "173001": "SGS",
        "173002": "SGS",
        "115054": "BSSGP",
        "115053": "BSSGP",
        "86513": "TCAP",
        "86512": "TCAP",
        "51002": "USERL3_IPV6",
        "51006": "USERL3_IPV6",
        "86731": "SCCP",
        "86730": "SCCP",
        "122903": "IKEv2",
        "122904": "IKEv2",
        "50000": "L2TP",
        "50001": "L2TP",
        "49000": "L2TP",
        "49001": "L2TP",
        "25000": "PPP",
        "25001": "PPP",
        "5956": "DNS",
        "5957": "DNS",
        "53500": "DHCP",
        "53501": "DHCP",
        "75002": "L3_TUNNEL",
        "75003": "L3_TUNNEL",
        "221301": "PFCP",
        "221302": "PFCP",
        "52000": "GTPP",
        "52001": "GTPP",
        "206301": "SLS",
        "206302": "SLS",
        "87301": "SCTP",
        "87302": "SCTP",
        "69126": "LMISF",
    }
    return table.get(eventid)

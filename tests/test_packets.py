"""Tests for packet-class parsing."""

import pytest

from mon2pcap.errors import IENotFound
from mon2pcap.packets import Diameter

# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------


def _make_diameter(raw_lines):
    """Return a ``Diameter`` instance with ``raw_text`` pre-set.

    Bypasses ``__init__`` (which requires a hexdump) so we can unit-test the
    parsing helpers in isolation.
    """
    d = Diameter.__new__(Diameter)
    d.raw_text = raw_lines
    d.ip_version = 4
    d.direction = "OUTBOUND"
    return d


# ---------------------------------------------------------------------------
# Sample raw packet texts
# ---------------------------------------------------------------------------

# A "standard" request whose type name does NOT contain the string "REQ".
# The old split("REQ") approach happened to work here.
CREDIT_CONTROL_REQUEST = [
    "Thursday April 16 2026\n",
    "<<<<OUTBOUND  10:00:00:000 Eventid:92800(5)\n",
    "Diameter message from 10.0.0.1:3868 to 10.0.0.2:3868\n",
    "  Diameter Credit-Control-Request Diameter Gx v1 L256 REQ PXY\n",
    "    Hop2Hop-ID: 00000001 End2End-ID: 00000002\n",
]

# Diameter-EAP-Request: "REQ" is embedded inside "EAP-Request".
# The old split("REQ") cut the line at the wrong position → IndexError.
EAP_REQUEST = [
    "Thursday April 16 2026\n",
    "<<<<OUTBOUND  14:51:10:069 Eventid:92870(5)\n",
    "Diameter message from 10.0.0.1:3868 to 10.0.0.2:3868\n",
    "  Diameter-EAP-Request Diameter STa v1 L612 REQ PXY   \n",
    "    Hop2Hop-ID: afcf1f4b End2End-ID: 4ba79809\n",
]

# Verbose decoded format with "Message Length:" instead of the compact token.
MESSAGE_LENGTH_LINE = [
    "Thursday April 16 2026\n",
    "<<<<OUTBOUND  10:00:00:000 Eventid:92800(5)\n",
    "Diameter message from 10.0.0.1:3868 to 10.0.0.2:3868\n",
    "  Some-Decoded-Message\n",
    "    Message Length: 128\n",
]

# Header with "Message Length: 128(0x80)" — parenthesised hex form.
MESSAGE_LENGTH_HEX = [
    "Thursday April 16 2026\n",
    "<<<<OUTBOUND  10:00:00:000 Eventid:92800(5)\n",
    "Diameter message from 10.0.0.1:3868 to 10.0.0.2:3868\n",
    "  Some-Decoded-Message\n",
    "    Message Length: 128(0x80)\n",
]

# Hexdump in "0xNNNN   hh hh ..." format (3 spaces after offset).
# The old slice line[7:46] started 2 chars inside the padding and ended 2 chars
# before the last hex group, silently truncating every line's last hex pair.
# Lines below reproduce the first two hexdump rows of real packet #236 from
# DERH-EX-CASR5500-01 16-04-2026 mon-prot-2.log (Diameter-EAP-Request, 612 B).
# We use a 20-byte (16 + 4) subset so the test stays concise.
HEXDUMP_0X_PREFIX_20B = [
    "Thursday April 16 2026\n",
    "<<<<OUTBOUND  14:49:37:760 Eventid:92870(5)\n",
    "Diameter message from 10.0.0.1:3868 to 10.0.0.2:3868\n",
    "  Diameter-EAP-Request Diameter STa v1 L20 REQ PXY   \n",
    "    Hop2Hop-ID: cee202e5 End2End-ID: 17dbd87b\n",
    '0x0000   0100 0264 c000 02ac 0100 0022 fa62 02e5        ...d..."....\n',
    "0x0010   17db d87b                                      ...{\n",
]
# Expected: 8 groups from line 1 + 2 groups from line 2 = 20 bytes = 40 hex chars.
_HEXDUMP_0X_PREFIX_20B_EXPECTED = "01000264c00002ac01000022fa6202e517dbd87b"

# No recognisable length anywhere — should raise IENotFound.
NO_LENGTH = [
    "Thursday April 16 2026\n",
    "<<<<OUTBOUND  14:51:10:069 Eventid:92870(5)\n",
    "Diameter message from 10.0.0.1:3868 to 10.0.0.2:3868\n",
    "  Unknown-Message Diameter STa v1 REQ PXY\n",  # no L{n} token
    "    Hop2Hop-ID: afcf1f4b End2End-ID: 4ba79809\n",
]


# ---------------------------------------------------------------------------
# Diameter length extraction
# ---------------------------------------------------------------------------


class TestDiameterLengthExtraction:
    """Unit-tests for ``Diameter._extract_diameter_length``."""

    def test_standard_request_compact_token(self):
        """A plain 'L256' token is found correctly."""
        d = _make_diameter(CREDIT_CONTROL_REQUEST)
        assert d._extract_diameter_length() == 256

    def test_eap_request_compact_token(self):
        """'L612' is found even though the line also contains 'REQ' in the
        message type name ('Diameter-EAP-Request').

        Regression: the old ``split("REQ")`` split 'Diameter-EAP-Request' at
        the wrong place, leaving only ``["Diameter-EAP-"]``, so index [3]
        raised an IndexError that propagated uncaught from inside the
        ``except ValueError`` handler.
        """
        d = _make_diameter(EAP_REQUEST)
        assert d._extract_diameter_length() == 612

    def test_message_length_line_plain(self):
        """'Message Length: 128' fallback path."""
        d = _make_diameter(MESSAGE_LENGTH_LINE)
        assert d._extract_diameter_length() == 128

    def test_message_length_line_hex(self):
        """'Message Length: 128(0x80)' parenthesised-hex fallback path."""
        d = _make_diameter(MESSAGE_LENGTH_HEX)
        assert d._extract_diameter_length() == 128

    def test_no_length_returns_none(self):
        """Returns ``None`` when no length can be found."""
        d = _make_diameter(NO_LENGTH)
        assert d._extract_diameter_length() is None


class TestDiameterL3L4Data:
    """Integration-style tests for ``Diameter._get_l3_l4_data``."""

    def test_eap_request_addresses(self):
        """IP addresses and ports are parsed correctly for EAP-Request."""
        d = _make_diameter(EAP_REQUEST)
        ip_src, ip_dst, sport, dport, _ = d._get_l3_l4_data()
        assert ip_src == "10.0.0.1"
        assert ip_dst == "10.0.0.2"
        assert sport == 3868
        assert dport == 3868

    def test_eap_request_length(self):
        """Length is 612 for the EAP-Request sample."""
        d = _make_diameter(EAP_REQUEST)
        _, _, _, _, length = d._get_l3_l4_data()
        assert length == 612

    def test_no_length_raises_ie_not_found(self):
        """``IENotFound`` is raised — not a bare ``IndexError`` — when the
        length cannot be determined."""
        d = _make_diameter(NO_LENGTH)
        with pytest.raises(IENotFound, match="length"):
            d._get_l3_l4_data()


class TestHexdumpExtraction:
    """Regression tests for ``Packet._get_hexdump``."""

    def test_0x_prefix_full_line_bytes_correct(self):
        """All 16 bytes of a full ``0xNNNN`` hexdump row are captured."""
        d = _make_diameter(HEXDUMP_0X_PREFIX_20B)
        result = d._get_hexdump(20)
        assert result == _HEXDUMP_0X_PREFIX_20B_EXPECTED

    def test_0x_prefix_length_correct(self):
        """Extracted hex string has exactly ``pkt_len * 2`` characters."""
        d = _make_diameter(HEXDUMP_0X_PREFIX_20B)
        result = d._get_hexdump(20)
        assert len(result) == 20 * 2

    def test_0x_prefix_sanity_check_passes(self):
        """``_hexdump_sanity_check`` does not raise after the fix."""
        d = _make_diameter(HEXDUMP_0X_PREFIX_20B)
        result = d._get_hexdump(20)
        d._hexdump_sanity_check(result, 20)  # must not raise

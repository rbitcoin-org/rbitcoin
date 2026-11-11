"""Core `TryParseHex` for the test shims. Not the node.

The node never derives a datadir. This pin is Bitcoin Core v32.1, whose
harness reads `<datadir>/signet` for every signet, including a custom
`-signetchallenge`. A later Core uses `signet_<message start>`.
"""

from __future__ import annotations

# Core `IsSpace`.
_SPACE = " \f\n\r\t\v"
_HEX = "0123456789abcdefABCDEF"


def parse_hex(raw: str) -> bytes | None:
    """Core `TryParseHex`: whitespace between bytes is skipped. Empty is valid."""
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] in _SPACE:
            i += 1
            continue
        pair = raw[i : i + 2]
        if len(pair) != 2 or pair[0] not in _HEX or pair[1] not in _HEX:
            return None
        out.append(int(pair, 16))
        i += 2
    return bytes(out)

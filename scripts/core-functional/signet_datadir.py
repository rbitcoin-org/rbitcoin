"""Core's per-network datadir name for the test shims. Not the node.

The node never derives a datadir. Core puts a custom signet under
`signet_<message start hex>` (`GetSignetDataDir`), so the shims map
`-datadir=DIR` the same way before handing the node `--datadir`.
"""

from __future__ import annotations

import hashlib
import re

SIGNET_DEFAULT_CHALLENGE = (
    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be43021"
    "0359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"
)


def is_hex(raw: str) -> bool:
    """Core `TryParseHex`: even-length hex. Empty is an empty script."""
    return len(raw) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]*", raw) is not None


def message_start(challenge_hex: str) -> str:
    """BIP325 magic: sha256d of the CompactSize-prefixed challenge, first 4 bytes."""
    raw = bytes.fromhex(challenge_hex)
    if len(raw) >= 0xFD:
        raise ValueError("signet challenge longer than 252 bytes")
    digest = hashlib.sha256(hashlib.sha256(bytes([len(raw)]) + raw).digest()).digest()
    return digest[:4].hex()


def chain_dir(network: str, challenge: str | None) -> str:
    """`regtest`, `signet`, or `signet_<magic>` for a custom challenge."""
    if network != "signet" or challenge is None or not is_hex(challenge):
        return network
    if challenge.lower() == SIGNET_DEFAULT_CHALLENGE:
        return network
    return f"signet_{message_start(challenge)}"

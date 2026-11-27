#!/usr/bin/env python3
"""PROBE v4 ONLY. Give every review-class probe entry a reason, or fail."""
import re, sys
SAFE = {"CREATE", "ARMED", "CLASS_A", "ONE_SECTOR", "LEN_CREATE", "LEN_ARMED",
        "LEN_CLASS_A", "LEN_AFTER_SYNC", "FIXTURE"}
# (class regex, file regex, frames regex, reason)
RULES = [
    (r"MULTI_SECTOR", r"tx\.head/", r"AddressHead::write_snapshot",
     "fresh shutdown snapshot: data synced before the footer generation (one sector)"),
    (r".*", r"scripthash", r"scripthash_materialize::|pack_shard_session|ScriptHashBulkSession",
     "cold scripthash build behind scripthash.dirty: a crash rebuilds"),
    (r"MULTI_SECTOR", r"scripthash\.ovf/ingest|shhead", r"ScriptHashHead|SlotPageCache|unlink_write_home|scripthash_head::",
     "scripthash ingest head: synced ingest.ahead image"),
    (r"MULTI_SECTOR", r"scripthash", r"unlink::restore_page|unlink::arm_undo|recover_unlink_undos",
     "legacy unlink undo replay at open, or its test hook"),
    (r".*", r".*", r"testutil::tear_|flush_observing|test_tear_",
     "test hook"),
    (r".*", r".*", r"^PROBE \S+ \S+ test-body:",
     "a test body writes the file directly"),
]
lines = open(sys.argv[1], errors="replace").read().split("\n")
lines = [re.sub(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ", "", l) for l in lines]
ents, cur = [], None
for l in lines:
    if l.startswith("PROBE "):
        cur = [l]; ents.append(cur)
    elif cur is not None and l.startswith("    "):
        cur.append(l.strip())
    else:
        cur = None
counts, reasons, bad = {}, {}, []
for e in ents:
    h = e[0].split()
    cls, f = h[1], h[2]
    counts[cls] = counts.get(cls, 0) + 1
    if cls in SAFE:
        continue
    frames = " ".join(e[0:1] + e[1:])
    for rc, rf, rr, why in RULES:
        if re.fullmatch(rc, cls) and re.search(rf, f) and re.search(rr, frames):
            reasons[why] = reasons.get(why, 0) + 1
            break
    else:
        bad.append(e)
for c in sorted(counts):
    print(f"class {c}: {counts[c]}")
for why, n in sorted(reasons.items(), key=lambda x: -x[1]):
    print(f"classified [{n}] {why}")
print(f"UNCLASSIFIED: {len(bad)}")
for e in bad:
    print("\n".join(e[:6]))
sys.exit(1 if bad else 0)

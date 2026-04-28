#!/usr/bin/env python3
"""AArch64 page table visualizer.

Reads a physical memory hex dump and walks the translation table hierarchy
starting from a given TTBR base address.

Supported hex dump formats:
  xxd:         00000000: dead beef cafe babe  ....
  hexdump -C:  00000000  de ad be ef  |....|
  simple:      0x00000000: deadbeefcafebabe...
"""

import sys
import re
import struct
import argparse
from typing import Optional

# ── ANSI colors ───────────────────────────────────────────────────────────────

NO_COLOR = False

def c(text: str, *codes: str) -> str:
    if NO_COLOR:
        return text
    return "".join(codes) + text + "\033[0m"

B  = "\033[1m"    # bold
DIM= "\033[2m"
R  = "\033[31m"   # red
G  = "\033[32m"   # green
Y  = "\033[33m"   # yellow
BL = "\033[34m"   # blue
M  = "\033[35m"   # magenta
CY = "\033[36m"   # cyan
GR = "\033[90m"   # gray


# ── Memory map ────────────────────────────────────────────────────────────────

class Memory:
    """Sparse physical memory map built from a hex dump."""

    def __init__(self):
        self._segs: list[tuple[int, bytearray]] = []

    def add(self, addr: int, data: bytes) -> None:
        if self._segs:
            last_addr, last_data = self._segs[-1]
            if last_addr + len(last_data) == addr:
                last_data.extend(data)
                return
        self._segs.append((addr, bytearray(data)))

    def read64_le(self, addr: int) -> Optional[int]:
        raw = self._read_bytes(addr, 8)
        return None if raw is None else struct.unpack_from("<Q", raw)[0]

    def _read_bytes(self, addr: int, size: int) -> Optional[bytes]:
        result = bytearray()
        remaining = size
        cur = addr
        for seg_base, seg_data in self._segs:
            seg_end = seg_base + len(seg_data)
            if cur >= seg_end or seg_base > cur + remaining:
                continue
            if cur < seg_base:
                break
            off = cur - seg_base
            take = min(len(seg_data) - off, remaining)
            result.extend(seg_data[off:off + take])
            remaining -= take
            cur += take
            if remaining == 0:
                return bytes(result)
        return None if remaining > 0 else bytes(result)

    @property
    def total_bytes(self) -> int:
        return sum(len(d) for _, d in self._segs)

    @property
    def num_segments(self) -> int:
        return len(self._segs)


# ── Hex dump parser ───────────────────────────────────────────────────────────

# xxd:         00000000: dead beef cafe babe  ....
_XXD   = re.compile(r'^([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2,4}\s*)+)')
# hexdump -C:  00000000  de ad be ef  |....|
_HEXC  = re.compile(r'^([0-9a-fA-F]+)\s{2,}((?:[0-9a-fA-F]{2}\s+)+)')
# simple:      0xADDR: hexdata
_PLAIN = re.compile(r'^(?:0x)?([0-9a-fA-F]+)[:\s]\s*([0-9a-fA-F\s]+)')


def parse_hex_dump(path: str, addr_offset: int = 0) -> Memory:
    mem = Memory()
    with open(path) as f:
        for raw in f:
            line = raw.rstrip()
            if not line or line.startswith('#'):
                continue
            m = _XXD.match(line) or _HEXC.match(line) or _PLAIN.match(line)
            if not m:
                continue
            try:
                addr = int(m.group(1), 16) + addr_offset
                hs = m.group(2).replace(' ', '').strip()
                if len(hs) % 2:
                    hs = hs[:-1]
                data = bytes.fromhex(hs)
                if data:
                    mem.add(addr, data)
            except (ValueError, struct.error):
                pass
    return mem


# ── AArch64 descriptor parsing ────────────────────────────────────────────────

_AP  = {0: "RW/--", 1: "RW/RW", 2: "RO/--", 3: "RO/RO"}
_SH  = {0: "NSH",   1: "?SH",   2: "OSH",   3: "ISH"}


class Desc:
    """Parsed AArch64 translation table descriptor."""

    __slots__ = ("raw", "kind", "oa",
                 "af", "sh", "ap", "attrindx", "ng",
                 "pxn", "uxn", "contig", "dbm",
                 # table-only upper attributes
                 "ns_table", "pxn_table", "uxn_table", "ap_table")

    def __init__(self, raw: int, level: int, block_shift: int, gran_shift: int):
        self.raw = raw
        phys_mask = (1 << 48) - 1

        if not (raw & 1):
            self.kind = "invalid"
            self.oa = 0
            self._zero_attrs()
            return

        type_bit = bool(raw & 2)

        if level == 3:
            self.kind = "page" if type_bit else "invalid"
            oa_mask = phys_mask & ~((1 << gran_shift) - 1)
        elif type_bit:
            self.kind = "table"
            oa_mask = phys_mask & ~((1 << gran_shift) - 1)
        else:
            self.kind = "block"
            oa_mask = phys_mask & ~((1 << block_shift) - 1)

        self.oa       = raw & oa_mask
        self.af       = bool(raw & (1 << 10))
        self.sh       = (raw >> 8) & 3
        self.ap       = (raw >> 6) & 3
        self.attrindx = (raw >> 2) & 7
        self.ng       = bool(raw & (1 << 11))
        self.pxn      = bool(raw & (1 << 53))
        self.uxn      = bool(raw & (1 << 54))
        self.contig   = bool(raw & (1 << 52))
        self.dbm      = bool(raw & (1 << 51))

        # Table upper-attribute override bits (only meaningful for table descs)
        self.ns_table  = bool(raw & (1 << 63))
        self.pxn_table = bool(raw & (1 << 59))
        self.uxn_table = bool(raw & (1 << 60))
        self.ap_table  = (raw >> 61) & 3

    def _zero_attrs(self):
        for f in ("af","sh","ap","attrindx","ng","pxn","uxn","contig","dbm",
                  "ns_table","pxn_table","uxn_table","ap_table"):
            setattr(self, f, 0 if f in ("sh","ap","attrindx","ap_table") else False)

    def attr_str(self) -> str:
        parts = [_AP.get(self.ap, f"AP={self.ap}"),
                 _SH.get(self.sh, f"SH={self.sh}"),
                 f"MAIR[{self.attrindx}]"]
        if not self.af:  parts.append("!AF")
        if self.pxn:     parts.append("PXN")
        if self.uxn:     parts.append("UXN")
        if self.ng:      parts.append("nG")
        if self.contig:  parts.append("Cont")
        if self.dbm:     parts.append("DBM")
        return " ".join(parts)

    def table_override_str(self) -> str:
        parts = []
        if self.ns_table:  parts.append("NSTable")
        if self.pxn_table: parts.append("PXNTable")
        if self.uxn_table: parts.append("UXNTable")
        if self.ap_table:  parts.append(f"APTable={self.ap_table}")
        return " ".join(parts)


# ── Page table configuration ──────────────────────────────────────────────────

GRANULE_SHIFTS = {4096: 12, 16384: 14, 65536: 16}
GRANULE_NAMES  = {4096: "4KB", 16384: "16KB", 65536: "64KB"}


def _start_level(va_bits: int, gran_shift: int) -> int:
    """Root translation level per ARM DDI0487."""
    idx_bits = gran_shift - 3
    addr_bits = va_bits - gran_shift
    num_levels = (addr_bits + idx_bits - 1) // idx_bits
    return 4 - num_levels


def _level_shift(level: int, gran_shift: int) -> int:
    return gran_shift + (3 - level) * (gran_shift - 3)


def _table_entries(level: int, va_bits: int, gran_shift: int, start_level: int) -> int:
    if level == start_level:
        # Root table may be smaller than a full page
        idx_bits = gran_shift - 3
        covered = gran_shift + (3 - level) * idx_bits
        remaining = va_bits - covered
        return 1 << remaining
    return 1 << (gran_shift - 3)


# ── Walker ────────────────────────────────────────────────────────────────────

class Walker:
    def __init__(self, mem: Memory, ttbr: int, granule: int = 4096,
                 va_bits: int = 48, el: int = 1, max_depth: int = 99,
                 show_invalid: bool = False):
        self.mem         = mem
        self.ttbr        = ttbr
        self.granule     = granule
        self.gs          = GRANULE_SHIFTS[granule]
        self.va_bits     = va_bits
        self.el          = el
        self.max_depth   = max_depth
        self.show_invalid= show_invalid
        self.start_level = _start_level(va_bits, self.gs)
        self.stats       = dict(tables=0, blocks=0, pages=0,
                                invalid=0, missing_table=0)

    # ── public ────────────────────────────────────────────────────────────────

    def walk(self) -> None:
        self._header()
        self._walk(self.ttbr, self.start_level, 0, "")

    def print_stats(self) -> None:
        s = self.stats
        print()
        print(c("── Summary ──────────────────────────────────────────────────────────", B))
        print(f"  Tables  : {s['tables']}")
        print(f"  Blocks  : {s['blocks']}")
        print(f"  Pages   : {s['pages']}")
        print(f"  Invalid : {s['invalid']}")
        if s['missing_table']:
            print(c(f"  Tables with missing data in dump: {s['missing_table']}", Y))

    # ── private ───────────────────────────────────────────────────────────────

    def _header(self) -> None:
        gran_name = GRANULE_NAMES[self.granule]
        print(c("┌─ AArch64 Page Table Visualizer ────────────────────────────────────┐", B+CY))
        print(c("│  TTBR  : ", B) + c(f"0x{self.ttbr:016x}", B+Y))
        print(c("│  Config: ", B) +
              f"Granule={gran_name}  VA={self.va_bits}-bit  "
              f"EL{self.el}  Start=L{self.start_level}")
        print(c("└────────────────────────────────────────────────────────────────────┘", B+CY))
        print()

    def _walk(self, table_pa: int, level: int, va_base: int,
              indent: str) -> None:
        if level - self.start_level >= self.max_depth:
            return

        self.stats["tables"] += 1
        lshift      = _level_shift(level, self.gs)
        block_shift = lshift
        n           = _table_entries(level, self.va_bits, self.gs, self.start_level)

        # Collect entries to allow proper ├──/└── drawing
        rows: list[tuple[int, Desc, int]] = []  # (idx, desc, va_start)
        for idx in range(n):
            raw = self.mem.read64_le(table_pa + idx * 8)
            # None means PA not in dump; treat as zero (= invalid) for sparse dumps
            val = raw if raw is not None else 0
            desc = Desc(val, level, block_shift, self.gs)
            va_start = va_base | (idx << lshift)
            if desc.kind == "invalid":
                self.stats["invalid"] += 1
            rows.append((idx, desc, va_start))

        display = rows if self.show_invalid else [(i, d, v) for i, d, v in rows if d.kind != "invalid"]

        for pos, (idx, desc, va_start) in enumerate(display):
            is_last  = pos == len(display) - 1
            branch   = "└── " if is_last else "├── "
            child_px = "    " if is_last else "│   "
            va_end   = va_start + (1 << lshift) - 1

            line = self._fmt(level, idx, va_start, va_end, desc)
            print(indent + branch + line)

            if desc.kind == "table":
                if self.mem.read64_le(desc.oa) is None:
                    self.stats["missing_table"] += 1
                    print(indent + child_px +
                          c(f"    <table PA 0x{desc.oa:x} not in dump>", R))
                else:
                    self._walk(desc.oa, level + 1, va_start, indent + child_px)

    def _fmt(self, level: int, idx: int, va0: int, va1: int, desc: Desc) -> str:
        lbl  = c(f"L{level}", B+CY) + c(f"[{idx:3d}]", CY)
        va   = c(f"  VA[{va0:#018x}–{va1:#018x}]", "\033[37m")  # white

        if desc.kind == "invalid":
            return lbl + va + c("  invalid", DIM+GR)

        pa = c(f"  →  PA {desc.oa:#018x}", Y)

        if desc.kind == "table":
            kind = c("TABLE", B+BL)
            extra = desc.table_override_str()
            tail = (c(f"  [{extra}]", GR) if extra else "")
            return lbl + va + f"  {kind}" + pa + tail

        if desc.kind == "block":
            self.stats["blocks"] += 1
            kind = c("BLOCK", B+M)
        else:
            self.stats["pages"] += 1
            kind = c("PAGE ", B+G)

        return lbl + va + f"  {kind}" + pa + c(f"  [{desc.attr_str()}]", GR)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    global NO_COLOR

    ap = argparse.ArgumentParser(
        description="AArch64 page table visualizer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s dump.xxd 0x1000
  %(prog)s dump.xxd 0x400000 --granule 64K --va-bits 39 --el 2
  %(prog)s dump.xxd 0x1000 --show-invalid --no-color > out.txt
  %(prog)s dump.xxd 0x1000 --addr-offset 0x80000000

Hex dump formats accepted:
  xxd -a        00000000: dead beef cafe babe  ....
  hexdump -C    00000000  de ad be ef  |....|
  simple        0x400000: deadbeefcafebabe
""")
    ap.add_argument("dump",  help="Hex dump file (physical memory)")
    ap.add_argument("ttbr",  help="Translation table base address (hex)")
    ap.add_argument("--granule",  default="4K",
                    help="Granule size: 4K, 16K, or 64K (default: 4K)")
    ap.add_argument("--va-bits",  type=int, default=48,
                    help="Virtual address size in bits (default: 48)")
    ap.add_argument("--el", type=int, default=1, choices=[1, 2, 3],
                    help="Exception level for annotation (default: 1)")
    ap.add_argument("--addr-offset", default="0",
                    help="Add this hex offset to all dump addresses (default: 0)")
    ap.add_argument("--max-depth", type=int, default=99,
                    help="Max levels to walk from root (default: unlimited)")
    ap.add_argument("--show-invalid", action="store_true",
                    help="Print invalid/empty entries")
    ap.add_argument("--no-color",  action="store_true",
                    help="Disable ANSI color (auto-disabled when not a tty)")
    ap.add_argument("--no-stats",  action="store_true",
                    help="Suppress summary statistics")

    args = ap.parse_args()
    NO_COLOR = args.no_color or not sys.stdout.isatty()

    gran_map = {"4k":4096,"4096":4096,"16k":16384,"16384":16384,
                "64k":65536,"65536":65536}
    gran_key = args.granule.lower().replace(" ","")
    if gran_key not in gran_map:
        ap.error(f"Unknown granule '{args.granule}'. Use 4K, 16K, or 64K.")
    granule = gran_map[gran_key]

    try:
        ttbr = int(args.ttbr, 16)
    except ValueError:
        ap.error(f"Invalid TTBR '{args.ttbr}' — expected hex (e.g. 0x400000)")

    try:
        addr_offset = int(args.addr_offset, 16)
    except ValueError:
        ap.error(f"Invalid --addr-offset '{args.addr_offset}'")

    gs = GRANULE_SHIFTS[granule]
    if not (gs + 1 <= args.va_bits <= 52):
        ap.error(f"--va-bits must be {gs+1}–52 for {GRANULE_NAMES[granule]} granule")

    try:
        mem = parse_hex_dump(args.dump, addr_offset)
    except FileNotFoundError:
        ap.error(f"File not found: {args.dump}")

    if mem.total_bytes == 0:
        print(c("Warning: no data parsed — check the hex dump format.", Y), file=sys.stderr)
    else:
        print(c(f"Loaded {mem.total_bytes:,} bytes in {mem.num_segments} segment(s)"
                f" from '{args.dump}'", GR), file=sys.stderr)

    walker = Walker(
        mem=mem, ttbr=ttbr, granule=granule,
        va_bits=args.va_bits, el=args.el,
        max_depth=args.max_depth,
        show_invalid=args.show_invalid,
    )
    walker.walk()
    if not args.no_stats:
        walker.print_stats()


if __name__ == "__main__":
    main()

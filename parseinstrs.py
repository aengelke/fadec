#!/usr/bin/python3

import argparse
from collections import OrderedDict, defaultdict, namedtuple, Counter
from enum import Enum
from itertools import product
import re
import struct
from typing import NamedTuple, FrozenSet, List, Tuple, Union, Optional, ByteString

INSTR_FLAGS_FIELDS, INSTR_FLAGS_SIZES = zip(*[
    ("modrm_idx", 2),
    ("modreg_idx", 2),
    ("vexreg_idx", 2),
    ("zeroreg_idx", 2),
    ("imm_idx", 2),
    ("zeroreg_val", 1),
    ("lock", 1),
    ("imm_control", 3),
    ("vsib", 1),
    ("op0_size", 2),
    ("op1_size", 2),
    ("op2_size", 2),
    ("op3_size", 2),
    ("opsize", 2),
    ("size_fix1", 3),
    ("size_fix2", 2),
    ("instr_width", 1),
    ("op0_regty", 3),
    ("op1_regty", 3),
    ("op2_regty", 3),
    ("unused", 5),
    ("modrm", 1),
    ("ign66", 1),
][::-1])
class InstrFlags(namedtuple("InstrFlags", INSTR_FLAGS_FIELDS)):
    def __new__(cls, **kwargs):
        init = {**{f: 0 for f in cls._fields}, **kwargs}
        return super(InstrFlags, cls).__new__(cls, **init)
    def _encode(self):
        enc = 0
        for value, size in zip(self, INSTR_FLAGS_SIZES):
            enc = enc << size | (value & ((1 << size) - 1))
        return enc

ENCODINGS = {
    "NP": InstrFlags(),
    "M": InstrFlags(modrm=1, modrm_idx=0^3),
    "M1": InstrFlags(modrm=1, modrm_idx=0^3, imm_idx=1^3, imm_control=1),
    "MI": InstrFlags(modrm=1, modrm_idx=0^3, imm_idx=1^3, imm_control=4),
    "MC": InstrFlags(modrm=1, modrm_idx=0^3, zeroreg_idx=1^3, zeroreg_val=1),
    "MR": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=1^3),
    "RM": InstrFlags(modrm=1, modrm_idx=1^3, modreg_idx=0^3),
    "RMA": InstrFlags(modrm=1, modrm_idx=1^3, modreg_idx=0^3, zeroreg_idx=2^3),
    "MRI": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=1^3, imm_idx=2^3, imm_control=4),
    "RMI": InstrFlags(modrm=1, modrm_idx=1^3, modreg_idx=0^3, imm_idx=2^3, imm_control=4),
    "MRC": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=1^3, zeroreg_idx=2^3, zeroreg_val=1),
    "AM": InstrFlags(modrm=1, modrm_idx=1^3, zeroreg_idx=0^3),
    "MA": InstrFlags(modrm=1, modrm_idx=0^3, zeroreg_idx=1^3),
    "I": InstrFlags(imm_idx=0^3, imm_control=4),
    "IA": InstrFlags(zeroreg_idx=0^3, imm_idx=1^3, imm_control=4),
    "O": InstrFlags(modrm_idx=0^3),
    "OI": InstrFlags(modrm_idx=0^3, imm_idx=1^3, imm_control=4),
    "OA": InstrFlags(modrm_idx=0^3, zeroreg_idx=1^3),
    "S": InstrFlags(modreg_idx=0^3), # segment register in bits 3,4,5
    "A": InstrFlags(zeroreg_idx=0^3),
    "D": InstrFlags(imm_idx=0^3, imm_control=6),
    "FD": InstrFlags(zeroreg_idx=0^3, imm_idx=1^3, imm_control=2),
    "TD": InstrFlags(zeroreg_idx=1^3, imm_idx=0^3, imm_control=2),

    "RVM": InstrFlags(modrm=1, modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3),
    "RVMI": InstrFlags(modrm=1, modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3, imm_idx=3^3, imm_control=4),
    "RVMR": InstrFlags(modrm=1, modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3, imm_idx=3^3, imm_control=3),
    "RMV": InstrFlags(modrm=1, modrm_idx=1^3, modreg_idx=0^3, vexreg_idx=2^3),
    "VM": InstrFlags(modrm=1, modrm_idx=1^3, vexreg_idx=0^3),
    "VMI": InstrFlags(modrm=1, modrm_idx=1^3, vexreg_idx=0^3, imm_idx=2^3, imm_control=4),
    "MVR": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=2^3, vexreg_idx=1^3),
}

OPKIND_REGEX = re.compile(r"^([A-Z]+)([0-9]+)?$")
OPKIND_DEFAULTS = {"GP": -1, "IMM": -1, "SEG": -1, "MEM": -1, "XMM": -2, "MMX": 8, "FPU": 10}
OPKIND_KINDS = ("IMM", "MEM", "GP", "MMX", "XMM", "SEG", "FPU", "MEM", "MASK", "CR", "DR", "TMM", "BND")
class OpKind(NamedTuple):
    size: int
    kind: str

    SZ_OP = -1
    SZ_VEC = -2

    def abssize(self, opsz=None, vecsz=None):
        res = opsz if self.size == self.SZ_OP else \
              vecsz if self.size == self.SZ_VEC else self.size
        if res is None:
            raise Exception("unspecified operand size")
        return res
    @classmethod
    def parse(cls, op):
        op = {"MEMZ": "MEM0", "MEMV": "XMM"}.get(op, op)
        match = OPKIND_REGEX.match(op)
        if not match:
            raise Exception(f"invalid opkind str: {op}")
        kind, size = match.groups()
        size = int(size) // 8 if size else OPKIND_DEFAULTS.get(kind, 0)
        if kind not in OPKIND_KINDS:
            raise Exception(f"invalid opkind kind: {op}")
        return cls(size, kind)

class InstrDesc(NamedTuple):
    mnemonic: str
    encoding: str
    operands: Tuple[str, ...]
    flags: FrozenSet[str]

    OPKIND_REGTYS = {"GP": 0, "FPU": 1, "XMM": 2, "MASK": 3, "MMX": 4, "BND": 5,
                     "SEG": 6}
    OPKIND_REGTYS_ENC = {"SEG": 3, "FPU": 4, "MMX": 5, "XMM": 6, "BND": 8,
                         "CR": 9, "DR": 10}
    OPKIND_SIZES = {
        0: 0, 1: 1, 2: 2, 4: 3, 8: 4, 16: 5, 32: 6, 64: 7, 10: 0,
        OpKind.SZ_OP: -2, OpKind.SZ_VEC: -3,
    }

    @classmethod
    def parse(cls, desc):
        desc = desc.split()
        operands = tuple(OpKind.parse(op) for op in desc[1:5] if op != "-")
        return cls(desc[5], desc[0], operands, frozenset(desc[6:]))

    def imm_size(self, opsz):
        flags = ENCODINGS[self.encoding]
        if flags.imm_control < 4:
            return 0
        if self.mnemonic == "ENTER":
            return 3
        if "IMM_8" in self.flags:
            return 1
        max_imm_size = 4 if self.mnemonic != "MOVABS" else 8
        return min(max_imm_size, self.operands[flags.imm_idx^3].abssize(opsz))

    def optype_str(self):
        optypes = ["", "", "", ""]
        flags = ENCODINGS[self.encoding]
        if flags.modrm_idx:   optypes[flags.modrm_idx^3] = "M"
        if flags.modreg_idx:  optypes[flags.modreg_idx^3] = "r"
        if flags.vexreg_idx:  optypes[flags.vexreg_idx^3] = "r"
        if flags.zeroreg_idx: optypes[flags.zeroreg_idx^3] = "r"
        if flags.imm_control: optypes[flags.imm_idx^3] = " iariioo"[flags.imm_control]
        return "".join(optypes)

    def encode_regtys(self, ots, opsz):
        tys = []
        for ot, op in zip(ots, self.operands):
            if ot == "m":
                tys.append(0xf)
            elif ot in "io":
                tys.append(0)
            elif op.kind == "GP":
                if (self.mnemonic == "MOVSX" or self.mnemonic == "MOVZX" or
                    opsz == 1):
                    tys.append(2 if op.abssize(opsz) == 1 else 1)
                else:
                    tys.append(1)
            else:
                tys.append(self.OPKIND_REGTYS_ENC[op.kind])
        return sum(ty << (4*i) for i, ty in enumerate(tys))

    def encode(self, ign66, modrm):
        flags = ENCODINGS[self.encoding]
        extraflags = {}

        opsz = set(self.OPKIND_SIZES[opkind.size] for opkind in self.operands)

        # Sort fixed sizes encodable in size_fix2 as second element.
        fixed = sorted((x for x in opsz if x >= 0), key=lambda x: 1 <= x <= 4)
        if len(fixed) > 2 or (len(fixed) == 2 and not (1 <= fixed[1] <= 4)):
            raise Exception("invalid fixed operand sizes: %r"%fixed)
        sizes = (fixed + [1, 1])[:2] + [-2, -3] # See operand_sizes in decode.c.
        extraflags["size_fix1"] = sizes[0]
        extraflags["size_fix2"] = sizes[1] - 1

        for i, opkind in enumerate(self.operands):
            sz = self.OPKIND_SIZES[opkind.size]
            reg_type = self.OPKIND_REGTYS.get(opkind.kind, 7)
            extraflags["op%d_size"%i] = sizes.index(sz)
            if i < 3:
                extraflags["op%d_regty"%i] = reg_type
            elif reg_type not in (7, 2):
                raise Exception("invalid regty for op 3, must be VEC")

        # Miscellaneous Flags
        if "SIZE_8" in self.flags:      extraflags["opsize"] = 1
        if "DEF64" in self.flags:       extraflags["opsize"] = 2
        if "FORCE64" in self.flags:     extraflags["opsize"] = 3
        if "INSTR_WIDTH" in self.flags: extraflags["instr_width"] = 1
        if "LOCK" in self.flags:        extraflags["lock"] = 1
        if "VSIB" in self.flags:        extraflags["vsib"] = 1
        if modrm:                       extraflags["modrm"] = 1

        if "USE66" not in self.flags and (ign66 or "IGN66" in self.flags):
            extraflags["ign66"] = 1

        if self.imm_size(1 if "SIZE_8" in self.flags else 8) == 1:
            extraflags["imm_control"] = flags.imm_control | 1

        enc = flags._replace(**extraflags)._encode()
        enc = tuple((enc >> i) & 0xffff for i in range(0, 48, 16))
        # First 2 bytes are the mnemonic, last 6 bytes are the encoding.
        return ("FDI_"+self.mnemonic,) + enc

class EntryKind(Enum):
    NONE = 0
    INSTR = 1
    WEAKINSTR = 9
    TABLE256 = 2
    TABLE16 = 3
    TABLE8E = 4
    TABLE_PREFIX = 5
    TABLE_VEX = 6
    TABLE_ROOT = -1
    @property
    def is_instr(self):
        return self == EntryKind.INSTR or self == EntryKind.WEAKINSTR

opcode_regex = re.compile(
    r"^(?:(?P<prefixes>(?P<vex>VEX\.)?(?P<legacy>NP|66|F2|F3|NFx)\." +
                     r"(?:W(?P<rexw>[01]|IG)\.)?(?:L(?P<vexl>[01]|IG)\.)?))?" +
     r"(?P<escape>0f38|0f3a|0f|)" +
     r"(?P<opcode>[0-9a-f]{2})" +
     r"(?:(?P<extended>\+)|/(?P<modreg>[0-7]|[rm]|[0-7][rm])|(?P<opcext>[c-f][0-9a-f]))?$")

class Opcode(NamedTuple):
    prefix: Union[None, str] # None/NP/66/F2/F3/NFx
    escape: int # [0, 0f, 0f38, 0f3a]
    opc: int
    extended: bool # Extend opc or opcext, if present
    modreg: Union[None, Tuple[Union[None, int], str]] # (modreg, "r"/"m"/"rm"), None
    opcext: Union[None, int] # 0xc0-0xff, or 0
    vex: bool
    vexl: Union[str, None] # 0, 1, IG, None = used, both
    rexw: Union[str, None] # 0, 1, IG, None = used, both

    @classmethod
    def parse(cls, opcode_string):
        match = opcode_regex.match(opcode_string)
        if match is None:
            raise Exception(opcode_string)
            return None

        modreg = match.group("modreg")
        if modreg:
            if modreg[0] in "rm":
                modreg = None, modreg[0]
            else:
                modreg = int(modreg[0]), modreg[1] if len(modreg) == 2 else "rm"

        return cls(
            prefix=match.group("legacy"),
            escape=["", "0f", "0f38", "0f3a"].index(match.group("escape")),
            opc=int(match.group("opcode"), 16),
            extended=match.group("extended") is not None,
            modreg=modreg,
            opcext=int(match.group("opcext") or "0", 16) or None,
            vex=match.group("vex") is not None,
            vexl=match.group("vexl"),
            rexw=match.group("rexw"),
        )

    def for_trie(self):
        opcode = []
        opcode.append((EntryKind.TABLE_ROOT, [self.escape | self.vex << 2]))
        if not self.extended:
            opcode.append((EntryKind.TABLE256, [self.opc]))
        else:
            opcode.append((EntryKind.TABLE256, [self.opc + i for i in range(8)]))
        if self.prefix:
            if self.prefix == "NFx":
                opcode.append((EntryKind.TABLE_PREFIX, [0, 1]))
            else:
                prefix_val = ["NP", "66", "F3", "F2"].index(self.prefix)
                opcode.append((EntryKind.TABLE_PREFIX, [prefix_val]))
        if self.opcext:
            opcode.append((EntryKind.TABLE16, [((self.opcext - 0xc0) >> 3) | 8]))
            opcode.append((EntryKind.TABLE8E, [self.opcext & 7]))
        if self.modreg:
            # TODO: optimize for /r and /m specifiers to reduce size
            mod = {"m": [0], "r": [1<<3], "rm": [0, 1<<3]}[self.modreg[1]]
            reg = [self.modreg[0]] if self.modreg[0] is not None else list(range(8))
            opcode.append((EntryKind.TABLE16, [x + y for x in mod for y in reg]))
        if self.vexl in ("0", "1") or self.rexw in ("0", "1"):
            rexw = {"0": [0], "1": [1<<0], "IG": [0, 1<<0]}[self.rexw or "IG"]
            vexl = {"0": [0], "1": [1<<1], "IG": [0, 1<<1]}[self.vexl or "IG"]
            entries = list(map(sum, product(rexw, vexl)))
            opcode.append((EntryKind.TABLE_VEX, entries))
        return opcode

class Trie:
    KIND_ORDER = (EntryKind.TABLE_ROOT, EntryKind.TABLE256,
                  EntryKind.TABLE_PREFIX, EntryKind.TABLE16,
                  EntryKind.TABLE8E, EntryKind.TABLE_VEX)
    TABLE_LENGTH = {
        EntryKind.TABLE_ROOT: 8,
        EntryKind.TABLE256: 256,
        EntryKind.TABLE_PREFIX: 4,
        EntryKind.TABLE16: 16,
        EntryKind.TABLE8E: 8,
        EntryKind.TABLE_VEX: 4,
    }

    def __init__(self, root_count):
        self.trie = []
        self.trie.append([None] * root_count)
        self.kindmap = defaultdict(list)

    def _add_table(self, kind):
        self.trie.append([None] * self.TABLE_LENGTH[kind])
        self.kindmap[kind].append(len(self.trie) - 1)
        return len(self.trie) - 1

    def _transform_opcode(self, opcode):
        vals = {k: v for k, v in opcode.for_trie()}
        return [vals.get(kind) for kind in self.KIND_ORDER]

    def _clone(self, elem):
        if not elem or elem[0].is_instr:
            return elem
        new_num = self._add_table(elem[0])
        self.trie[new_num] = [self._clone(e) for e in self.trie[elem[1]]]
        return elem[0], new_num

    def add_opcode(self, opcode, descidx, root_idx, weak=False):
        opcode = self._transform_opcode(opcode)
        frontier = [(0, root_idx)]
        for elem_kind, elem in zip(self.KIND_ORDER, opcode):
            new_frontier = []
            for entry_num, entry_idx in frontier:
                entry = self.trie[entry_num]
                if elem is None:
                    if entry[entry_idx] is None or entry[entry_idx][0] != elem_kind:
                        new_frontier.append((entry_num, entry_idx))
                        continue
                    elem = list(range(self.TABLE_LENGTH[elem_kind]))
                if entry[entry_idx] is None:
                    new_num = self._add_table(elem_kind)
                    entry[entry_idx] = elem_kind, new_num
                elif entry[entry_idx][0] != elem_kind:
                    # Need to add a new node here and copy entry one level below
                    new_num = self._add_table(elem_kind)
                    # Keep original entry, but clone others recursively
                    self.trie[new_num][0] = entry[entry_idx]
                    for i in range(1, len(self.trie[new_num])):
                        self.trie[new_num][i] = self._clone(entry[entry_idx])
                    entry[entry_idx] = elem_kind, new_num
                for elem_idx in elem:
                    new_frontier.append((entry[entry_idx][1], elem_idx))
            frontier = new_frontier
        for entry_num, entry_idx in frontier:
            entry = self.trie[entry_num]
            if not entry[entry_idx] or entry[entry_idx][0] == EntryKind.WEAKINSTR:
                kind = EntryKind.INSTR if not weak else EntryKind.WEAKINSTR
                entry[entry_idx] = kind, descidx
            elif not weak:
                raise Exception(f"redundant non-weak {opcode}")

    def deduplicate(self):
        synonyms = {}
        for kind in self.KIND_ORDER[::-1]:
            entries = {}
            for num in self.kindmap[kind]:
                # Replace previous synonyms
                entry = self.trie[num]
                for i, elem in enumerate(entry):
                    if elem and not elem[0].is_instr and elem[1] in synonyms:
                        entry[i] = elem[0], synonyms[elem[1]]

                # And deduplicate all entries of this kind
                unique_entry = tuple(entry)
                if unique_entry in entries:
                    synonyms[num] = entries[unique_entry]
                    self.trie[num] = None
                else:
                    entries[unique_entry] = num

    def compile(self):
        offsets = [None] * len(self.trie)
        last_off = 0
        for num, entry in enumerate(self.trie[1:], start=1):
            if not entry:
                continue
            offsets[num] = last_off
            last_off += (len(entry) + 3) & ~3
        if last_off >= 0x8000:
            raise Exception(f"maximum table size exceeded: {last_off:#x}")

        data = [0] * last_off
        for off, entry in zip(offsets, self.trie):
            if off is None:
                continue
            for i, elem in enumerate(entry, start=off):
                if elem is not None:
                    value = elem[1] << 2 if elem[0].is_instr else offsets[elem[1]]
                    data[i] = (value << 1) | (elem[0].value & 7)

        stats = {k: len(v) for k, v in self.kindmap.items()}
        print("%d bytes" % (2*len(data)), stats)
        return tuple(data), [offsets[v] for _, v in self.trie[0]]

def bytes_to_table(data, notes):
    strdata = tuple(d+"," if type(d) == str else "%#04x,"%d for d in data)
    offs = [0] + sorted(notes.keys()) + [len(data)]
    return "\n".join("".join(strdata[p:c]) + "\n//%04x "%c + notes.get(c, "")
                     for p, c in zip(offs, offs[1:]))

def parse_mnemonics(mnemonics):
    mktree = lambda: defaultdict(mktree)
    tree = mktree()
    for m in mnemonics:
        cur = tree
        for c in m[::-1]:
            cur = cur[c]
    def tree_walk(tree, cur="\0"):
        if not tree:
            yield cur
        else:
            for el, subtree in tree.items():
                for path in tree_walk(subtree, el + cur):
                    yield path
    merged_str = "".join(sorted(tree_walk(tree)))
    cstr = '"' + merged_str[:-1].replace("\0", '\\0') + '"'
    tab = [merged_str.index(m + "\0") for m in mnemonics]
    return cstr, ",".join(map(str, tab))

template = """// Auto-generated file -- do not modify!
#if defined(FD_DECODE_TABLE_DATA)
{hex_table}
#elif defined(FD_DECODE_TABLE_DESCS)
{descs}
#elif defined(FD_DECODE_TABLE_STRTAB1)
{mnemonics[0]}
#elif defined(FD_DECODE_TABLE_STRTAB2)
{mnemonics[1]}
#elif defined(FD_DECODE_TABLE_DEFINES)
{defines}
#else
#error "unspecified decode table"
#endif
"""

def encode_table(entries):
    mnemonics = defaultdict(list)
    mnemonics["FE_NOP"].append(("NP", 0, 0, "0x90"))
    for weak, opcode, desc in entries:
        if weak or "ONLY32" in desc.flags:
            continue

        opsizes = {8} if "SIZE_8" in desc.flags else {16, 32, 64}
        hasvex, vecsizes = False, {128}

        opc_i = opcode.opc
        if opcode.opcext:
            opc_i |= opcode.opcext << 8
        if opcode.modreg and opcode.modreg[0] is not None:
            opc_i |= opcode.modreg[0] << 8
        opc_flags = ""
        opc_flags += ["","|OPC_0F","|OPC_0F38","|OPC_0F3A"][opcode.escape]
        if "VSIB" in desc.flags:
            opc_flags += "|OPC_VSIB"
        if opcode.vex:
            hasvex, vecsizes = True, {128, 256}
            opc_flags += "|OPC_VEX"
        if opcode.prefix:
            if opcode.prefix in ("66", "F2", "F3"):
                opc_flags += "|OPC_" + opcode.prefix
            if "USE66" not in desc.flags and opcode.prefix != "NFx":
                opsizes -= {16}
        if opcode.vexl == "IG":
            vecsizes = {0}
        elif opcode.vexl:
            vecsizes -= {128 if opcode.vexl == "1" else 256}
            if opcode.vexl == "1": opc_flags += "|OPC_VEXL"
        if opcode.rexw == "IG":
            opsizes = {0}
        elif opcode.rexw:
            opsizes -= {32 if opcode.rexw == "1" else 64}
            if opcode.rexw == "1": opc_flags += "|OPC_REXW"

        if "DEF64" in desc.flags:
            opsizes -= {32}
        if "INSTR_WIDTH" not in desc.flags and all(op.size != OpKind.SZ_OP for op in desc.operands):
            opsizes = {0}
        if "VSIB" not in desc.flags and all(op.size != OpKind.SZ_VEC for op in desc.operands):
            vecsizes = {0} # for VEX-encoded general-purpose instructions.
        if "ENC_NOSZ" in desc.flags:
            opsizes, vecsizes = {0}, {0}

        # Where to put the operand size in the mnemonic
        separate_opsize = "ENC_SEPSZ" in desc.flags
        prepend_opsize = max(opsizes) > 0 and not separate_opsize
        prepend_vecsize = hasvex and max(vecsizes) > 0 and not separate_opsize

        if "FORCE64" in desc.flags:
            opsizes = {64}
            prepend_opsize = False

        modrm_type = opcode.modreg[1] if opcode.modreg else "rm"
        optypes_base = desc.optype_str()
        optypes = [optypes_base.replace("M", t) for t in modrm_type]

        prefixes = [("", "")]
        if "LOCK" in desc.flags:
            prefixes.append(("LOCK_", "|OPC_LOCK"))
        if "ENC_REP" in desc.flags:
            prefixes.append(("REP_", "|OPC_F3"))
        if "ENC_REPCC" in desc.flags:
            prefixes.append(("REPNZ_", "|OPC_F2"))
            prefixes.append(("REPZ_", "|OPC_F3"))

        for opsize, vecsize, prefix, ots in product(opsizes, vecsizes, prefixes, optypes):
            if prefix[1] == "|OPC_LOCK" and ots[0] != "m":
                continue

            imm_size = desc.imm_size(opsize//8)
            tys_i = desc.encode_regtys(ots, opsize//8)
            opc_s = hex(opc_i) + opc_flags + prefix[1]
            if opsize == 16: opc_s += "|OPC_66"
            if vecsize == 256: opc_s += "|OPC_VEXL"
            if opsize == 64 and "DEF64" not in desc.flags and "FORCE64" not in desc.flags: opc_s += "|OPC_REXW"

            # Construct mnemonic name
            mnem_name = {"MOVABS": "MOV", "XCHG_NOP": "XCHG"}.get(desc.mnemonic, desc.mnemonic)
            name = "FE_" + prefix[0] + mnem_name
            if prepend_opsize and not ("DEF64" in desc.flags and opsize == 64):
                name += f"_{opsize}"[name[-1] not in "0123456789":]
            if prepend_vecsize:
                name += f"_{vecsize}"[name[-1] not in "0123456789":]
            for ot, op in zip(ots, desc.operands):
                name += ot.replace("o", "")
                if separate_opsize:
                    name += f"{op.abssize(opsize//8, vecsize//8)*8}"
            mnemonics[name].append((desc.encoding, imm_size, tys_i, opc_s))

    descs = ""
    alt_index = 0
    for mnem, variants in mnemonics.items():
        dedup = []
        for variant in variants:
            # TODO: when adapting to 32-bit mode, handle S encodings.
            if not any(x[:3] == variant[:3] for x in dedup):
                dedup.append(variant)

        enc_prio = ["O", "OA", "OI", "IA", "M", "MI", "MR", "RM"]
        dedup.sort(key=lambda e: (e[1], e[0] in enc_prio and enc_prio.index(e[0])))

        indices = [mnem] + [f"FE_MNEM_MAX+{alt_index+i}" for i in range(len(dedup) - 1)]
        alt_list = indices[1:] + ["0"]
        alt_index += len(alt_list) - 1
        for idx, alt, (enc, immsz, tys_i, opc_s) in zip(indices, alt_list, dedup):
            descs += f"[{idx}] = {{ .enc = ENC_{enc}, .immsz = {immsz}, .tys = {tys_i:#x}, .opc = {opc_s}, .alt = {alt} }},\n"

    mnem_list = sorted(mnemonics.keys())
    mnem_tab = "".join(f"FE_MNEMONIC({m},{i})\n" for i, m in enumerate(mnem_list))
    return mnem_tab, descs

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--32", dest="modes", action="append_const", const=32)
    parser.add_argument("--64", dest="modes", action="append_const", const=64)
    parser.add_argument("--with-undoc", action="store_true")
    parser.add_argument("table", type=argparse.FileType('r'))
    parser.add_argument("decode_mnems", type=argparse.FileType('w'))
    parser.add_argument("decode_table", type=argparse.FileType('w'))
    parser.add_argument("encode_mnems", type=argparse.FileType('w'))
    parser.add_argument("encode_table", type=argparse.FileType('w'))
    args = parser.parse_args()

    entries = []
    for line in args.table.read().splitlines():
        if not line or line[0] == "#": continue
        line, weak = (line, False) if line[0] != "*" else (line[1:], True)
        opcode_string, desc_string = tuple(line.split(maxsplit=1))
        opcode, desc = Opcode.parse(opcode_string), InstrDesc.parse(desc_string)
        if "UNDOC" not in desc.flags or args.with_undoc:
            entries.append((weak, opcode, desc))

    mnemonics = sorted({desc.mnemonic for _, _, desc in entries})

    decode_mnems_lines = [f"FD_MNEMONIC({m},{i})\n" for i, m in enumerate(mnemonics)]
    args.decode_mnems.write("".join(decode_mnems_lines))

    trie = Trie(root_count=len(args.modes))
    descs, desc_map = [], {}
    for weak, opcode, desc in entries:
        ign66 = opcode.prefix in ("NP", "66", "F2", "F3")
        modrm = opcode.modreg or opcode.opcext
        descenc = desc.encode(ign66, modrm)
        desc_idx = desc_map.get(descenc)
        if desc_idx is None:
            desc_idx = desc_map[descenc] = len(descs)
            descs.append(descenc)
        for i, mode in enumerate(args.modes):
            if "ONLY%d"%(96-mode) not in desc.flags:
                trie.add_opcode(opcode, desc_idx, i, weak)

    trie.deduplicate()
    table_data, root_offsets = trie.compile()

    mnemonics_intel = [m.replace("SSE_", "").replace("MMX_", "")
                        .replace("MOVABS", "MOV").replace("RESERVED_", "")
                        .replace("JMPF", "JMP FAR").replace("CALLF", "CALL FAR")
                        .replace("_S2G", "").replace("_G2S", "")
                        .replace("_CR", "").replace("_DR", "")
                        .lower() for m in mnemonics]

    defines = ["FD_TABLE_OFFSET_%d %d"%k for k in zip(args.modes, root_offsets)]

    decode_table = template.format(
        hex_table=bytes_to_table(table_data, {}),
        descs="\n".join("{{{0},{1},{2},{3}}},".format(*desc) for desc in descs),
        mnemonics=parse_mnemonics(mnemonics_intel),
        defines="\n".join("#define " + line for line in defines),
    )
    args.decode_table.write(decode_table)

    fe_mnem_list, fe_code = encode_table(entries)
    args.encode_mnems.write(fe_mnem_list)
    args.encode_table.write(fe_code)

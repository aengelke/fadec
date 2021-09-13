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
    ("modrm_ty", 3),
    ("modreg_ty", 3),
    ("vexreg_ty", 2),
    ("zeroreg_ty", 2),
    ("unused", 4),
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
ENCODING_OPTYS = ["modrm", "modreg", "vexreg", "zeroreg", "imm"]
ENCODING_OPORDER = { enc: sorted(ENCODING_OPTYS, key=lambda ty: getattr(ENCODINGS[enc], ty+"_idx")^3) for enc in ENCODINGS}

OPKIND_CANONICALIZE = {
    "I": "IMM", # immediate
        "A": "IMM", # Direct address, far jmp
    "J": "IMM", # RIP-relative address
    "M": "MEM", # ModRM.r/m selects memory only
        "O": "MEM", # Direct address, FD/TD encoding
    "R": "GP", # ModRM.r/m selects GP
        "B": "GP", # VEX.vvvv selects GP
        "E": "GP", # ModRM.r/m selects GP or memory
        "G": "GP", # ModRM.reg selects GP
    "P": "MMX", # ModRM.reg selects MMX
        "N": "MMX", # ModRM.r/m selects MMX
        "Q": "MMX", # ModRM.r/m selects MMX or memory
    "V": "XMM", # ModRM.reg selects XMM
        "H": "XMM", # VEX.vvvv selects XMM
        "L": "XMM", # bits7:4 of imm8 select XMM
        "U": "XMM", # ModRM.r/m selects XMM
        "W": "XMM", # ModRM.r/m selects XMM or memory
    "S": "SEG", # ModRM.reg selects SEG
    "C": "CR", # ModRM.reg selects CR
    "D": "DR", # ModRM.reg selects DR

    # Custom names
    "F": "FPU", # F is used for RFLAGS by Intel
    "K": "MASK",
    "T": "TMM",
    "Z": "BND",
}
OPKIND_SIZES = {
    "b": 1,
    "w": 2,
    "d": 4,
    "ss": 4, # Scalar single of XMM
    "q": 8,
    "sd": 8, # Scalar double of XMM
    "t": 10, # FPU/ten-byte
    "dq": 16,
    "qq": 32,
    "oq": 64, # oct-quadword
    "": 0, # for MEMZ
    "v": -1,
    "y": -1, # actually, dword or qword
    "z": -1, # actually, op-size maxed at 4 (immediates)
    "a": -1, # actually, twice the size
    "p": -1, # actually, far pointer = SZ_OP + 2
    "x": -2,
    "pd": -2, # packed double
    "ps": -2, # packed single

    # Custom names
    "bs": -1, # sign-extended immediate
    "zd": 4, # z-immediate, but always 4-byte operand
    "zq": 8, # z-immediate, but always 8-byte operand
}
class OpKind(NamedTuple):
    kind: str
    sizestr: str
    size: int

    SZ_OP = -1
    SZ_VEC = -2

    def abssize(self, opsz=None, vecsz=None):
        res = opsz if self.size == self.SZ_OP else \
              vecsz if self.size == self.SZ_VEC else self.size
        if res is None:
            raise Exception("unspecified operand size")
        return res
    def immsize(self, opsz):
        maxsz = 1 if self.sizestr == "bs" else 4 if self.sizestr[0] == "z" else 8
        return min(maxsz, self.abssize(opsz))
    @classmethod
    def parse(cls, op):
        return cls(OPKIND_CANONICALIZE[op[0]], op[1:], OPKIND_SIZES[op[1:]])

class InstrDesc(NamedTuple):
    mnemonic: str
    encoding: str
    operands: Tuple[str, ...]
    flags: FrozenSet[str]

    OPKIND_REGTYS_MODRM = { "GP": 0, "XMM": 1, "MMX": 4, "FPU": 5, "MASK": 6,  }
    OPKIND_REGTYS_MODREG = { "GP": 0, "XMM": 1, "MASK": 2, "MMX": 4, "SEG": 5,
                             "CR": 0, "DR": 0 } # CR/DR handled in code.
    OPKIND_REGTYS_VEXREG = { "GP": 0, "XMM": 1, "MASK": 2 }
    OPKIND_REGTYS_ZEROREG = { "GP": 0, "XMM": 1, "FPU": 2 }
    OPKIND_REGTYS_ENC = {"SEG": 3, "FPU": 4, "MMX": 5, "XMM": 6, "BND": 8,
                         "CR": 9, "DR": 10}
    OPKIND_SIZES = {
        0: 0, 1: 1, 2: 2, 4: 3, 8: 4, 16: 5, 32: 6, 64: 7, 10: 0,
        OpKind.SZ_OP: -2, OpKind.SZ_VEC: -3,
    }

    @classmethod
    def parse(cls, desc):
        desc = desc.split()
        if desc[5][-2:] == "+w":
            desc[5] = desc[5][:-2]
            desc.append("INSTR_WIDTH")
        operands = tuple(OpKind.parse(op) for op in desc[1:5] if op != "-")
        return cls(desc[5], desc[0], operands, frozenset(desc[6:]))

    def imm_size(self, opsz):
        flags = ENCODINGS[self.encoding]
        if flags.imm_control < 3:
            return 0
        if flags.imm_control == 3:
            return 1
        if self.mnemonic == "ENTER":
            return 3
        return self.operands[flags.imm_idx^3].immsize(opsz)

    def optype_str(self):
        optypes = ["", "", "", ""]
        flags = ENCODINGS[self.encoding]
        if flags.modrm_idx:   optypes[flags.modrm_idx^3] = "rM"[flags.modrm]
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
            elif ot in "ioa":
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
            raise Exception(f"invalid fixed sizes {fixed} in {self}")
        sizes = (fixed + [1, 1])[:2] + [-2, -3] # See operand_sizes in decode.c.
        extraflags["size_fix1"] = sizes[0]
        extraflags["size_fix2"] = sizes[1] - 1

        for i, opkind in enumerate(self.operands):
            sz = self.OPKIND_SIZES[opkind.size]
            extraflags["op%d_size"%i] = sizes.index(sz)
            if i >= 3:
                continue
            opname = ENCODING_OPORDER[self.encoding][i]
            if opname == "modrm":
                if opkind.kind == "MEM":
                    continue
                extraflags["modrm_ty"] = self.OPKIND_REGTYS_MODRM[opkind.kind]
            elif opname == "modreg":
                extraflags["modreg_ty"] = self.OPKIND_REGTYS_MODREG[opkind.kind]
            elif opname == "vexreg":
                extraflags["vexreg_ty"] = self.OPKIND_REGTYS_VEXREG[opkind.kind]
            elif opname == "zeroreg":
                extraflags["zeroreg_ty"] = self.OPKIND_REGTYS_ZEROREG[opkind.kind]
            else:
                if opkind.kind not in ("IMM", "MEM", "XMM"):
                    raise Exception("invalid regty for op 3, must be VEC")

        # Miscellaneous Flags
        if "SZ8" in self.flags:         extraflags["opsize"] = 1
        if "D64" in self.flags:         extraflags["opsize"] = 2
        if "F64" in self.flags:         extraflags["opsize"] = 3
        if "INSTR_WIDTH" in self.flags: extraflags["instr_width"] = 1
        if "LOCK" in self.flags:        extraflags["lock"] = 1
        if "VSIB" in self.flags:        extraflags["vsib"] = 1
        if modrm:                       extraflags["modrm"] = 1

        if "U66" not in self.flags and (ign66 or "I66" in self.flags):
            extraflags["ign66"] = 1

        if self.imm_size(4) == 1:
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

    def _clone(self, elem):
        if not elem or elem[0].is_instr:
            return elem
        new_num = self._add_table(elem[0])
        self.trie[new_num] = [self._clone(e) for e in self.trie[elem[1]]]
        return elem[0], new_num

    def _transform_opcode(self, opc):
        troot = [opc.escape | opc.vex << 2]
        t256 = [opc.opc + i for i in range(8 if opc.extended else 1)]
        tprefix, t16, t8e, tvex = None, None, None, None
        if opc.prefix == "NFx":
            tprefix = [0, 1]
        elif opc.prefix:
            tprefix = [["NP", "66", "F3", "F2"].index(opc.prefix)]
        if opc.opcext:
            t16 = [((opc.opcext - 0xc0) >> 3) | 8]
            t8e = [opc.opcext & 7]
        elif opc.modreg:
            # TODO: optimize for /r and /m specifiers to reduce size
            mod = {"m": [0], "r": [1<<3], "rm": [0, 1<<3]}[opc.modreg[1]]
            reg = [opc.modreg[0]] if opc.modreg[0] is not None else list(range(8))
            t16 = [x + y for x in mod for y in reg]
        if opc.vexl in ("0", "1") or opc.rexw in ("0", "1"):
            rexw = {"0": [0], "1": [1<<0], "IG": [0, 1<<0]}[opc.rexw or "IG"]
            vexl = {"0": [0], "1": [1<<1], "IG": [0, 1<<1]}[opc.vexl or "IG"]
            tvex = list(map(sum, product(rexw, vexl)))
        # Order must match KIND_ORDER.
        return troot, t256, tprefix, t16, t8e, tvex

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
                        entry[i] = synonyms[elem[1]]

                unique_entry = tuple(entry)
                if len(set(unique_entry)) == 1:
                    # Omit kind if all entries point to the same child
                    synonyms[num] = entry[0]
                    self.trie[num] = None
                elif unique_entry in entries:
                    # Deduplicate entries of this kind
                    synonyms[num] = kind, entries[unique_entry]
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
        return tuple(data), [offsets[v] for _, v in self.trie[0]]

    @property
    def stats(self):
        return {k.name: sum(self.trie[e] is not None for e in v)
                for k, v in self.kindmap.items()}


def superstring(strs):
    # This faces the "shortest superstring" problem, which is NP-hard.
    # Preprocessing: remove any strings which are already completely covered
    realstrs = []
    for s in sorted(strs, key=len, reverse=True):
        for s2 in realstrs:
            if s in s2:
                break
        else:
            realstrs.append(s)

    # Greedy heuristic generally yields acceptable results, though it depends on
    # the order of the menmonics. More compact results are possible, but the
    # expectable gains of an optimal result (probably with O(n!)) are small.
    merged = ""
    def maxoverlap(s1, s2):
        for i in range(min(len(s1), len(s2))-1, 0, -1):
            if s1[:i] == s2[-i:]:
                return i
        return 0
    while realstrs:
        s = max(realstrs, key=lambda k: maxoverlap(k, merged))
        merged += s[maxoverlap(s, merged):]
        realstrs.remove(s)
    return merged

def decode_table(entries, modes):
    mnems = sorted({desc.mnemonic for _, _, desc in entries})
    decode_mnems_lines = [f"FD_MNEMONIC({m},{i})\n" for i, m in enumerate(mnems)]

    trie = Trie(root_count=len(modes))
    descs, desc_map = [], {}
    for weak, opcode, desc in entries:
        ign66 = opcode.prefix in ("NP", "66", "F2", "F3")
        modrm = opcode.modreg or opcode.opcext
        descenc = desc.encode(ign66, modrm)
        desc_idx = desc_map.get(descenc)
        if desc_idx is None:
            desc_idx = desc_map[descenc] = len(descs)
            descs.append(descenc)
        for i, mode in enumerate(modes):
            if "IO"[mode <= 32]+"64" not in desc.flags:
                trie.add_opcode(opcode, desc_idx, i, weak)

    trie.deduplicate()
    table_data, root_offsets = trie.compile()

    mnemonics_intel = [m.replace("SSE_", "").replace("MMX_", "")
                        .replace("MOVABS", "MOV").replace("RESERVED_", "")
                        .replace("JMPF", "JMP FAR").replace("CALLF", "CALL FAR")
                        .replace("_S2G", "").replace("_G2S", "")
                        .replace("_CR", "").replace("_DR", "")
                        .replace("REP_", "REP ").replace("CMPXCHGD", "CMPXCHG")
                        .replace("JCXZ", "JCXZ JECXZJRCXZ")
                        .replace("C_SEP", "CWD CDQ CQO")
                        .replace("C_EX", "CBW CWDECDQE")
                        .lower() for m in mnems]
    mnemonics_str = superstring(mnemonics_intel)

    print(f"Stats: Descs -- {len(descs)} ({8*len(descs)} bytes);",
          f"Trie -- {2*len(table_data)} bytes, {trie.stats};"
          f"Mnems -- {len(mnemonics_str)} + {3*len(mnemonics_intel)} bytes")

    defines = ["FD_TABLE_OFFSET_%d %d\n"%k for k in zip(modes, root_offsets)]

    return "".join(decode_mnems_lines), f"""// Auto-generated file -- do not modify!
#if defined(FD_DECODE_TABLE_DATA)
{"".join(f"{e:#06x}," for e in table_data)}
#elif defined(FD_DECODE_TABLE_DESCS)
{"".join("{{{0},{1},{2},{3}}},".format(*desc) for desc in descs)}
#elif defined(FD_DECODE_TABLE_STRTAB1)
"{mnemonics_str}"
#elif defined(FD_DECODE_TABLE_STRTAB2)
{",".join(str(mnemonics_str.index(mnem)) for mnem in mnemonics_intel)}
#elif defined(FD_DECODE_TABLE_STRTAB3)
{",".join(str(len(mnem)) for mnem in mnemonics_intel)}
#elif defined(FD_DECODE_TABLE_DEFINES)
{"".join("#define " + line for line in defines)}
#else
#error "unspecified decode table"
#endif
"""

def encode_table(entries):
    mnemonics = defaultdict(list)
    mnemonics["FE_NOP"].append(("NP", 0, 0, "0x90"))
    for weak, opcode, desc in entries:
        if "I64" in desc.flags or desc.mnemonic[:9] == "RESERVED_":
            continue

        opsizes = {8} if "SZ8" in desc.flags else {16, 32, 64}
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
            if "U66" not in desc.flags and opcode.prefix != "NFx":
                opsizes -= {16}
        if "I66" in desc.flags:
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

        if "D64" in desc.flags:
            opsizes -= {32}
        if "SZ8" not in desc.flags and "INSTR_WIDTH" not in desc.flags and all(op.size != OpKind.SZ_OP for op in desc.operands):
            opsizes = {0}
        if "VSIB" not in desc.flags and all(op.size != OpKind.SZ_VEC for op in desc.operands):
            vecsizes = {0} # for VEX-encoded general-purpose instructions.
        if "ENC_NOSZ" in desc.flags:
            opsizes, vecsizes = {0}, {0}

        # Where to put the operand size in the mnemonic
        separate_opsize = "ENC_SEPSZ" in desc.flags
        prepend_opsize = max(opsizes) > 0 and not separate_opsize
        prepend_vecsize = hasvex and max(vecsizes) > 0 and not separate_opsize

        if "F64" in desc.flags:
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
            if opsize == 64 and "D64" not in desc.flags and "F64" not in desc.flags: opc_s += "|OPC_REXW"

            # Construct mnemonic name
            mnem_name = {"MOVABS": "MOV", "XCHG_NOP": "XCHG"}.get(desc.mnemonic, desc.mnemonic)
            name = "FE_" + prefix[0] + mnem_name
            if prepend_opsize and not ("D64" in desc.flags and opsize == 64):
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

    fd_mnem_list, fd_table = decode_table(entries, args.modes)
    args.decode_mnems.write(fd_mnem_list)
    args.decode_table.write(fd_table)

    fe_mnem_list, fe_code = encode_table(entries)
    args.encode_mnems.write(fe_mnem_list)
    args.encode_table.write(fe_code)

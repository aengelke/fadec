#!/usr/bin/python3

import argparse
import bisect
from collections import OrderedDict, defaultdict, namedtuple, Counter
from enum import Enum
from itertools import product
import re
import struct
from typing import NamedTuple, FrozenSet, List, Tuple, Union, Optional, ByteString

INSTR_FLAGS_FIELDS, INSTR_FLAGS_SIZES = zip(*[
    ("modrm_idx", 2),
    ("modreg_idx", 2),
    ("vexreg_idx", 2), # note: vexreg w/o vex prefix is zeroreg_val
    ("imm_idx", 2),
    ("evex_bcst", 1),
    ("evex_mask", 1),
    ("zeroreg_val", 1),
    ("lock", 1),
    ("imm_control", 3),
    ("vsib", 1),
    ("modrm_size", 2),
    ("modreg_size", 2),
    ("vexreg_size", 2),
    ("imm_size", 2),
    ("legacy", 1),
    ("unused2", 1),
    ("size_fix1", 3),
    ("size_fix2", 2),
    ("instr_width", 1),
    ("modrm_ty", 3),
    ("modreg_ty", 3),
    ("vexreg_ty", 2),
    ("imm_ty", 0),
    ("evex_rc", 2),
    ("evex_bcst16", 1),
    ("opsize", 3),
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
    "R": InstrFlags(modrm=1, modreg_idx=0^3), # AMX TILEZERO
    "M1": InstrFlags(modrm=1, modrm_idx=0^3, imm_idx=1^3, imm_control=1),
    "MI": InstrFlags(modrm=1, modrm_idx=0^3, imm_idx=1^3, imm_control=4),
    "MC": InstrFlags(modrm=1, modrm_idx=0^3, vexreg_idx=1^3, zeroreg_val=1),
    "MR": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=1^3),
    "RM": InstrFlags(modrm=1, modrm_idx=1^3, modreg_idx=0^3),
    "RMA": InstrFlags(modrm=1, modrm_idx=1^3, modreg_idx=0^3, vexreg_idx=2^3),
    "MRI": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=1^3, imm_idx=2^3, imm_control=4),
    "RMI": InstrFlags(modrm=1, modrm_idx=1^3, modreg_idx=0^3, imm_idx=2^3, imm_control=4),
    "MRC": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=1^3, vexreg_idx=2^3, zeroreg_val=1),
    "AM": InstrFlags(modrm=1, modrm_idx=1^3, vexreg_idx=0^3),
    "MA": InstrFlags(modrm=1, modrm_idx=0^3, vexreg_idx=1^3),
    "I": InstrFlags(imm_idx=0^3, imm_control=4),
    "IA": InstrFlags(vexreg_idx=0^3, imm_idx=1^3, imm_control=4),
    "O": InstrFlags(modrm_idx=0^3),
    "OI": InstrFlags(modrm_idx=0^3, imm_idx=1^3, imm_control=4),
    "OA": InstrFlags(modrm_idx=0^3, vexreg_idx=1^3),
    "S": InstrFlags(modreg_idx=0^3), # segment register in bits 3,4,5
    "A": InstrFlags(vexreg_idx=0^3),
    "D": InstrFlags(imm_idx=0^3, imm_control=6),
    "FD": InstrFlags(vexreg_idx=0^3, imm_idx=1^3, imm_control=2),
    "TD": InstrFlags(vexreg_idx=1^3, imm_idx=0^3, imm_control=2),

    "RVM": InstrFlags(modrm=1, modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3),
    "RVMI": InstrFlags(modrm=1, modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3, imm_idx=3^3, imm_control=4),
    "RVMR": InstrFlags(modrm=1, modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3, imm_idx=3^3, imm_control=3),
    "RMV": InstrFlags(modrm=1, modrm_idx=1^3, modreg_idx=0^3, vexreg_idx=2^3),
    "VM": InstrFlags(modrm=1, modrm_idx=1^3, vexreg_idx=0^3),
    "VMI": InstrFlags(modrm=1, modrm_idx=1^3, vexreg_idx=0^3, imm_idx=2^3, imm_control=4),
    "MVR": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=2^3, vexreg_idx=1^3),
    "MRV": InstrFlags(modrm=1, modrm_idx=0^3, modreg_idx=1^3, vexreg_idx=2^3),
}
ENCODING_OPTYS = ["modrm", "modreg", "vexreg", "imm"]
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
    "ss": 4, # Scalar single of XMM (d)
    "q": 8,
    "sd": 8, # Scalar double of XMM (q)
    "t": 10, # FPU/ten-byte
    "dq": 16,
    "qq": 32,
    "oq": 64, # oct-quadword
    "": 0, # for MEMZ
    "v": -1, # operand size (w/d/q)
    "y": -1, # operand size (d/q)
    "z": -1, # w/d (immediates, min(operand size, 4))
    "a": -1, # z:z
    "p": -1, # w:z
    "x": -2, # vector size
    "h": -3, # half x
    "f": -4, # fourth x
    "e": -5, # eighth x
    "pd": -2, # packed double (x)
    "ps": -2, # packed single (x)

    # Custom names
    "bs": -1, # sign-extended immediate
    "zd": 4, # z-immediate, but always 4-byte operand
    "zq": 8, # z-immediate, but always 8-byte operand
}
class OpKind(NamedTuple):
    regkind: str
    sizestr: str

    SZ_OP = -1
    SZ_VEC = -2
    SZ_VEC_HALF = -3
    SZ_VEC_QUARTER = -4
    SZ_VEC_EIGHTH = -5

    def abssize(self, opsz=None, vecsz=None):
        res = opsz if self.size == self.SZ_OP else \
              vecsz if self.size == self.SZ_VEC else \
              vecsz >> 1 if self.size == self.SZ_VEC_HALF else \
              vecsz >> 2 if self.size == self.SZ_VEC_QUARTER else \
              vecsz >> 3 if self.size == self.SZ_VEC_EIGHTH else self.size
        if res is None:
            raise Exception("unspecified operand size")
        return res
    def immsize(self, opsz):
        maxsz = 1 if self.sizestr == "bs" else 4 if self.sizestr[0] == "z" else 8
        return min(maxsz, self.abssize(opsz))
    @property
    def kind(self):
        return OPKIND_CANONICALIZE[self.regkind]
    @property
    def size(self):
        return OPKIND_SIZES[self.sizestr]
    @classmethod
    def parse(cls, op):
        return cls(op[0], op[1:])

class InstrDesc(NamedTuple):
    mnemonic: str
    encoding: str
    operands: Tuple[str, ...]
    flags: FrozenSet[str]

    OPKIND_REGTYS = {
        ("modrm", "GP"): 1,   ("modreg", "GP"): 1,   ("vexreg", "GP"): 1,
        ("modrm", "XMM"): 0,  ("modreg", "XMM"): 0,  ("vexreg", "XMM"): 0,
        ("modrm", "MMX"): 5,  ("modreg", "MMX"): 5,
        ("modrm", "FPU"): 4,                         ("vexreg", "FPU"): 3,
        ("modrm", "TMM"): 6,  ("modreg", "TMM"): 6,  ("vexreg", "TMM"): 3,
        ("modrm", "MASK"): 7, ("modreg", "MASK"): 7, ("vexreg", "MASK"): 2,
                              ("modreg", "SEG"): 3,
                              ("modreg", "DR"): 0, # handled in code
                              ("modreg", "CR"): 0, # handled in code
        ("modrm", "MEM"): 0,
        ("imm", "MEM"): 0, ("imm", "IMM"): 0, ("imm", "XMM"): 0,
    }
    OPKIND_SIZES = {
        0: 0, 1: 1, 2: 2, 4: 3, 8: 4, 16: 5, 32: 6, 64: 7, 10: 0,
        # OpKind.SZ_OP: -2, OpKind.SZ_VEC: -3, OpKind.SZ_HALFVEC: -4,
    }

    @classmethod
    def parse(cls, desc):
        desc = desc.split()
        mnem, _, compactDesc = desc[5].partition("+")
        flags = frozenset(desc[6:] + [{
            "w": "INSTR_WIDTH",
            "a": "U67",
            "s": "USEG",
            "k": "MASK",
            "b": "BCST",
            "e": "SAE",
            "r": "ER",
        }[c] for c in compactDesc])
        operands = tuple(OpKind.parse(op) for op in desc[1:5] if op != "-")
        return cls(mnem, desc[0], operands, flags)

    def imm_size(self, opsz):
        flags = ENCODINGS[self.encoding]
        if flags.imm_control < 3:
            return 0
        if flags.imm_control == 3:
            return 1
        if self.mnemonic == "ENTER":
            return 3
        return self.operands[flags.imm_idx^3].immsize(opsz)

    def dynsizes(self):
        dynopsz = set(op.size for op in self.operands if op.size < 0)
        if {"INSTR_WIDTH", "SZ8"} & self.flags: dynopsz.add(OpKind.SZ_OP)
        if OpKind.SZ_OP in dynopsz and len(dynopsz) > 1:
            raise Exception(f"conflicting dynamic operand sizes in {self}")
        return dynopsz

    def encode(self, mnem, ign66, modrm):
        flags = ENCODINGS[self.encoding]
        extraflags = {}

        dynopsz = self.dynsizes()
        # Operand size either refers to vectors or GP, but not both
        if dynopsz and OpKind.SZ_OP not in dynopsz: # Vector operand size
            if self.flags & {"SZ8", "D64", "F64", "INSTR_WIDTH", "LOCK", "U66"}:
                raise Exception(f"incompatible flags in {self}")
            # Allow at most the vector size together with one alternative
            dynsizes = [OpKind.SZ_VEC] + list(dynopsz - {OpKind.SZ_VEC})
            extraflags["opsize"] = 4 | (OpKind.SZ_VEC - dynsizes[-1])
            if len(dynsizes) > 2:
                raise Exception(f"conflicting vector operand sizes in {self}")
        else: # either empty or GP operand size
            dynsizes = [OpKind.SZ_OP]
            if "SZ8" in self.flags:
                dynsizes = []
            if "D64" in self.flags: extraflags["opsize"] = 2
            if "F64" in self.flags: extraflags["opsize"] = 3
            extraflags["lock"] = "LOCK" in self.flags

        if (self.flags & {"SZ8", "INSTR_WIDTH"} or
            mnem in ("MOVSX", "MOVZX", "XCHG_NOP", "3DNOW")):
            extraflags["legacy"] = 1
            # INSTR_WIDTH defaults to zero, so only enable when SZ8 is unset
            if "INSTR_WIDTH" in self.flags and "SZ8" not in self.flags:
                extraflags["instr_width"] = 1

        imm_byte = self.imm_size(4) == 1
        extraflags["imm_control"] = flags.imm_control | imm_byte

        # Sort fixed sizes encodable in size_fix2 as second element.
        # But: byte-sized immediates are handled specially and don't cost space.
        fixed = set(self.OPKIND_SIZES[op.size] for op in self.operands if
                    op.size >= 0 and not (imm_byte and op.kind == "IMM"))
        fixed = sorted(fixed, key=lambda x: 1 <= x <= 4)
        if len(fixed) > 2 or (len(fixed) == 2 and not (1 <= fixed[1] <= 4)):
            raise Exception(f"invalid fixed sizes {fixed} in {self}")
        sizes = (fixed + [1, 1])[:2] + dynsizes # See operand_sizes in decode.c.
        extraflags["size_fix1"] = sizes[0]
        extraflags["size_fix2"] = sizes[1] - 1

        for i, opkind in enumerate(self.operands):
            sz = self.OPKIND_SIZES[opkind.size] if opkind.size >= 0 else opkind.size
            if opkind.kind == "IMM":
                if imm_byte and sz not in [1] + dynsizes[:1]:
                    raise Exception(f"imm_byte with opsize {sz} in {self}")
                extraflags[f"imm_size"] = sz == 1 if imm_byte else sizes.index(sz)
            else:
                opname = ENCODING_OPORDER[self.encoding][i]
                extraflags[f"{opname}_size"] = sizes.index(sz)
                extraflags[f"{opname}_ty"] = self.OPKIND_REGTYS[opname, opkind.kind]

        # Miscellaneous Flags
        if "VSIB" in self.flags:        extraflags["vsib"] = 1
        if "BCST" in self.flags:        extraflags["evex_bcst"] = 1
        if "BCST16" in self.flags:      extraflags["evex_bcst16"] = 1
        if "MASK" in self.flags:        extraflags["evex_mask"] = 1
        if "SAE" in self.flags:         extraflags["evex_rc"] = 1
        if "ER" in self.flags:          extraflags["evex_rc"] = 3
        if modrm:                       extraflags["modrm"] = 1

        if "U66" not in self.flags and (ign66 or "I66" in self.flags):
            extraflags["ign66"] = 1

        enc = flags._replace(**extraflags)._encode()
        enc = tuple((enc >> i) & 0xffff for i in range(0, 48, 16))
        # First 2 bytes are the mnemonic, last 6 bytes are the encoding.
        return f"{{FDI_{mnem}, {enc[0]}, {enc[1]}, {enc[2]}}}"

class EntryKind(Enum):
    NONE = 0x00
    PREFIX = 0x10
    INSTR = 0x20
    WEAKINSTR = 0x30
    TABLE16 = 0x01
    TABLE8E = 0x11
    ESCAPE = 0x02
    TABLE256 = 0x12
    TABLE_VEX = 0x22
    TABLE_PREFIX = 0x03
    TABLE_ROOT = -1
    @property
    def is_table(self):
        return self != EntryKind.INSTR and self != EntryKind.WEAKINSTR and self != EntryKind.PREFIX

opcode_regex = re.compile(
     r"^(?:(?P<prefixes>(?P<vex>E?VEX\.)?(?P<legacy>NP|66|F2|F3|NFx)\." +
                     r"(?:W(?P<rexw>[01])\.)?(?:L(?P<vexl>0|1|12|2|IG)\.)?))?" +
     r"(?P<escape>0f38|0f3a|0f|M[56]\.|)" +
     r"(?P<opcode>[0-9a-f]{2})" +
     r"(?:/(?P<modreg>[0-7]|[rm][0-7]?|[0-7][rm])|(?P<opcext>[c-f][0-9a-f]))?(?P<extended>\+)?$")

class Opcode(NamedTuple):
    prefix: Union[None, str] # None/NP/66/F2/F3/NFx
    escape: int # [0, 0f, 0f38, 0f3a]
    opc: int
    extended: bool # Extend opc or opcext in ModRM.rm, if present
    # Fixed ModRM.mod ("r"/"m"), ModRM.reg, ModRM.rm (opcext + AMX)
    modrm: Tuple[Union[None, str], Union[None, int], Union[None, int]]
    vex: int # 0 = legacy, 1 = VEX, 2 = EVEX
    vexl: Union[str, None] # 0, 1, 12, 2, IG, None = used, both
    rexw: Union[str, None] # 0, 1, None = both (or ignored)

    @classmethod
    def parse(cls, opcode_string):
        match = opcode_regex.match(opcode_string)
        if match is None:
            raise Exception(opcode_string)
            return None

        opcext = int(match.group("opcext") or "0", 16)
        modreg = match.group("modreg")
        if opcext:
            modrm = "r", (opcext >> 3) & 7, opcext & 7
        elif modreg:
            if modreg[0] in "rm":
                modrm = modreg[0], None, int(modreg[1:]) if modreg[1:] else None
            else:
                modrm = modreg[1:] or None, int(modreg[0]), None
        else:
            modrm = None, None, None

        return cls(
            prefix=match.group("legacy"),
            escape=["", "0f", "0f38", "0f3a", "M4.", "M5.", "M6."].index(match.group("escape")),
            opc=int(match.group("opcode"), 16),
            extended=match.group("extended") is not None,
            modrm=modrm,
            vex=[None, "VEX.", "EVEX."].index(match.group("vex")),
            vexl=match.group("vexl"),
            rexw=match.group("rexw"),
        )

def verifyOpcodeDesc(opcode, desc):
    flags = ENCODINGS[desc.encoding]
    oporder = ENCODING_OPORDER[desc.encoding]
    expected_immkinds = ["", "I", "O", "L", "IA", "", "J"][flags.imm_control]
    fixed_mod = opcode.modrm[0]
    if opcode.extended or desc.mnemonic in ("MOV_CR2G", "MOV_DR2G", "MOV_G2CR", "MOV_G2DR"):
        fixed_mod = "r"
    expected_modrmkinds = {None: "EQWFKT", "r": "RNUFKT", "m": "M"}[fixed_mod]
    # allow F and R for zeroreg, which we overlap with vexreg
    expected_vexkinds = "BHKT" if opcode.vex else "BHRF"
    for i, opkind in enumerate(desc.operands):
        if oporder[i] == "modrm" and opkind.regkind not in expected_modrmkinds:
            raise Exception(f"modrm operand-regkind mismatch {opcode}, {desc}")
        if oporder[i] == "modreg" and opkind.regkind not in "GPVSCDFKT":
            raise Exception(f"modreg operand-regkind mismatch {opcode}, {desc}")
        if oporder[i] == "vexreg" and opkind.regkind not in expected_vexkinds:
            raise Exception(f"vexreg operand-regkind mismatch {opcode}, {desc}")
        if oporder[i] == "imm" and opkind.regkind not in expected_immkinds:
            raise Exception(f"imm operand-regkind mismatch {opcode}, {desc}")
    if opcode.escape == 2 and flags.imm_control != 0:
        raise Exception(f"0f38 has no immediate operand {opcode}, {desc}")
    if opcode.escape == 3 and desc.imm_size(4) != 1:
        raise Exception(f"0f3a must have immediate byte {opcode}, {desc}")
    if opcode.escape == 0 and opcode.prefix is not None:
        raise Exception(f"unescaped opcode has prefix {opcode}, {desc}")
    if opcode.escape == 0 and opcode.vexl is not None:
        raise Exception(f"unescaped opcode has L specifier {opcode}, {desc}")
    if opcode.escape == 0 and opcode.rexw is not None:
        raise Exception(f"unescaped opcode has W specifier {opcode}, {desc}")
    if opcode.escape == 0 and opcode.vex:
        raise Exception(f"VEX opcode without escape {opcode}, {desc}")
    if opcode.vex and opcode.extended:
        raise Exception(f"VEX/EVEX must not be extended {opcode}, {desc}")
    if opcode.vex and opcode.prefix not in ("NP", "66", "F2", "F3"):
        raise Exception(f"VEX/EVEX must have mandatory prefix {opcode}, {desc}")
    if opcode.vexl == "IG" and desc.dynsizes() - {OpKind.SZ_OP}:
        raise Exception(f"(E)VEX.LIG with dynamic vector size {opcode}, {desc}")
    if "VSIB" in desc.flags and opcode.modrm[0] != "m":
        raise Exception(f"VSIB for non-memory opcode {opcode}, {desc}")
    if opcode.vex == 2 and flags.vexreg_idx:
        # Checking this here allows to omit check for V' in decoder.
        if desc.operands[flags.vexreg_idx ^ 3].kind != "XMM":
            raise Exception(f"EVEX.vvvv must refer to XMM {opcode}, {desc}")
    if opcode.vex == 2 and flags.modreg_idx and flags.modreg_idx ^ 3 != 0:
        # EVEX.z=0 is only checked for mask operands in ModReg
        if desc.operands[flags.modreg_idx ^ 3].kind == "MASK":
            raise Exception(f"ModRM.reg mask not first operand {opcode}, {desc}")
    # Verify tuple type
    if opcode.vex == 2 and opcode.modrm[0] != "r":
        tts = [s for s in desc.flags if s.startswith("TUPLE")]
        if len(tts) != 1:
            raise Exception(f"missing tuple type in {opcode}, {desc}")
        if flags.modrm_idx == 3 ^ 3:
            raise Exception(f"missing memory operand {opcode}, {desc}")
        # From Intel SDM
        bcst, evexw, vszs = {
            "TUPLE_FULL_16":      (2,    "0",  (  16,   32,   64)),
            "TUPLE_FULL_32":      (4,    "0",  (  16,   32,   64)),
            "TUPLE_FULL_64":      (8,    "1",  (  16,   32,   64)),
            "TUPLE_HALF_16":      (2,    "0",  (   8,   16,   32)),
            "TUPLE_HALF_32":      (4,    "0",  (   8,   16,   32)),
            "TUPLE_HALF_64":      (8,    "1",  (   8,   16,   32)),
            "TUPLE_QUARTER_16":   (2,    "0",  (   4,    8,   16)),
            "TUPLE_FULL_MEM":     (None, None, (  16,   32,   64)),
            "TUPLE_HALF_MEM":     (None, None, (   8,   16,   32)),
            "TUPLE_QUARTER_MEM":  (None, None, (   4,    8,   16)),
            "TUPLE_EIGHTH_MEM":   (None, None, (   2,    4,    8)),
            "TUPLE1_SCALAR_8":    (None, None, (   1,    1,    1)),
            "TUPLE1_SCALAR_16":   (None, None, (   2,    2,    2)),
            "TUPLE1_SCALAR_32":   (None, "0",  (   4,    4,    4)),
            "TUPLE1_SCALAR_64":   (None, "1",  (   8,    8,    8)),
            "TUPLE1_SCALAR_OPSZ": (None, None, (   0,    0,    0)),
            "TUPLE1_FIXED_32":    (None, None, (   4,    4,    4)),
            "TUPLE1_FIXED_64":    (None, None, (   8,    8,    8)),
            "TUPLE2_32":          (None, "0",  (   8,    8,    8)),
            "TUPLE2_64":          (None, "1",  (None,   16,   16)),
            "TUPLE4_32":          (None, "0",  (None,   16,   16)),
            "TUPLE4_64":          (None, "1",  (None, None,   32)),
            "TUPLE8_32":          (None, "0",  (None, None,   32)),
            "TUPLE_MEM128":       (None, None, (  16,   16,   16)),
            # TODO: Fix MOVDDUP tuple size :(
            "TUPLE_MOVDDUP":      (None, None, (  16,   32,   64)),
        }[tts[0]]
        if "BCST" in desc.flags:
            if bcst is None:
                raise Exception(f"broadcast on incompatible type {opcode}, {desc}")
            if ("BCST16" in desc.flags) != (bcst == 2):
                raise Exception(f"bcst16 mismatch, should be {bcst} {opcode}, {desc}")
        # EVEX.W is used to distinguish 4/8-byte broadcast size
        if evexw and opcode.rexw != evexw:
            raise Exception(f"incompatible EVEX.W {opcode}, {desc}")
        for l, tupsz in enumerate(vszs):
            opsz = desc.operands[flags.modrm_idx ^ 3].abssize(0, 16 << l)
            if tupsz is not None and opsz != tupsz:
                raise Exception(f"memory size {opsz} != {tupsz} {opcode}, {desc}")

class Trie:
    KIND_ORDER = (EntryKind.TABLE_ROOT, EntryKind.ESCAPE, EntryKind.TABLE256,
                  EntryKind.TABLE_PREFIX, EntryKind.TABLE16,
                  EntryKind.TABLE8E, EntryKind.TABLE_VEX)
    TABLE_LENGTH = {
        EntryKind.TABLE_ROOT: 256,
        EntryKind.ESCAPE: 8,
        EntryKind.TABLE256: 256,
        EntryKind.TABLE_PREFIX: 4,
        EntryKind.TABLE16: 16,
        EntryKind.TABLE8E: 8,
        EntryKind.TABLE_VEX: 8,
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
        if not elem or not elem[0].is_table:
            return elem
        new_num = self._add_table(elem[0])
        self.trie[new_num] = [self._clone(e) for e in self.trie[elem[1]]]
        return elem[0], new_num

    def _transform_opcode(self, opc):
        realopcext = opc.extended and opc.modrm[2] is None
        topc = [opc.opc + i for i in range(8 if realopcext else 1)]
        if opc.escape == 0 and opc.opc in (0xc4, 0xc5, 0x62):
            assert opc.prefix is None
            assert opc.modrm == ("m", None, None)
            assert opc.rexw is None
            assert opc.vexl is None
            # We do NOT encode /m, this is handled by prefix code.
            # Order must match KIND_ORDER.
            return topc, [0], None, None, None, None, None
        elif opc.escape == 0:
            troot, tescape, topc = topc, None, None
        else:
            troot = [[0x0f], [0xc4, 0xc5], [0x62]][opc.vex]
            tescape = [opc.escape]

        tprefix, t16, t8e, tvex = None, None, None, None
        if opc.prefix == "NFx":
            tprefix = [0, 1]
        elif opc.prefix:
            tprefix = [["NP", "66", "F3", "F2"].index(opc.prefix)]
        if opc.modrm != (None, None, None):
            # TODO: optimize for /r and /m specifiers to reduce size
            mod = {"m": [0], "r": [1], None: [0, 1]}[opc.modrm[0]]
            reg = [opc.modrm[1]] if opc.modrm[1] is not None else list(range(8))
            t16 = [x + (y << 1) for x in mod for y in reg]
            if opc.modrm[2] is not None and not opc.extended:
                t8e = [opc.modrm[2]]
        if opc.rexw is not None or (opc.vexl or "IG") != "IG":
            rexw = {"0": [0], "1": [1<<0], None: [0, 1<<0]}[opc.rexw]
            if opc.vex < 2:
                vexl = {"0": [0], "1": [1<<1], "IG": [0, 1<<1]}[opc.vexl or "IG"]
            else:
                vexl = {"0": [0], "12": [1<<1, 2<<1], "2": [2<<1], "IG": [0, 1<<1, 2<<1, 3<<1]}[opc.vexl or "IG"]
            tvex = list(map(sum, product(rexw, vexl)))
        # Order must match KIND_ORDER.
        return troot, tescape, topc, tprefix, t16, t8e, tvex

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
                entry[entry_idx] = kind, descidx << 2
            elif not weak:
                raise Exception(f"redundant non-weak {opcode}")

    def add_prefix(self, byte, prefix, root_idx):
        if self.trie[0][root_idx] is None:
            self.trie[0][root_idx] = EntryKind.TABLE_ROOT, self._add_table(EntryKind.TABLE_ROOT)
        self.trie[self.trie[0][root_idx][1]][byte] = EntryKind.PREFIX, prefix

    def deduplicate(self):
        synonyms = {}
        for kind in self.KIND_ORDER[::-1]:
            entries = {}
            for num in self.kindmap[kind]:
                # Replace previous synonyms
                entry = self.trie[num]
                for i, elem in enumerate(entry):
                    if elem and elem[0].is_table and elem[1] in synonyms:
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
                    value = offsets[elem[1]] if elem[0].is_table else elem[1]
                    data[i] = value | (elem[0].value & 3)
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
    # First sort strings and later do a binary search for each possible prefix.
    realstrs.sort()
    merged = ""
    while realstrs:
        for i in range(min(16, len(merged)), 0, -1):
            idx = bisect.bisect_left(realstrs, merged[-i:])
            if idx < len(realstrs) and realstrs[idx][:i] == merged[-i:]:
                merged += realstrs.pop(idx)[i:]
                break
        else:
            merged += realstrs.pop()
    return merged

def decode_table(entries, args):
    modes = args.modes

    trie = Trie(root_count=len(modes))
    for i, mode in enumerate(modes):
        # Magic values must match PF_* enum in decode.c.
        trie.add_prefix(0x66, 0xfffa, i)
        trie.add_prefix(0x67, 0xfffb, i)
        trie.add_prefix(0xf0, 0xfffc, i)
        trie.add_prefix(0xf2, 0xfffd, i)
        trie.add_prefix(0xf3, 0xfffd, i)
        trie.add_prefix(0x64, 0xfff9, i)
        trie.add_prefix(0x65, 0xfff9, i)
        for seg in (0x26, 0x2e, 0x36, 0x3e):
            trie.add_prefix(seg, 0xfff8 + (mode <= 32), i)
        if mode > 32:
            for rex in range(0x40, 0x50):
                trie.add_prefix(rex, 0xfffe, i)

    mnems, descs, desc_map = set(), [], {}
    descs.append("{0}") # desc index zero is "invalid"
    for weak, opcode, desc in entries:
        ign66 = opcode.prefix in ("NP", "66", "F2", "F3")
        modrm = opcode.modrm != (None, None, None)
        mnem = {
            "PUSH_SEG": "PUSH", "POP_SEG": "POP",
            "MOV_CR2G": "MOV_CR", "MOV_G2CR": "MOV_CR",
            "MOV_DR2G": "MOV_DR", "MOV_G2DR": "MOV_DR",
            "MMX_MOVD_M2G": "MMX_MOVD", "MMX_MOVD_G2M": "MMX_MOVD",
            "MMX_MOVQ_M2G": "MMX_MOVQ", "MMX_MOVQ_G2M": "MMX_MOVQ",
            "SSE_MOVD_X2G": "SSE_MOVD", "SSE_MOVD_G2X": "SSE_MOVD",
            "SSE_MOVQ_X2G": "SSE_MOVQ", "SSE_MOVQ_G2X": "SSE_MOVQ",
            "VMOVD_X2G": "VMOVD", "VMOVD_G2X": "VMOVD",
            "VMOVQ_X2G": "VMOVQ", "VMOVQ_G2X": "VMOVQ",
        }.get(desc.mnemonic, desc.mnemonic)
        mnems.add(mnem)
        descenc = desc.encode(mnem, ign66, modrm)
        desc_idx = desc_map.get(descenc)
        if desc_idx is None:
            desc_idx = desc_map[descenc] = len(descs)
            descs.append(descenc)
        for i, mode in enumerate(modes):
            if "IO"[mode <= 32]+"64" not in desc.flags:
                trie.add_opcode(opcode, desc_idx, i, weak)

    trie.deduplicate()
    table_data, root_offsets = trie.compile()

    mnems = sorted(mnems)
    decode_mnems_lines = [f"FD_MNEMONIC({m},{i})\n" for i, m in enumerate(mnems)]

    mnemonics_intel = [m.replace("SSE_", "").replace("MMX_", "")
                        .replace("EVX_", "V")
                        .replace("MOVABS", "MOV").replace("RESERVED_", "")
                        .replace("JMPF", "JMP FAR").replace("CALLF", "CALL FAR")
                        .replace("_S2G", "").replace("_G2S", "")
                        .replace("_X2G", "").replace("_G2X", "")
                        .replace("_CR", "").replace("_DR", "")
                        .replace("REP_", "REP ").replace("CMPXCHGD", "CMPXCHG")
                        .replace("JCXZ", "JCXZ JECXZJRCXZ")
                        .replace("C_SEP", "CWD CDQ CQO")
                        .replace("C_EX", "CBW CWDECDQE").replace("XCHG_NOP", "")
                        .lower() for m in mnems]
    mnemonics_str = superstring(mnemonics_intel)

    if args.stats:
        print(f"Decode stats: Descs -- {len(descs)} ({8*len(descs)} bytes); ",
              f"Trie -- {2*len(table_data)} bytes, {trie.stats}; "
              f"Mnems -- {len(mnemonics_str)} + {3*len(mnemonics_intel)} bytes")

    defines = ["FD_TABLE_OFFSET_%d %d\n"%k for k in zip(modes, root_offsets)]

    return "".join(decode_mnems_lines), f"""// Auto-generated file -- do not modify!
#if defined(FD_DECODE_TABLE_DATA)
{"".join(f"{e:#06x}," for e in table_data)}
#elif defined(FD_DECODE_TABLE_DESCS)
{",".join(descs)}
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

class EncodeVariant(NamedTuple):
    opcode: Opcode
    desc: InstrDesc

def encode_mnems(entries):
    # mapping from (mnem, opsize, ots) -> (opcode, desc)
    mnemonics = defaultdict(list)
    for weak, opcode, desc in entries:
        if "I64" in desc.flags or desc.mnemonic[:9] == "RESERVED_":
            continue
        if opcode.vex == 2: # EVEX not implemented
            continue

        opsizes, vecsizes = {0}, {0}
        prepend_opsize, prepend_vecsize = False, False
        # Where to put the operand size in the mnemonic
        separate_opsize = "ENC_SEPSZ" in desc.flags

        if "ENC_NOSZ" in desc.flags or not desc.dynsizes():
            pass
        elif OpKind.SZ_OP in desc.dynsizes():
            if opcode.rexw is not None:
                raise Exception(f"unexpected REXW specifier {desc}")
            opsizes = {8} if "SZ8" in desc.flags else {16, 32, 64}
            if opcode.prefix in ("NP", "66", "F2", "F3") and "U66" not in desc.flags:
                opsizes -= {16}
            if "I66" in desc.flags:
                opsizes -= {16}
            if "D64" in desc.flags:
                opsizes -= {32}
            prepend_opsize = not separate_opsize
            if "F64" in desc.flags:
                opsizes = {64}
                prepend_opsize = False
        elif opcode.vex and opcode.vexl != "IG": # vectors; don't care for SSE
            vecsizes = {128, 256} # TODO-EVEX
            if opcode.vexl:
                vecsizes -= {128 if opcode.vexl == "1" else 256}
            prepend_vecsize = not separate_opsize

        # All encoding types; reg is r; modrm is r/m
        optypes_base = []
        for i, opkind in enumerate(desc.operands):
            opname = ENCODING_OPORDER[desc.encoding][i]
            if opname == "modrm":
                modrm_type = opcode.modrm[0] or "rm"
                if opcode.extended or desc.mnemonic in ("MOV_CR2G", "MOV_DR2G", "MOV_G2CR", "MOV_G2DR"):
                    modrm_type = "r"
                optypes_base.append(modrm_type)
            elif opname == "modreg" or opname == "vexreg":
                optypes_base.append("r")
            else:
                optypes_base.append(" iariioo"[ENCODINGS[desc.encoding].imm_control])
        optypes = {"".join(x) for x in product(*optypes_base)}

        prefixes = [("", "")]
        if "LOCK" in desc.flags:
            prefixes.append(("LOCK_", "LOCK"))
        if "ENC_REP" in desc.flags:
            prefixes.append(("REP_", "F3"))
        if "ENC_REPCC" in desc.flags:
            prefixes.append(("REPNZ_", "F2"))
            prefixes.append(("REPZ_", "F3"))

        for opsize, vecsize, prefix, ots in product(opsizes, vecsizes, prefixes, optypes):
            if prefix[1] == "LOCK" and ots[0] != "m":
                continue

            spec_opcode = opcode
            if prefix[1]:
                spec_opcode = spec_opcode._replace(prefix=prefix[1])
            if opsize == 64 and "D64" not in desc.flags and "F64" not in desc.flags:
                spec_opcode = spec_opcode._replace(rexw="1")
            if vecsize == 256:
                spec_opcode = spec_opcode._replace(vexl="1")
            if spec_opcode.vexl == "IG":
                spec_opcode = spec_opcode._replace(vexl="0")
            if ENCODINGS[desc.encoding].modrm_idx:
                has_memory = "m" in ots
                modrm = ("m" if has_memory else "r",) + spec_opcode.modrm[1:]
                spec_opcode = spec_opcode._replace(modrm=modrm)
            if ENCODINGS[desc.encoding].modrm or None not in opcode.modrm:
                assert spec_opcode.modrm[0] in ("r", "m")

            # Construct mnemonic name
            mnem_name = {"MOVABS": "MOV", "XCHG_NOP": "XCHG"}.get(desc.mnemonic, desc.mnemonic)
            name = prefix[0] + mnem_name
            if prepend_opsize and not ("D64" in desc.flags and opsize == 64):
                name += f"_{opsize}"[name[-1] not in "0123456789":]
            if prepend_vecsize:
                name += f"_{vecsize}"[name[-1] not in "0123456789":]
            for ot, op in zip(ots, desc.operands):
                name += ot.replace("o", "")
                if separate_opsize:
                    name += f"{op.abssize(opsize//8, vecsize//8)*8}"
            variant = EncodeVariant(spec_opcode, desc)
            mnemonics[name, opsize, ots].append(variant)
            altname = {
                "C_EX16": "CBW", "C_EX32": "CWDE", "C_EX64": "CDQE",
                "C_SEP16": "CWD", "C_SEP32": "CDQ", "C_SEP64": "CQO",
                "CMPXCHGD32m": "CMPXCHG8Bm", "CMPXCHGD64m": "CMPXCHG16Bm",
            }.get(name)
            if altname:
                mnemonics[altname, opsize, ots].append(variant)

    for (mnem, opsize, ots), variants in mnemonics.items():
        dedup = OrderedDict()
        for i, variant in enumerate(variants):
            PRIO = ["O", "OA", "AO", "AM", "MA", "IA", "OI"]
            enc_prio = PRIO.index(variant.desc.encoding) if variant.desc.encoding in PRIO else len(PRIO)
            unique = 0 if variant.desc.encoding != "S" else i
            key = variant.desc.imm_size(opsize//8), enc_prio, unique
            if key not in dedup:
                dedup[key] = variant
        mnemonics[mnem, opsize, ots] = [dedup[k] for k in sorted(dedup.keys())]

    return dict(mnemonics)

def encode_table(entries, args):
    mnemonics = encode_mnems(entries)
    mnemonics["NOP", 0, ""] = [EncodeVariant(Opcode.parse("90"), InstrDesc.parse("NP - - - - NOP"))]
    mnem_map = {}
    alt_table = [0] # first entry is unused
    for (mnem, opsize, ots), variants in mnemonics.items():
        supports_high_regs = []
        if variants[0][1].mnemonic in ("MOVSX", "MOVZX") or opsize == 8:
            # Should be the same for all variants
            desc = variants[0][1]
            for i, (ot, op) in enumerate(zip(ots, desc.operands)):
                if ot == "r" and op.kind == "GP" and op.abssize(opsize//8) == 1:
                    supports_high_regs.append(i)

        alt_indices = [i + len(alt_table) for i in range(len(variants) - 1)] + [0]
        enc_opcs = []
        for alt, variant in zip(alt_indices, variants):
            opcode, desc = variant.opcode, variant.desc
            opc_i = opcode.opc
            if None not in opcode.modrm:
                opc_i |= 0xc000 | opcode.modrm[1] << 11 | opcode.modrm[2] << 8
            elif opcode.modrm[1] is not None:
                opc_i |= opcode.modrm[1] << 8
            if opcode.modrm == ("m", None, 4):
                opc_i |= 0x2000000000 # FORCE_SIB
            opc_i |= opcode.escape * 0x10000
            opc_i |= 0x80000 if opcode.prefix == "66" or opsize == 16 else 0
            opc_i |= 0x100000 if opcode.prefix == "F2" else 0
            opc_i |= 0x200000 if opcode.prefix == "F3" else 0
            opc_i |= 0x400000 if opcode.rexw == "1" else 0
            if opcode.prefix == "LOCK":
                opc_i |= 0x800000
            elif opcode.vex == 1:
                opc_i |= 0x1000000 + 0x800000 * int(opcode.vexl or 0)
            elif opcode.vex == 2: # TODO-EVEX
                opc_i |= 0x2000000 + 0x800000 * int(opcode.vexl or 0)
            opc_i |= 0x8000000 if "VSIB" in desc.flags else 0
            if alt >= 0x100:
                raise Exception("encode alternate bits exhausted")
            opc_i |= sum(1 << i for i in supports_high_regs) << 45
            opc_i |= desc.imm_size(opsize//8) << 47
            opc_i |= ["NP", "M", "R",
                "M1", "MI", "MC", "MR", "RM", "RMA", "MRI", "RMI", "MRC",
                "AM", "MA", "I", "IA", "O", "OI", "OA", "S", "A", "D", "FD", "TD",
                "RVM", "RVMI", "RVMR", "RMV", "VM", "VMI", "MVR", "MRV",
            ].index(desc.encoding) << 51
            opc_i |= alt << 56
            enc_opcs.append(opc_i)
        mnem_map[f"FE_{mnem}"] = enc_opcs[0]
        alt_table += enc_opcs[1:]

    mnem_tab = "".join(f"#define {m} {v:#x}\n" for m, v in mnem_map.items())
    alt_tab = "".join(f"[{i}] = {v:#x},\n" for i, v in enumerate(alt_table))
    return mnem_tab, alt_tab

def unique(it):
    vals = set(it)
    if len(vals) != 1:
        raise Exception(f"multiple values: {vals}")
    return next(iter(vals))

def encode2_gen_legacy(variant: EncodeVariant, opsize: int, supports_high_regs: list[int]) -> str:
    opcode = variant.opcode
    desc = variant.desc
    flags = ENCODINGS[variant.desc.encoding]
    code = "  {\n"
    code += "  unsigned rex = 0; (void) rex;\n"

    for i in supports_high_regs:
        code += f"  if (op_reg_idx(op{i}) >= 4 && op_reg_idx(op{i}) <= 15) rex = 0x40;\n"
    if opcode.rexw == "1":
        code += f"  rex |= 0x48;\n"
    if flags.modrm_idx:
        if opcode.modrm[0] == "m":
            code += f"  if (op_mem_base(op{flags.modrm_idx^3})&8) rex |= 0x41;\n"
            code += f"  if (op_mem_idx(op{flags.modrm_idx^3})&8) rex |= 0x42;\n"
        elif desc.operands[flags.modrm_idx^3].kind in ("GP", "XMM"):
            code += f"  if (op_reg_idx(op{flags.modrm_idx^3})&8) rex |= 0x41;\n"
        if flags.modreg_idx:
            if desc.operands[flags.modreg_idx^3].kind in ("GP", "XMM", "CR", "DR"):
                code += f"  if (op_reg_idx(op{flags.modreg_idx^3})&8) rex |= 0x44;\n"
    elif flags.modreg_idx: # O encoding
        if desc.operands[flags.modreg_idx^3].kind in ("GP", "XMM"):
            code += f"  if (op_reg_idx(op{flags.modreg_idx^3})&8) rex |= 0x41;\n"

    for i in supports_high_regs:
        code += f"  if (rex && op_reg_gph(op{i})) return 0;\n"

    if opcode.prefix == "LOCK":
        code += f"  buf[idx++] = 0xF0;\n"
    if opsize == 16 or opcode.prefix == "66":
        code += "  buf[idx++] = 0x66;\n"
    if opcode.prefix in ("F2", "F3"):
        code += f"  buf[idx++] = 0x{opcode.prefix};\n"
    code += f"  if (rex) buf[idx++] = rex;\n"
    if opcode.escape:
        code += f"  buf[idx++] = 0x0F;\n"
        if opcode.escape == 2:
            code += f"  buf[idx++] = 0x38;\n"
        elif opcode.escape == 3:
            code += f"  buf[idx++] = 0x3A;\n"
    code += f"  buf[idx++] = {opcode.opc:#x};\n"
    if None not in opcode.modrm:
        opcext = 0xc0 | opcode.modrm[1] << 3 | opcode.modrm[2]
        code += f"  buf[idx++] = {opcext:#x};\n"

    if flags.modrm:
        if flags.modreg_idx:
            modreg = f"op_reg_idx(op{flags.modreg_idx^3})"
        else:
            modreg = opcode.modrm[1] or 0
        if opcode.modrm[0] == "m":
            imm_size_expr = "imm_size" if flags.imm_control >= 2 else 0
            assert "VSIB" not in desc.flags
            assert opcode.modrm[2] is None
            modrm = f"op{flags.modrm_idx^3}"
            code += f"  unsigned memoff = enc_mem(buf, idx, {modrm}, {modreg}, {imm_size_expr}, 0);\n"
            code += f"  if (!memoff) return 0;\n  idx += memoff;\n"
        else:
            if flags.modrm_idx:
                modrm = f"op_reg_idx(op{flags.modrm_idx^3})"
            else:
                modrm = f"{opcode.modrm[2] or 0}"
            code += f"  buf[idx++] = 0xC0|(({modreg}&7)<<3)|({modrm}&7);\n"
    elif flags.modrm_idx:
        code += f"  buf[idx-1] |= op_reg_idx(op{flags.modrm_idx^3}) & 7;\n"
    return code + "  }\n"

def encode2_gen_vex(variant: EncodeVariant) -> str:
    opcode = variant.opcode
    flags = ENCODINGS[variant.desc.encoding]
    code = "  unsigned vexoff;\n"

    helperopc = opcode.opc << 16
    helperopc |= ["NP", "66", "F3", "F2"].index(opcode.prefix) << 8
    helperopc |= 0x8000 if opcode.rexw == "1" else 0
    helperopc |= 0x0004 if opcode.vexl == "1" else 0
    helperopc |= opcode.escape << 10
    if flags.modreg_idx:
        modreg = f"op_reg_idx(op{flags.modreg_idx^3})"
    else:
        modreg = opcode.modrm[1] or 0
    vexop = f"op_reg_idx(op{flags.vexreg_idx^3})" if flags.vexreg_idx else 0
    if not flags.modrm and opcode.modrm == (None, None, None):
        # No ModRM, prefix only (VZEROUPPER/VZEROALL)
        code += f"  vexoff = enc_vex_common(buf+idx, {helperopc:#x}, 0, 0, 0, 0);\n"
    elif opcode.modrm[0] == "m":
        imm_size_expr = "imm_size" if flags.imm_control >= 2 else 0
        memfn = "enc_vex_mem_vsib" if "VSIB" in variant.desc.flags else "enc_vex_mem"
        assert opcode.modrm[2] in (None, 4)
        forcesib = 1 if opcode.modrm[2] == 4 else 0 # AMX
        modrm = f"op{flags.modrm_idx^3}"
        code += (f"  vexoff = {memfn}(buf+idx, {helperopc:#x}, {modrm}, " +
                 f"{modreg}, {vexop}, {imm_size_expr}, {forcesib});\n")
    else:
        if flags.modrm_idx:
            modrm = f"op_reg_idx(op{flags.modrm_idx^3})"
        else:
            modrm = f"{opcode.modrm[2] or 0}"
        code += f"  vexoff = enc_vex_reg(buf+idx, {helperopc:#x}, {modrm}, {modreg}, {vexop});\n"
    code += f"  if (!vexoff) return 0;\n  idx += vexoff;\n"
    return code

def encode2_table(entries, args):
    mnemonics = encode_mnems(entries)

    enc_decls, enc_code = "", ""
    for (mnem, opsize, ots), variants in mnemonics.items():
        max_imm_size = max(v.desc.imm_size(opsize//8) for v in variants)

        supports_high_regs = []
        if variants[0].desc.mnemonic in ("MOVSX", "MOVZX") or opsize == 8:
            # Should be the same for all variants
            for i, (ot, op) in enumerate(zip(ots, variants[0].desc.operands)):
                if ot == "r" and op.kind == "GP" and op.abssize(opsize//8) == 1:
                    supports_high_regs.append(i)
        supports_vsib = unique("VSIB" in v.desc.flags for v in variants)
        opkinds = unique(tuple(op.kind for op in v.desc.operands) for v in variants)

        OPKIND_LUT = {"FPU": "ST", "SEG": "SREG", "MMX": "MM"}
        reg_tys = [OPKIND_LUT.get(opkind, opkind) for opkind in opkinds]

        fnname = f"fe64_{mnem}{'_impl' if supports_high_regs else ''}"
        op_tys = [{
            "i": f"int{max_imm_size*8 if max_imm_size != 3 else 32}_t",
            "a": "uintptr_t",
            "r": f"FeReg{reg_ty if i not in supports_high_regs else 'GPLH'}",
            "m": "FeMem" if not supports_vsib else "FeMemV",
            "o": "const void*",
        }[ot] for i, (ot, reg_ty) in enumerate(zip(ots, reg_tys))]
        fn_opargs = "".join(f", {ty} op{i}" for i, ty in enumerate(op_tys))
        fn_sig = f"unsigned {fnname}(uint8_t* buf, int flags{fn_opargs})"
        enc_decls += f"{fn_sig};\n"
        if supports_high_regs:
            enc_decls += f"#define fe64_{mnem}(buf, flags"
            enc_decls += "".join(f", op{i}" for i in range(len(op_tys)))
            enc_decls += f") {fnname}(buf, flags"
            enc_decls += "".join(f", FE_MAKE_GPLH(op{i})" if i in supports_high_regs else f", op{i}" for i in range(len(op_tys)))
            enc_decls += f")\n"

        code = f"{fn_sig} {{\n"

        code += "  unsigned idx = 0;\n"
        if max_imm_size or "a" in ots:
            code += "  int64_t imm; unsigned imm_size;\n"
        code += "  (void) flags;\n"

        neednext = True
        for i, variant in enumerate(variants):
            opcode, desc = variant.opcode, variant.desc
            if not neednext:
                break
            if i > 0:
                code += f"\nnext{i-1}:\n"
            neednext = False

            imm_size = desc.imm_size(opsize//8)
            flags = ENCODINGS[desc.encoding]
            # Select usable encoding.
            if desc.encoding == "S":
                # Segment encoding is weird.
                code += f"  if (op_reg_idx(op0)!={(opcode.opc>>3)&0x7:#x}) goto next{i};\n"
                neednext = True
            if desc.mnemonic == "XCHG_NOP" and opsize == 32:
                # XCHG eax, eax must not be encoded as 90 -- that'd be NOP.
                code += f"  if (op_reg_idx(op0)==0&&op_reg_idx(op1)==0) goto next{i};\n"
                neednext = True
            if flags.vexreg_idx and not opcode.vex: # vexreg w/o vex is zeroreg
                code += f"  if (op_reg_idx(op{flags.vexreg_idx^3})!={flags.zeroreg_val}) goto next{i};\n"
                neednext = True
            if flags.imm_control:
                if flags.imm_control != 3:
                    code += f"  imm = (int64_t) op{flags.imm_idx^3};\n"
                else:
                    code += f"  imm = op_reg_idx(op{flags.imm_idx^3}) << 4;\n"
                code += f"  imm_size = {imm_size};\n"
                if flags.imm_control == 1:
                    code += f"  if (imm != 1) goto next{i};\n"
                    neednext = True
                if flags.imm_control == 2:
                    code += "  imm_size = flags & FE_ADDR32 ? 4 : 8;\n"
                    code += "  if (imm_size == 4) imm = (int32_t) imm;\n"
                if imm_size < max_imm_size and 2 <= flags.imm_control < 6:
                    code += f"  if (!op_imm_n(imm, imm_size)) goto next{i};\n"
                    neednext = True
                if flags.imm_control == 6:
                    # idx is subtracted below.
                    code += f"  imm -= (int64_t) buf + imm_size;\n"
                    if i != len(variants) - 1: # only Jcc+JMP
                        code += f"  if (flags&FE_JMPL) goto next{i};\n"
                        # assume one-byte opcode without escape/prefixes
                        code += f"  if (!op_imm_n(imm-1, imm_size)) goto next{i};\n"
                        neednext = True

            if opcode.modrm[0] == "m" or "USEG" in desc.flags:
                # segment override without addrsize override shouldn't happen
                assert opcode.modrm[0] == "m" or "U67" in desc.flags
                code += "  if (UNLIKELY(flags & (FE_SEG_MASK|FE_ADDR32))) idx += enc_seg67(buf+idx, flags);\n"
            elif "U67" in desc.flags:
                # STOS, SCAS, JCXZ, LOOP, LOOPcc
                code += "  if (UNLIKELY(flags & FE_ADDR32)) buf[idx++] = 0x67;\n"

            if opcode.vex == 2:
                assert False
            elif opcode.vex == 1:
                code += encode2_gen_vex(variant)
            else:
                code += encode2_gen_legacy(variant, opsize, supports_high_regs)

            if flags.imm_control >= 2:
                if flags.imm_control == 6:
                    code += f"  imm -= idx;\n"
                code += f"  if (enc_imm(buf+idx, imm, imm_size)) return 0;\n"
                code += f"  idx += imm_size;\n"
            code += f"  return idx;\n"

        if neednext:
            code += f"next{len(variants)-1}: return 0;\n"
        code += "}\n"

        enc_code += code

    return enc_decls, enc_code


if __name__ == "__main__":
    generators = {
        "decode": decode_table,
        "encode": encode_table,
        "encode2": encode2_table,
    }

    parser = argparse.ArgumentParser()
    parser.add_argument("--32", dest="modes", action="append_const", const=32)
    parser.add_argument("--64", dest="modes", action="append_const", const=64)
    parser.add_argument("--with-undoc", action="store_true")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("mode", choices=generators.keys())
    parser.add_argument("table", type=argparse.FileType('r'))
    parser.add_argument("out_public", type=argparse.FileType('w'))
    parser.add_argument("out_private", type=argparse.FileType('w'))
    args = parser.parse_args()

    entries = []
    for line in args.table.read().splitlines():
        if not line or line[0] == "#": continue
        line, weak = (line, False) if line[0] != "*" else (line[1:], True)
        opcode_string, desc_string = tuple(line.split(maxsplit=1))
        opcode, desc = Opcode.parse(opcode_string), InstrDesc.parse(desc_string)
        verifyOpcodeDesc(opcode, desc)
        if "UNDOC" not in desc.flags or args.with_undoc:
            entries.append((weak, opcode, desc))

    res_public, res_private = generators[args.mode](entries, args)
    args.out_public.write(res_public)
    args.out_private.write(res_private)

#!/usr/bin/python3

import argparse
from binascii import unhexlify
from collections import OrderedDict, defaultdict, namedtuple, Counter
from copy import copy
from enum import Enum, IntEnum
from itertools import accumulate, product
import struct
from typing import NamedTuple, FrozenSet, List, Tuple, Union, Optional, ByteString

def bitstruct(name, fields):
    names, sizes = zip(*(field.split(":") for field in fields))
    sizes = tuple(map(int, sizes))
    offsets = (0,) + tuple(accumulate(sizes))
    class __class:
        def __init__(self, **kwargs):
            for name in names:
                setattr(self, name, kwargs.get(name, 0))
        def _encode(self, length):
            enc = 0
            for name, size, offset in zip(names, sizes, offsets):
                enc += (getattr(self, name) & ((1 << size) - 1)) << offset
            return enc.to_bytes(length, "little")
    __class.__name__ = name
    return __class

InstrFlags = bitstruct("InstrFlags", [
    "modrm_idx:2",
    "modreg_idx:2",
    "vexreg_idx:2",
    "zeroreg_idx:2",
    "imm_idx:2",
    "zeroreg_val:1",
    "lock:1",
    "imm_control:3",
    "vsib:1",
    "op0_size:2",
    "op1_size:2",
    "op2_size:2",
    "op3_size:2",
    "size8:1",
    "sized64:1",
    "size_fix1:3",
    "size_fix2:2",
    "instr_width:1",
    "op0_regty:3",
    "op1_regty:3",
    "op2_regty:3",
    "_unused:7",
])

ENCODINGS = {
    "NP": InstrFlags(),
    "M": InstrFlags(modrm_idx=0^3),
    "M1": InstrFlags(modrm_idx=0^3, imm_idx=1^3, imm_control=1),
    "MI": InstrFlags(modrm_idx=0^3, imm_idx=1^3, imm_control=4),
    "MC": InstrFlags(modrm_idx=0^3, zeroreg_idx=1^3, zeroreg_val=1),
    "MR": InstrFlags(modrm_idx=0^3, modreg_idx=1^3),
    "RM": InstrFlags(modrm_idx=1^3, modreg_idx=0^3),
    "RMA": InstrFlags(modrm_idx=1^3, modreg_idx=0^3, zeroreg_idx=2^3),
    "MRI": InstrFlags(modrm_idx=0^3, modreg_idx=1^3, imm_idx=2^3, imm_control=4),
    "RMI": InstrFlags(modrm_idx=1^3, modreg_idx=0^3, imm_idx=2^3, imm_control=4),
    "MRC": InstrFlags(modrm_idx=0^3, modreg_idx=1^3, zeroreg_idx=2^3, zeroreg_val=1),
    "I": InstrFlags(imm_idx=0^3, imm_control=4),
    "IA": InstrFlags(zeroreg_idx=0^3, imm_idx=1^3, imm_control=4),
    "O": InstrFlags(modreg_idx=0^3),
    "OI": InstrFlags(modreg_idx=0^3, imm_idx=1^3, imm_control=4),
    "OA": InstrFlags(modreg_idx=0^3, zeroreg_idx=1^3),
    "AO": InstrFlags(modreg_idx=1^3, zeroreg_idx=0^3),
    "A": InstrFlags(zeroreg_idx=0^3),
    "D": InstrFlags(imm_idx=0^3, imm_control=6),
    "FD": InstrFlags(zeroreg_idx=0^3, imm_idx=1^3, imm_control=2),
    "TD": InstrFlags(zeroreg_idx=1^3, imm_idx=0^3, imm_control=2),

    "RVM": InstrFlags(modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3),
    "RVMI": InstrFlags(modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3, imm_idx=3^3, imm_control=4, imm_byte=1),
    "RVMR": InstrFlags(modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3, imm_idx=3^3, imm_control=3, imm_byte=1),
    "RMV": InstrFlags(modrm_idx=1^3, modreg_idx=0^3, vexreg_idx=2^3),
    "VM": InstrFlags(modrm_idx=1^3, vexreg_idx=0^3),
    "VMI": InstrFlags(modrm_idx=1^3, vexreg_idx=0^3, imm_idx=2^3, imm_control=4, imm_byte=1),
    "MVR": InstrFlags(modrm_idx=0^3, modreg_idx=2^3, vexreg_idx=1^3),
}

class OpKind(NamedTuple):
    size: int
    kind: str

    SZ_OP = -1
    SZ_VEC = -2
    K_MEM = "mem"
    K_IMM = "imm"

    def abssize(self, opsz=None, vecsz=None):
        res = opsz if self.size == self.SZ_OP else \
              vecsz if self.size == self.SZ_VEC else self.size
        if res is None:
            raise Exception("unspecified operand size")
        return res

OPKINDS = {
    # sizeidx (0, fixedsz, opsz, vecsz), fixedsz (log2), regtype
    "IMM": OpKind(OpKind.SZ_OP, OpKind.K_IMM),
    "IMM8": OpKind(1, OpKind.K_IMM),
    "IMM16": OpKind(2, OpKind.K_IMM),
    "IMM32": OpKind(4, OpKind.K_IMM),
    "GP": OpKind(OpKind.SZ_OP, "GP"),
    "GP8": OpKind(1, "GP"),
    "GP16": OpKind(2, "GP"),
    "GP32": OpKind(4, "GP"),
    "GP64": OpKind(8, "GP"),
    "MMX": OpKind(8, "MMX"),
    "XMM": OpKind(OpKind.SZ_VEC, "XMM"),
    "XMM8": OpKind(1, "XMM"),
    "XMM16": OpKind(2, "XMM"),
    "XMM32": OpKind(4, "XMM"),
    "XMM64": OpKind(8, "XMM"),
    "XMM128": OpKind(16, "XMM"),
    "XMM256": OpKind(32, "XMM"),
    "SREG": OpKind(2, "SEG"),
    "FPU": OpKind(10, "FPU"),
    "MEM": OpKind(OpKind.SZ_OP, OpKind.K_MEM),
    "MEMV": OpKind(OpKind.SZ_VEC, OpKind.K_MEM),
    "MEMZ": OpKind(0, OpKind.K_MEM),
    "MEM8": OpKind(1, OpKind.K_MEM),
    "MEM16": OpKind(2, OpKind.K_MEM),
    "MEM32": OpKind(4, OpKind.K_MEM),
    "MEM64": OpKind(8, OpKind.K_MEM),
    "MEM128": OpKind(16, OpKind.K_MEM),
    "MASK8": OpKind(1, "MASK"),
    "MASK16": OpKind(2, "MASK"),
    "MASK32": OpKind(4, "MASK"),
    "MASK64": OpKind(8, "MASK"),
    "BND": OpKind(0, "BND"),
    "CR": OpKind(0, "CR"),
    "DR": OpKind(0, "DR"),
}

class InstrDesc(NamedTuple):
    mnemonic: str
    encoding: str
    operands: Tuple[str, ...]
    flags: FrozenSet[str]

    OPKIND_REGTYS = {"GP": 0, "FPU": 1, "XMM": 2, "MASK": 3, "MMX": 4, "BND": 5}
    OPKIND_SIZES = {
        0: 0, 1: 1, 2: 2, 4: 3, 8: 4, 16: 5, 32: 6, 10: 0,
        OpKind.SZ_OP: -2, OpKind.SZ_VEC: -3,
    }

    @classmethod
    def parse(cls, desc):
        desc = desc.split()
        operands = tuple(OPKINDS[op] for op in desc[1:5] if op != "-")
        return cls(desc[5], desc[0], operands, frozenset(desc[6:]))

    def encode(self):
        flags = copy(ENCODINGS[self.encoding])

        opsz = set(self.OPKIND_SIZES[opkind.size] for opkind in self.operands)

        # Sort fixed sizes encodable in size_fix2 as second element.
        fixed = sorted((x for x in opsz if x >= 0), key=lambda x: 1 <= x <= 4)
        if len(fixed) > 2 or (len(fixed) == 2 and not (1 <= fixed[1] <= 4)):
            raise Exception("invalid fixed operand sizes: %r"%fixed)
        sizes = (fixed + [1, 1])[:2] + [-2, -3] # See operand_sizes in decode.c.
        flags.size_fix1 = sizes[0]
        flags.size_fix2 = sizes[1] - 1

        for i, opkind in enumerate(self.operands):
            sz = self.OPKIND_SIZES[opkind.size]
            reg_type = self.OPKIND_REGTYS.get(opkind.kind, 7)
            setattr(flags, "op%d_size"%i, sizes.index(sz))
            if i < 3:
                setattr(flags, "op%d_regty"%i, reg_type)
            elif reg_type not in (7, 2):
                raise Exception("invalid regty for op 3, must be VEC")

        # Miscellaneous Flags
        if "DEF64" in self.flags:       flags.sized64 = 1
        if "SIZE_8" in self.flags:      flags.size8 = 1
        if "INSTR_WIDTH" in self.flags: flags.instr_width = 1
        if "LOCK" in self.flags:        flags.lock = 1
        if "VSIB" in self.flags:        flags.vsib = 1

        if flags.imm_control >= 4:
            imm_op = next(op for op in self.operands if op.kind == OpKind.K_IMM)
            if ("IMM_8" in self.flags or imm_op.size == 1 or
                (imm_op.size == OpKind.SZ_OP and flags.size8)):
                flags.imm_control |= 1

        enc = flags._encode(6)
        enc = tuple(int.from_bytes(enc[i:i+2], "little") for i in range(0, 6, 2))
        # First 2 bytes are the mnemonic, last 6 bytes are the encoding.
        return ("FDI_"+self.mnemonic,) + enc

class EntryKind(Enum):
    NONE = 0
    INSTR = 1
    TABLE256 = 2
    TABLE8 = 3
    TABLE72 = 4
    TABLE_PREFIX = 5
    TABLE_VEX = 6
    TABLE_PREFIX_REP = 7
    TABLE_ROOT = -1

class TrieEntry(NamedTuple):
    kind: EntryKind
    items: Tuple[Optional[str]]
    payload: Tuple[Union[int, str]]

    TABLE_LENGTH = {
        EntryKind.TABLE256: 256,
        EntryKind.TABLE8: 8,
        EntryKind.TABLE72: 72,
        EntryKind.TABLE_PREFIX: 4,
        EntryKind.TABLE_VEX: 4,
        EntryKind.TABLE_PREFIX_REP: 4,
        EntryKind.TABLE_ROOT: 8,
    }
    @classmethod
    def table(cls, kind):
        return cls(kind, (None,) * cls.TABLE_LENGTH[kind], ())
    @classmethod
    def instr(cls, payload):
        return cls(EntryKind.INSTR, (), payload)

    @property
    def encode_length(self):
        return len(self.payload) + len(self.items)
    def encode(self, encode_item) -> Tuple[Union[int, str]]:
        enc_items = (encode_item(item) if item else 0 for item in self.items)
        return self.payload + tuple(enc_items)

    def map(self, map_func):
        mapped_items = (map_func(i, v) for i, v in enumerate(self.items))
        return TrieEntry(self.kind, tuple(mapped_items), self.payload)
    def update(self, idx, new_val):
        return self.map(lambda i, v: new_val if i == idx else v)

import re
opcode_regex = re.compile(
    r"^(?:(?P<prefixes>(?P<vex>VEX\.)?(?P<legacy>NP|66|F2|F3)\." +
                     r"(?:W(?P<rexw>[01]|IG)\.)?(?:L(?P<vexl>[01]|IG)\.)?)" +
        r"|R(?P<repprefix>NP|F2|F3).)?" +
     r"(?P<opcode>(?:[0-9a-f]{2})+)" +
     r"(?P<modrm>//?[0-7]|//[c-f][0-9a-f])?" +
     r"(?P<extended>\+)?$")

class Opcode(NamedTuple):
    prefix: Union[None, Tuple[bool, str]] # (False, NP/66/F2/F3), (True, NP/F2/F3)
    escape: int # [0, 0f, 0f38, 0f3a]
    opc: int
    opcext: Union[None, Tuple[bool, int]] # (False, T8), (True, T72), None
    extended: bool # Extend opc or opcext, if present
    vex: bool
    vexl: Union[str, None] # 0, 1, IG, None = used, both
    rexw: Union[str, None] # 0, 1, IG, None = used, both

    @classmethod
    def parse(cls, opcode_string):
        match = opcode_regex.match(opcode_string)
        if match is None:
            return None

        opcext = match.group("modrm")
        if opcext:
            is72 = opcext[1] == "/"
            opcext = is72, int(opcext[1 + is72:], 16)

        if match.group("extended") and opcext and not opcext[0]:
            raise Exception("invalid opcode extension: {}".format(opcode_string))

        prefix_strs = match.group("legacy"), match.group("repprefix")
        prefix = prefix_strs[0] or prefix_strs[1]
        if prefix:
            prefix = prefix_strs[1] is not None, ["NP", "66", "F3", "F2"].index(prefix)

        return cls(
            prefix=prefix,
            escape=["", "0f", "0f38", "0f3a"].index(match.group("opcode")[:-2]),
            opc=int(match.group("opcode")[-2:], 16),
            opcext=opcext,
            extended=match.group("extended") is not None,
            vex=match.group("vex") is not None,
            vexl=match.group("vexl"),
            rexw=match.group("rexw"),
        )

    def for_trie(self):
        opcode = []
        opcode.append((EntryKind.TABLE_ROOT, [self.escape | self.vex << 2]))
        opcode.append((EntryKind.TABLE256, [self.opc]))
        if self.opcext:
            opcext_kind = [EntryKind.TABLE8, EntryKind.TABLE72][self.opcext[0]]
            opcext_val = self.opcext[1] - (0 if self.opcext[1] < 8 else 0xb8)
            opcode.append((opcext_kind, [opcext_val]))
        if self.extended:
            last_type, last_indices = opcode[-1]
            opcode[-1] = last_type, [last_indices[0] + i for i in range(8)]
        if self.prefix:
            prefix_kind = [EntryKind.TABLE_PREFIX, EntryKind.TABLE_PREFIX_REP][self.prefix[0]]
            prefix_val = self.prefix[1]
            opcode.append((prefix_kind, [prefix_val]))
        if self.vexl in ("0", "1") or self.rexw in ("0", "1"):
            rexw = {"0": [0], "1": [1<<0], "IG": [0, 1<<0]}[self.rexw or "IG"]
            vexl = {"0": [0], "1": [1<<1], "IG": [0, 1<<1]}[self.vexl or "IG"]
            entries = list(map(sum, product(rexw, vexl)))
            opcode.append((EntryKind.TABLE_VEX, entries))

        kinds, values = zip(*opcode)
        return [tuple(zip(kinds, prod)) for prod in product(*values)]

def format_opcode(opcode):
    opcode_string = ""
    prefix = ""
    for kind, byte in opcode:
        if kind == EntryKind.TABLE_ROOT:
            opcode_string += ["", "0f", "0f38", "0f3a"][byte & 3]
            prefix += ["", "VEX."][byte >> 2]
        elif kind == EntryKind.TABLE256:
            opcode_string += "{:02x}".format(byte)
        elif kind in (EntryKind.TABLE8, EntryKind.TABLE72):
            opcode_string += "/{:x}".format(byte)
        elif kind == EntryKind.TABLE_PREFIX:
            if byte & 4:
                prefix += "VEX."
            prefix += ["NP.", "66.", "F3.", "F2."][byte&3]
        elif kind == EntryKind.TABLE_PREFIX_REP:
            prefix += ["RNP.", "??.", "RF3.", "RF2."][byte&3]
        elif kind == EntryKind.TABLE_VEX:
            prefix += "W{}.L{}.".format(byte & 1, byte >> 1)
        else:
            raise Exception("unsupported opcode kind {}".format(kind))
    return prefix + opcode_string

class Table:
    def __init__(self, root_count=1):
        self.data = OrderedDict()
        self.roots = ["root%d"%i for i in range(root_count)]
        for i in range(root_count):
            self.data["root%d"%i] = TrieEntry.table(EntryKind.TABLE_ROOT)
        self.offsets = {}
        self.annotations = {}

    def _update_table(self, name, idx, entry_name, entry_val):
        # Don't override existing entries. This only happens on invalid input,
        # e.g. when an opcode is specified twice.
        if self.data[name].items[idx]:
            raise Exception("{}/{} set, not overriding to {}".format(name, idx, entry_name))
        self.data[entry_name] = entry_val
        self.data[name] = self.data[name].update(idx, entry_name)

    def add_opcode(self, opcode, instr_encoding, root_idx=0):
        name = "t{},{}".format(root_idx, format_opcode(opcode))

        tn = "root%d"%root_idx
        for i in range(len(opcode) - 1):
            # kind is the table kind that we want to point to in the _next_.
            kind, byte = opcode[i+1][0], opcode[i][1]
            # Retain prev_tn name so that we can update it.
            prev_tn, tn = tn, self.data[tn].items[byte]
            if tn is None:
                tn = "t{},{}".format(root_idx, format_opcode(opcode[:i+1]))
                self._update_table(prev_tn, byte, tn, TrieEntry.table(kind))

            if self.data[tn].kind != kind:
                raise Exception("{}, have {}, want {}".format(
                                name, self.data[tn].kind, kind))

        self._update_table(tn, opcode[-1][1], name, TrieEntry.instr(instr_encoding))

    def deduplicate(self):
        synonyms = True
        while synonyms:
            entries = {} # Mapping from entry to name
            synonyms = {} # Mapping from name to unique name
            for name, entry in self.data.items():
                if entry in entries:
                    synonyms[name] = entries[entry]
                else:
                    entries[entry] = name
            for name, entry in self.data.items():
                self.data[name] = entry.map(lambda _, v: synonyms.get(v, v))
            for key in synonyms:
                del self.data[key]

    def calc_offsets(self):
        current = 0
        for name, entry in self.data.items():
            self.annotations[current] = "%s(%d)" % (name, entry.kind.value)
            self.offsets[name] = current
            current += (entry.encode_length + 3) & ~3
        if current >= 0x8000:
            raise Exception("maximum table size exceeded: {:x}".format(current))

    def encode_item(self, name):
        return (self.offsets[name] << 1) | self.data[name].kind.value

    def compile(self):
        self.calc_offsets()
        ordered = sorted((off, self.data[k]) for k, off in self.offsets.items())

        data = ()
        for off, entry in ordered:
            data += (0,) * (off - len(data)) + entry.encode(self.encode_item)

        stats = dict(Counter(entry.kind for entry in self.data.values()))
        print("%d bytes" % (2*len(data)), stats)
        return data, self.annotations, [self.offsets[k] for k in self.roots]

def bytes_to_table(data, notes):
    strdata = tuple(d+"," if type(d) == str else "%#04x,"%d for d in data)
    offs = [0] + sorted(notes.keys()) + [len(data)]
    return "\n".join("".join(strdata[p:c]) + "\n//%04x "%c + notes.get(c, "")
                     for p, c in zip(offs, offs[1:]))

template = """// Auto-generated file -- do not modify!
#if defined(FD_DECODE_TABLE_DATA)
{hex_table}
#elif defined(FD_DECODE_TABLE_STRTAB1)
{mnemonic_cstr}
#elif defined(FD_DECODE_TABLE_STRTAB2)
{mnemonic_offsets}
#elif defined(FD_DECODE_TABLE_DEFINES)
{defines}
#else
#error "unspecified decode table"
#endif
"""

def encode_table(entries):
    mnemonics = defaultdict(list)
    mnemonics["FE_NOP"].append(("NP", 0, 0, "0x90"))
    for opcode, desc in entries:
        if desc.mnemonic[:9] == "RESERVED_":
            continue
        if "ONLY32" in desc.flags or "UNDOC" in desc.flags:
            continue

        opsizes = {8} if "SIZE_8" in desc.flags else {16, 32, 64}
        hasvex, vecsizes = False, {128}

        opc_i = opcode.opc | (opcode.opcext[1] << 8 if opcode.opcext else 0)
        opc_flags = ""
        opc_flags += ["","|OPC_0F","|OPC_0F38","|OPC_0F3A"][opcode.escape]
        if opcode.vex:
            hasvex, vecsizes = True, {128, 256}
            opc_flags += "|OPC_VEX"
        if opcode.prefix:
            opc_flags += ["", "|OPC_66", "|OPC_F3", "|OPC_F2"][opcode.prefix[1]]
            if not opcode.prefix[0]: opsizes -= {16}
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
        if all(op.size != OpKind.SZ_VEC for op in desc.operands):
            vecsizes = {0} # for VEX-encoded general-purpose instructions.
        if "ENC_NOSZ" in desc.flags:
            opsizes, vecsizes = {0}, {0}

        # Where to put the operand size in the mnemonic
        separate_opsize = "ENC_SEPSZ" in desc.flags
        prepend_opsize = max(opsizes) > 0 and not separate_opsize
        prepend_vecsize = hasvex and max(vecsizes) > 0 and not separate_opsize

        optypes = ["", "", "", ""]
        enc = ENCODINGS[desc.encoding]
        if enc.modrm_idx:
            if "NOMEM" in desc.flags:
                optypes[enc.modrm_idx^3] = "r"
            elif ((opcode.opcext and opcode.opcext[0] and opcode.opcext[1] < 8)
                  or desc.operands[enc.modrm_idx^3].kind == OpKind.K_MEM):
                optypes[enc.modrm_idx^3] = "m"
            else:
                optypes[enc.modrm_idx^3] = "rm"
        if enc.modreg_idx: optypes[enc.modreg_idx^3] = "r"
        if enc.vexreg_idx: optypes[enc.vexreg_idx^3] = "r"
        if enc.zeroreg_idx: optypes[enc.zeroreg_idx^3] = "r"
        if enc.imm_control: optypes[enc.imm_idx^3] = " iariioo"[enc.imm_control]
        optypes = product(*(ot for ot in optypes if ot))

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

            imm_size = 0
            if enc.imm_control >= 4:
                if desc.mnemonic == "ENTER":
                    imm_size = 3
                elif "IMM_8" in desc.flags:
                    imm_size = 1
                else:
                    max_imm_size = 4 if desc.mnemonic != "MOVABS" else 8
                    imm_opsize = desc.operands[enc.imm_idx^3].abssize(opsize//8)
                    imm_size = min(max_imm_size, imm_opsize)

            tys = [] # operands that require special handling
            for ot, op in zip(ots, desc.operands):
                if ot == "m":
                    tys.append(0xf)
                elif op.kind == "GP":
                    tys.append(2 if op.abssize(opsize//8) == 1 else 1)
                else:
                    tys.append({
                        "imm": 0, "SEG": 3, "FPU": 4, "MMX": 5, "XMM": 6,
                        "BND": 8, "CR": 9, "DR": 10,
                    }.get(op.kind, -1))

            tys_i = sum(ty << (4*i) for i, ty in enumerate(tys))
            opc_s = hex(opc_i) + opc_flags + prefix[1]
            if opsize == 16: opc_s += "|OPC_66"
            if opsize == 64 and "DEF64" not in desc.flags: opc_s += "|OPC_REXW"

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
    for mnem, variants in sorted(mnemonics.items()):
        dedup = []
        for variant in variants:
            if not any(x[:3] == variant[:3] for x in dedup):
                dedup.append(variant)

        enc_prio = ["O", "OA", "OI", "IA", "M", "MI", "MR", "RM"]
        dedup.sort(key=lambda e: (e[1], e[0] in enc_prio and enc_prio.index(e[0])))

        indices = [mnem] + [f"FE_MNEM_MAX+{alt_index+i}" for i in range(len(dedup) - 1)]
        alt_list = indices[1:] + ["0"]
        alt_index += len(alt_list) - 1
        for idx, alt, (enc, immsz, tys_i, opc_s) in zip(indices, alt_list, dedup):
            descs += f"[{idx}] = {{ .enc = ENC_{enc}, .immsz = {immsz}, .tys = {tys_i:#x}, .opc = {opc_s}, .alt = {alt} }},\n"

    mnemonics_list = sorted(mnemonics.keys())
    mnemonics_lut = {mnem: mnemonics_list.index(mnem) for mnem in mnemonics_list}
    mnemonics_tab = "\n".join("FE_MNEMONIC(%s,%d)"%entry for entry in mnemonics_lut.items())
    return mnemonics_tab, descs

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--32", dest="modes", action="append_const", const=32)
    parser.add_argument("--64", dest="modes", action="append_const", const=64)
    parser.add_argument("table", type=argparse.FileType('r'))
    parser.add_argument("decode_mnems", type=argparse.FileType('w'))
    parser.add_argument("decode_table", type=argparse.FileType('w'))
    parser.add_argument("encode_mnems", type=argparse.FileType('w'))
    parser.add_argument("encode_table", type=argparse.FileType('w'))
    args = parser.parse_args()

    entries = []
    for line in args.table.read().splitlines():
        if not line or line[0] == "#": continue
        opcode_string, desc = tuple(line.split(maxsplit=1))
        entries.append((Opcode.parse(opcode_string), InstrDesc.parse(desc)))

    mnemonics = sorted({desc.mnemonic for _, desc in entries})
    mnemonics_lut = {name: mnemonics.index(name) for name in mnemonics}

    decode_mnems_lines = ["FD_MNEMONIC(%s,%d)"%e for e in mnemonics_lut.items()]
    args.decode_mnems.write("\n".join(decode_mnems_lines))

    modes = [32, 64]
    table = Table(root_count=len(args.modes))
    for opcode, desc in entries:
        for i, mode in enumerate(args.modes):
            if "ONLY%d"%(96-mode) not in desc.flags:
                for opcode_path in opcode.for_trie():
                    table.add_opcode(opcode_path, desc.encode(), i)

    table.deduplicate()
    table_data, annotations, root_offsets = table.compile()

    mnemonic_tab = [0]
    for name in mnemonics:
        mnemonic_tab.append(mnemonic_tab[-1] + len(name) + 1)
    mnemonic_cstr = '"' + "\\0".join(mnemonics) + '"'

    defines = ["FD_TABLE_OFFSET_%d %d"%k for k in zip(args.modes, root_offsets)]

    decode_table = template.format(
        hex_table=bytes_to_table(table_data, annotations),
        mnemonic_cstr=mnemonic_cstr,
        mnemonic_offsets=",".join(str(off) for off in mnemonic_tab),
        defines="\n".join("#define " + line for line in defines),
    )
    args.decode_table.write(decode_table)

    fe_mnem_list, fe_code = encode_table(entries)
    args.encode_mnems.write(fe_mnem_list)
    args.encode_table.write(fe_code)

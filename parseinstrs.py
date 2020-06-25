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
    "op0_size:2",
    "op1_size:2",
    "op2_size:2",
    "op3_size:2",
    "imm_idx:2",
    "zeroreg_val:1",
    "_unused:1",
    "imm_control:3",
    "_unused:1",
    "gp_size_8:1",
    "gp_size_def64:1",
    "gp_instr_width:1",
    "gp_fixed_operand_size:3",
    "lock:1",
    "vsib:1",
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

OPKIND_LOOKUP = {
    # sizeidx (0, fixedsz, opsz, vecsz), fixedsz (log2), regtype
    "-": (0, 0, 7),
    "IMM": (2, 0, 7),
    "IMM8": (1, 0, 7),
    "IMM16": (1, 1, 7),
    "IMM32": (1, 2, 7),
    "GP": (2, 0, 0),
    "GP8": (1, 0, 0),
    "GP16": (1, 1, 0),
    "GP32": (1, 2, 0),
    "GP64": (1, 3, 0),
    "MMX": (1, 3, 4),
    "XMM": (3, 0, 2),
    "XMM8": (1, 0, 2),
    "XMM16": (1, 1, 2),
    "XMM32": (1, 2, 2),
    "XMM64": (1, 3, 2),
    "XMM128": (1, 4, 2),
    "XMM256": (1, 5, 2),
    "SREG": (0, 0, 7),
    "FPU": (0, 0, 1),
    "MEMZ": (0, 0, 7),
    "MEM8": (1, 0, 7),
    "MEM16": (1, 1, 7),
    "MEM32": (1, 2, 7),
    "MEM64": (1, 3, 7),
    "BND": (0, 0, 5),
    "CR": (0, 0, 7),
    "DR": (0, 0, 7),
}

class InstrDesc(NamedTuple):
    mnemonic: str
    encoding: str
    operands: Tuple[str, ...]
    flags: FrozenSet[str]

    @classmethod
    def parse(cls, desc):
        desc = desc.split()
        operands = tuple(op for op in desc[1:5] if op != "-")
        return cls(desc[5], desc[0], operands, frozenset(desc[6:]))

    def encode(self):
        flags = copy(ENCODINGS[self.encoding])

        fixed_opsz = set()
        for i, opkind in enumerate(self.operands):
            enc_size, fixed_size, reg_type = OPKIND_LOOKUP[opkind]
            if enc_size == 1: fixed_opsz.add(fixed_size)
            setattr(flags, "op%d_size"%i, enc_size)
            if i < 3:
                setattr(flags, "op%d_regty"%i, reg_type)
            elif reg_type not in (7, 2):
                raise Exception("invalid regty for op 3, must be VEC")

        if fixed_opsz: flags.gp_fixed_operand_size = next(iter(fixed_opsz))

        # Miscellaneous Flags
        if "DEF64" in self.flags:       flags.gp_size_def64 = 1
        if "SIZE_8" in self.flags:      flags.gp_size_8 = 1
        if "INSTR_WIDTH" in self.flags: flags.gp_instr_width = 1
        if "IMM_8" in self.flags:       flags.imm_control = {4: 5, 6: 7}[flags.imm_control]
        if "LOCK" in self.flags:        flags.lock = 1
        if "VSIB" in self.flags:        flags.vsib = 1
        if "MUSTMEM" in self.flags:     setattr(flags, "op%d_regty"%(flags.modrm_idx^3), 0xf)

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
opcode_regex = re.compile(r"^(?:(?P<prefixes>(?P<vex>VEX\.)?(?P<legacy>NP|66|F2|F3)\.(?P<rexw>W[01]\.)?(?P<vexl>L[01]\.)?)|R(?P<repprefix>NP|F2|F3).)?(?P<opcode>(?:[0-9a-f]{2})+)(?P<modrm>//?[0-7]|//[c-f][0-9a-f])?(?P<extended>\+)?$")

def parse_opcode(opcode_string):
    """
    Parse opcode string into list of type-index tuples.
    """
    match = opcode_regex.match(opcode_string)
    if match is None:
        raise Exception("invalid opcode: '%s'" % opcode_string)

    opcode = []
    opcode_bytes = unhexlify(match.group("opcode"))

    idx = [b"", b"\x0f", b"\x0f\x38", b"\x0f\x3a"].index(opcode_bytes[:-1])
    if match.group("vex"):
        idx |= 4
    opcode.append((EntryKind.TABLE_ROOT, [idx]))
    opcode.append((EntryKind.TABLE256, [opcode_bytes[-1]]))

    opcext = match.group("modrm")
    if opcext:
        if opcext[1] == "/":
            opcext = int(opcext[2:], 16)
            if not (0 <= opcext <= 7) and not (0xc0 <= opcext <= 0xff):
                raise Exception("invalid opcext range: {}".format(opcode_string))
            if opcext >= 0xc0:
                opcext -= 0xb8
            opcode.append((EntryKind.TABLE72, [opcext]))
        else:
            opcode.append((EntryKind.TABLE8, [int(opcext[1:], 16)]))

    if match.group("extended"):
        last_type, last_indices = opcode[-1]
        if (last_type not in (EntryKind.TABLE256, EntryKind.TABLE72) or
               len(last_indices) != 1 or last_indices[0] & 7 != 0):
            raise Exception("invalid opcode duplication: {}".format(opcode_string))

        opcode[-1] = last_type, [last_indices[0] + i for i in range(8)]

    if match.group("prefixes"):
        legacy = {"NP": 0, "66": 1, "F3": 2, "F2": 3}[match.group("legacy")]
        opcode.append((EntryKind.TABLE_PREFIX, [legacy]))

        if match.group("vexl") or match.group("rexw"):
            rexw = match.group("rexw")
            rexw = [0, 1<<0] if not rexw else [1<<0] if "W1" in rexw else [0]
            vexl = match.group("vexl")
            vexl = [0, 1<<1] if not vexl else [1<<1] if "L1" in vexl else [0]

            entries = list(map(sum, product(rexw, vexl)))
            opcode.append((EntryKind.TABLE_VEX, entries))
    elif match.group("repprefix"):
        rep = {"NP": 0, "F3": 2, "F2": 3}[match.group("repprefix")]
        opcode.append((EntryKind.TABLE_PREFIX_REP, [rep]))

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
#elif defined(FD_DECODE_TABLE_MNEMONICS)
{mnemonic_list}
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--32", dest="modes", action="append_const", const=32)
    parser.add_argument("--64", dest="modes", action="append_const", const=64)
    parser.add_argument("table", type=argparse.FileType('r'))
    parser.add_argument("output", type=argparse.FileType('w'))
    args = parser.parse_args()

    entries = []
    for line in args.table.read().splitlines():
        if not line or line[0] == "#": continue
        opcode_string, desc = tuple(line.split(maxsplit=1))
        for opcode in parse_opcode(opcode_string):
            entries.append((opcode, InstrDesc.parse(desc)))

    mnemonics = sorted({desc.mnemonic for _, desc in entries})
    mnemonics_lut = {name: mnemonics.index(name) for name in mnemonics}

    modes = [32, 64]
    table = Table(root_count=len(args.modes))
    for opcode, desc in entries:
        for i, mode in enumerate(args.modes):
            if "ONLY%d"%(96-mode) not in desc.flags:
                table.add_opcode(opcode, desc.encode(), i)

    table.deduplicate()
    table_data, annotations, root_offsets = table.compile()

    mnemonic_tab = [0]
    for name in mnemonics:
        mnemonic_tab.append(mnemonic_tab[-1] + len(name) + 1)
    mnemonic_cstr = '"' + "\\0".join(mnemonics) + '"'

    defines = ["FD_TABLE_OFFSET_%d %d"%k for k in zip(args.modes, root_offsets)]

    file = template.format(
        hex_table=bytes_to_table(table_data, annotations),
        mnemonic_list="\n".join("FD_MNEMONIC(%s,%d)"%entry for entry in mnemonics_lut.items()),
        mnemonic_cstr=mnemonic_cstr,
        mnemonic_offsets=",".join(str(off) for off in mnemonic_tab),
        defines="\n".join("#define " + line for line in defines),
    )
    args.output.write(file)

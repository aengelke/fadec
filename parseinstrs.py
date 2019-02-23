#!/usr/bin/python3

from binascii import unhexlify
from collections import OrderedDict, defaultdict, namedtuple
from copy import copy
from enum import Enum, IntEnum
from itertools import accumulate
import struct
import sys

def bitstruct(name, fields):
    names, sizes = zip(*(field.split(":") for field in fields))
    sizes = tuple(map(int, sizes))
    offsets = (0,) + tuple(accumulate(sizes))
    class __class:
        def __init__(self, **kwargs):
            for name in names:
                setattr(self, name, kwargs.get(name, 0))
        def _encode(self):
            return sum((getattr(self, name) & ((1 << size) - 1)) << offset
                for name, size, offset in zip(names, sizes, offsets))
    __class.__name__ = name
    __class._encode_size = offsets[-1]
    return __class

InstrFlags = bitstruct("InstrFlags", [
    "modrm_idx:2",
    "modreg_idx:2",
    "vexreg_idx:2",
    "zeroreg_idx:2",
    "operand_sizes:8",
    "imm_idx:2",
    "imm_size:2",
    "imm_control:3",
    "imm_byte:1",
    "gp_size_8:1",
    "gp_size_def64:1",
    "gp_instr_width:1",
    "gp_fixed_operand_size:3",
])
assert InstrFlags._encode_size <= 32

ENCODINGS = {
    "NP": InstrFlags(),
    "M": InstrFlags(modrm_idx=0^3),
    "M1": InstrFlags(modrm_idx=0^3, imm_idx=1^3, imm_control=1),
    "MI": InstrFlags(modrm_idx=0^3, imm_idx=1^3, imm_control=3),
    "MR": InstrFlags(modrm_idx=0^3, modreg_idx=1^3),
    "RM": InstrFlags(modrm_idx=1^3, modreg_idx=0^3),
    "RMA": InstrFlags(modrm_idx=1^3, modreg_idx=0^3, zeroreg_idx=2^3),
    "MRI": InstrFlags(modrm_idx=0^3, modreg_idx=1^3, imm_idx=2^3, imm_control=3),
    "RMI": InstrFlags(modrm_idx=1^3, modreg_idx=0^3, imm_idx=2^3, imm_control=3),
    "I": InstrFlags(imm_idx=0^3, imm_control=3),
    "IA": InstrFlags(zeroreg_idx=0^3, imm_idx=1^3, imm_control=3),
    "O": InstrFlags(modreg_idx=0^3),
    "OI": InstrFlags(modreg_idx=0^3, imm_idx=1^3, imm_control=3),
    "OA": InstrFlags(modreg_idx=0^3, zeroreg_idx=1^3),
    "AO": InstrFlags(modreg_idx=1^3, zeroreg_idx=0^3),
    "D": InstrFlags(imm_idx=0^3, imm_control=4),
    "FD": InstrFlags(zeroreg_idx=0^3, imm_idx=1^3, imm_control=2),
    "TD": InstrFlags(zeroreg_idx=1^3, imm_idx=0^3, imm_control=2),

    "RVM": InstrFlags(modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3),
    "RVMI": InstrFlags(modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3, imm_idx=3^3, imm_control=3, imm_byte=1),
    "RVMR": InstrFlags(modrm_idx=2^3, modreg_idx=0^3, vexreg_idx=1^3, imm_idx=3^3, imm_control=5, imm_byte=1),
    "RMV": InstrFlags(modrm_idx=1^3, modreg_idx=0^3, vexreg_idx=2^3),
    "VM": InstrFlags(modrm_idx=1^3, vexreg_idx=0^3),
    "VMI": InstrFlags(modrm_idx=1^3, vexreg_idx=0^3, imm_idx=2^3, imm_control=3, imm_byte=1),
    "MVR": InstrFlags(modrm_idx=0^3, modreg_idx=2^3, vexreg_idx=1^3),
}

OPKIND_LOOKUP = {
    "-": (0, 0),
    "IMM": (2, 0),
    "IMM8": (1, 0),
    "IMM16": (1, 1),
    "IMM32": (1, 2),
    "GP": (2, 0),
    "GP8": (1, 0),
    "GP16": (1, 1),
    "GP32": (1, 2),
    "GP64": (1, 3),
    "XMM": (3, 0),
    "XMM8": (1, 0),
    "XMM16": (1, 1),
    "XMM32": (1, 2),
    "XMM64": (1, 3),
    "XMM128": (1, 4),
    "XMM256": (1, 5),
    "SREG": (0, 0),
    "FPU": (0, 0),
}

class InstrDesc(namedtuple("InstrDesc", "mnemonic,flags,encoding")):
    __slots__ = ()
    @classmethod
    def parse(cls, desc):
        desc = desc.split()

        fixed_opsz = set()
        opsizes = 0
        for i, opkind in enumerate(desc[1:5]):
            enc_size, fixed_size = OPKIND_LOOKUP[opkind]
            if enc_size == 1: fixed_opsz.add(fixed_size)
            opsizes |= enc_size << 2 * i

        flags = copy(ENCODINGS[desc[0]])
        flags.operand_sizes = opsizes
        if fixed_opsz: flags.gp_fixed_operand_size = next(iter(fixed_opsz))

        # Miscellaneous Flags
        if "DEF64" in desc[6:]:       flags.gp_size_def64 = 1
        if "SIZE_8" in desc[6:]:      flags.gp_size_8 = 1
        if "INSTR_WIDTH" in desc[6:]: flags.gp_instr_width = 1
        if "IMM_8" in desc[6:]:       flags.imm_byte = 1

        return cls(desc[5], frozenset(desc[6:]), flags._encode())

class EntryKind(Enum):
    NONE = 0
    INSTR = 1
    TABLE256 = 2
    TABLE8 = 3
    TABLE72 = 4
    TABLE_PREFIX = 5

    @property
    def table_length(self):
        return {
            EntryKind.INSTR: 0,
            EntryKind.TABLE256: 256,
            EntryKind.TABLE8: 8,
            EntryKind.TABLE72: 72,
            EntryKind.TABLE_PREFIX: 16
        }[self]

import re
opcode_regex = re.compile(r"^(?P<prefixes>(?P<vex>VEX\.)?(?P<legacy>NP|66|F2|F3)\.(?P<rexw>W[01]\.)?(?P<vexl>L[01]\.)?)?(?P<opcode>(?:[0-9a-f]{2})+)(?P<modrm>//?[0-7]|//[c-f][0-9a-f])?(?P<extended>\+)?$")

def parse_opcode(opcode_string):
    """
    Parse opcode string into list of type-index tuples.
    """
    match = opcode_regex.match(opcode_string)
    if match is None:
        raise Exception("invalid opcode: '%s'" % opcode_string)

    extended = match.group("extended") is not None

    opcode = [(EntryKind.TABLE256, x) for x in unhexlify(match.group("opcode"))]

    opcext = match.group("modrm")
    if opcext:
        if opcext[1] == "/":
            opcext = int(opcext[2:], 16)
            assert (0 <= opcext <= 7) or (0xc0 <= opcext <= 0xff)
            if opcext >= 0xc0:
                opcext -= 0xb8
            opcode.append((EntryKind.TABLE72, opcext))
        else:
            opcode.append((EntryKind.TABLE8, int(opcext[1:], 16)))

    if match.group("prefixes"):
        assert not extended

        legacy = {"NP": 0, "66": 1, "F3": 2, "F2": 3}[match.group("legacy")]
        entry = legacy | ((1 << 3) if match.group("vex") else 0)

        if match.group("vexl"):
            print("ignored mandatory VEX.L prefix for:", opcode_string)

        rexw = match.group("rexw")
        if not rexw:
            return [tuple(opcode) + ((EntryKind.TABLE_PREFIX, entry),),
                    tuple(opcode) + ((EntryKind.TABLE_PREFIX, entry | (1 << 2)),)]

        entry |= (1 << 2) if "W1" in rexw else 0
        return [tuple(opcode) + ((EntryKind.TABLE_PREFIX, entry),)]

    if not extended:
        return [tuple(opcode)]

    last_type, last_index = opcode[-1]
    assert last_type in (EntryKind.TABLE256, EntryKind.TABLE72)
    assert last_index & 7 == 0

    common_prefix = tuple(opcode[:-1])
    return [common_prefix + ((last_type, last_index + i),) for i in range(8)]

class Table:
    def __init__(self, root_count=1):
        self.data = OrderedDict()
        for i in range(root_count):
            self.data["root%d"%i] = (EntryKind.TABLE256, [None] * 256)

    def compile(self, mnemonics_lut):
        offsets = {}
        annotations = {}
        currentOffset = 0
        stats = defaultdict(int)
        for name, (kind, _) in self.data.items():
            annotations[currentOffset] = "%s(%d)" % (name, kind.value)
            offsets[name] = currentOffset
            stats[kind] += 1
            if kind.table_length:
                currentOffset += kind.table_length * 2
            else:
                currentOffset += 6
            currentOffset = (currentOffset + 7) & ~7
            assert currentOffset < 0x10000

        data = b""
        for name, (kind, value) in self.data.items():
            if len(data) < offsets[name]:
                data += b"\0" * (offsets[name] - len(data))
            assert len(data) == offsets[name]
            if kind == EntryKind.INSTR:
                mnemonicIdx = mnemonics_lut[value[0]]
                data += struct.pack("<HL", mnemonicIdx, value[1])
            else: # Table
                # count = sum(1 for x in value if x is not None)
                # print("Table of kind", kind, "with %d/%d entries"%(count, kind.table_length))
                for i, entry in enumerate(value):
                    if entry is not None:
                        targetKind, _ = self.data[entry]
                        value = (offsets[entry] & ~7) | targetKind.value
                    else:
                        value = 0
                    data += struct.pack("<H", value)

        print("%d bytes" % len(data), stats)
        return data, annotations

    def deduplicate(self):
        # Make values hashable
        for n, (k, v) in self.data.items():
            self.data[n] = k, tuple(v)
        synonyms = True
        while synonyms:
            entries = {} # Mapping from entry to name
            synonyms = {} # Mapping from name to unique name
            for name, entry in self.data.items():
                if entry in entries:
                    synonyms[name] = entries[entry]
                else:
                    entries[entry] = name
            for name, (kind, value) in self.data.items():
                if kind != EntryKind.INSTR:
                    self.data[name] = kind, tuple(synonyms.get(v, v) for v in value)
            for key in synonyms:
                del self.data[key]

    def add_opcode(self, opcode, instrData, root_idx=0):
        opcode = list(opcode) + [(None, None)]
        opcode = [(opcode[i+1][0], opcode[i][1]) for i in range(len(opcode)-1)]

        name, table = "t%d"%root_idx, self.data["root%d"%root_idx]
        for kind, byte in opcode[:-1]:
            if table[1][byte] is None:
                name += "{:02x}".format(byte)
                self.data[name] = kind, [None] * kind.table_length
                table[1][byte] = name
            else:
                name = table[1][byte]
            table = self.data[name]
            assert table[0] == kind

        # An opcode can occur once only.
        assert table[1][opcode[-1][1]] is None

        name += "{:02x}/{}".format(opcode[-1][1], instrData[0])
        table[1][opcode[-1][1]] = name
        self.data[name] = EntryKind.INSTR, instrData

def wrap(string):
    return "\n".join(string[i:i+80] for i in range(0, len(string), 80))

def bytes_to_table(data, notes):
    hexdata = ",".join("0x{:02x}".format(byte) for byte in data)
    offs = [0] + sorted(notes.keys()) + [len(data)]
    return "\n".join(wrap(hexdata[p*5:c*5]) + "\n//%04x "%c + notes.get(c, "")
                     for p, c in zip(offs, offs[1:]))

template = """// Auto-generated file -- do not modify!
#if defined(FD_DECODE_TABLE_DATA_32)
{hex_table32}
#elif defined(FD_DECODE_TABLE_DATA_64)
{hex_table64}
#elif defined(FD_DECODE_TABLE_MNEMONICS)
{mnemonic_list}
#elif defined(FD_DECODE_TABLE_STRTAB1)
{mnemonic_cstr}
#elif defined(FD_DECODE_TABLE_STRTAB2)
{mnemonic_offsets}
#else
#error "unspecified decode table"
#endif
"""

if __name__ == "__main__":
    entries = defaultdict(list)
    with open(sys.argv[1], "r") as f:
        for line in f.read().splitlines():
            if line and line[0] != "#":
                opcode_string, desc = tuple(line.split(maxsplit=1))
                for opcode in parse_opcode(opcode_string):
                    entries[opcode].append(InstrDesc.parse(desc))

    mnemonics = set()
    table32 = Table()
    table64 = Table()
    masks = "ONLY64", "ONLY32"
    for opcode, descs in entries.items():
        for table, ignore_mask in zip((table32, table64), masks):
            parsed = [desc for desc in descs if ignore_mask not in desc.flags]
            assert len(parsed) <= 1
            if parsed:
                mnemonics.add(parsed[0].mnemonic)
                table.add_opcode(opcode, (parsed[0].mnemonic, parsed[0].encoding))

    table32.deduplicate()
    table64.deduplicate()

    mnemonics = sorted(mnemonics)
    mnemonics_lut = {name: mnemonics.index(name) for name in mnemonics}

    mnemonic_tab = [0]
    for name in mnemonics:
        mnemonic_tab.append(mnemonic_tab[-1] + len(name) + 1)
    mnemonic_cstr = '"' + "\\0".join(mnemonics) + '"'

    file = template.format(
        hex_table32=bytes_to_table(*table32.compile(mnemonics_lut)),
        hex_table64=bytes_to_table(*table64.compile(mnemonics_lut)),
        mnemonic_list="\n".join("FD_MNEMONIC(%s,%d)"%entry for entry in mnemonics_lut.items()),
        mnemonic_cstr=mnemonic_cstr,
        mnemonic_offsets=",".join(str(off) for off in mnemonic_tab),
    )

    with open(sys.argv[2], "w") as f:
        f.write(file)

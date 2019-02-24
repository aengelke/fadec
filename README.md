# Fadec — Fast Decoder for x86-32 and x86-64

Fadec is a fast and lightweight decoder for x86-32 and x86-64. To meet the goal of speed, lookup tables are used to map the opcode the (internal) description of the instruction encoding. This table currently has a size of roughly 19.5 kiB (for 32/64-bit combined).

*Note: This is not a disassembler, it does not intend to produce valid assembly.*

### Key features

**Q: Why not just just use any other decoder available out there?**
A: Because I needed to embed a small and fast decoder in a project which didn't link against a libc.

- **Small size:** the compiled library uses only 40 kiB and the main decode routine is only a few hundreds lines of code.
- **Performance:** Fadec is significantly times faster than libopcodes or Capstone due to the absence of high-level abstractions and the small lookup table.
- **Almost no dependencies:** the formatter only uses the function `snprintf`, the decoder itself has no dependencies, making it suitable for environments without a full libc or `malloc`-style memory allocation.
- **Correctness:** even corner cases should be handled correctly (if not, that's a bug), e.g., the order of prefixes, the presence of the `lock` prefix, or properly handling VEX.W in 32-bit mode.

### Basic Usage
```c
FdInstr instr;
// Decode from buffer in 64-bit mode and virtual address 0x401000
int ret = fd_decode(buffer, sizeof(buffer), 64, 0x401000, &instr);
// ret<0 indicates an error, ret>0 the number of decoded bytes
// Relevant properties of instructions can now be queries using the FD_* macros.
```

### Intended differences
To achieve higher performance, minor differences to other decoders exist, requiring special handling.

- The registers `ah`/... and `spl`/... have the same number (as in machine code). Distinguishing them is possible using `FD_OP_REG_HIGH`.
- The decoded operand sizes are not always exact. However, the exact size can be reconstructed in all cases.
    - For instructions with rare memory access sizes (e.g. `lgdt`), the provided size is zero. These are: `cmpxchg16b`, `cmpxchg8b`, `fbld` (for 80-bit), `fbstp` (for 80-bit), `fldenv`, `frstor`, `fsave`, `fstenv`, `fstp` (for 80-bit), `fxrstor`, `fxsave`, `lds`, `lds`, `lgdt`, `lidt`, `lldt`, `ltr`, `sgdt`, `sidt`, `sldt`, `str`
    - For some SSE/AVX instructions, the operand size is an over-approximation of the real size, e.g. for permutations or extensions.
    - The operand size of segment and FPU registers is always zero.
- An implicit `fwait` in FPU instructions is decoded as a separate instruction (matching the opcode layout in machine code). For example:
    - `finit` is decoded as `FD_FWAIT` + `FD_FINIT`
    - `fninit` is decoded as plain `FD_FINIT`
- For `scas` and `cmps`, the `repz` prefix can be queried using `FD_HAS_REP` (matching prefix byte in machine code).
- The instructions `bsf`/`tzcnt` and `bsr`/`lzcnt` can only be distinguished by the presence of a `rep` prefix (matching the machine code encoding). Note that on older processors `tzcnt`/`lzcnt` are executed as plain `rep bsf`/`rep bsr`.
- The instructions `movbe`/`crc32` can only be distinguished by the presence of a `repnz` prefix.

### Known issues
- MMX instructions are not supported yet.
- The AVX VSIB encoding is not supported yet, all instructions using this will result in a decode error.
- The EVEX prefix (AVX-512) is not supported (yet).
- The layout of entries in the tables can be improved to improve usage of caches. (Help needed.)
- No Python API.
- Low test coverage. (Help needed.)
- No benchmarking has been performed yet. (Help needed.)
- Prefixes for indirect jumps and calls are not properly decoded, e.g. `notrack`, `bnd`. This requires additional information on the prefix ordering, which is currently not decoded. (Analysis of performance impact and help needed.)

If you find any other issues, please report a bug. Or, even better, send a patch fixing the issue.

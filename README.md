# Fadec — Fast Decoder for x86-32 and x86-64 and Encoder for x86-64

Fadec is a fast and lightweight decoder for x86-32 and x86-64. To meet the goal of speed, lookup tables are used to map the opcode the (internal) description of the instruction encoding. This table currently has a size of roughly 24 kiB (for 32/64-bit combined).

Fadec-Enc (or Faenc) is a small, lightweight and easy-to-use encoder, currently for x86-64 only.

## Key features

> **Q: Why not just use any other decoding/encoding library available out there?**
>
> A: I needed to embed a small and fast decoder in a project for a freestanding environment (i.e., no libc). Further, only very few plain encoding libraries are available for x86-64; and most of them are large or make heavy use of external dependencies.

- **Small size:** the entire library with a x86-64/32 decoder and a x86-64 encoder uses only 80 kiB; for specific use cases, the size can be reduced even further. The main decode/encode routines are only a few hundreds lines of code.
- **Performance:** Fadec is significantly faster than libopcodes or Capstone due to the absence of high-level abstractions and the small lookup table.
- **Zero dependencies:** the entire library has no dependencies, even on the standard library, making it suitable for freestanding environments without a full libc or `malloc`-style memory allocation.
- **Correctness:** even corner cases should be handled correctly (if not, that's a bug), e.g., the order of prefixes, immediate sizes of jump instructions, the presence of the `lock` prefix, or properly handling VEX.W in 32-bit mode.

All components of this library target the Intel 64 implementations of x86. While AMD64 is _mostly similar_, there are some minor differences (e.g. operand sizes for jump instructions, more instructions, `cr8` can be accessed with `lock` prefix) which are currently not handled.

## Decoder Usage

### Example
```c
uint8_t buffer[] = {0x49, 0x90};
FdInstr instr;
// Decode from buffer into instr in 64-bit mode.
int ret = fd_decode(buffer, sizeof(buffer), 64, 0, &instr);
// ret<0 indicates an error, ret>0 the number of decoded bytes
// Relevant properties of instructions can now be queried using the FD_* macros.
// Or, we can format the instruction to a string buffer:
char fmtbuf[64];
fd_format(instr, fmtbuf, sizeof(fmtbuf));
// fmtbuf now reads: "xchg r8, rax"
```

### API

The API consists of two functions to decode and format instructions, as well as several accessor macros. A full documentation can be found in [fadec.h](fadec.h). Direct access of any structure fields is not recommended.

- `int fd_decode(const uint8_t* buf, size_t len, int mode, uintptr_t address, FdInstr* out_instr)`
    - Decode a single instruction. For internal performance reasons, note that:
        - The decoded operand sizes are not always exact. However, the exact size can be reconstructed in all cases.
        - An implicit `fwait` in FPU instructions is decoded as a separate instruction (matching the opcode layout in machine code). For example, `finit` is decoded as `FD_FWAIT` + `FD_FINIT`
    - Return value: number of bytes used, or a negative value in case of an error.
    - `buf`/`len`: buffer containing instruction bytes. At most 15 bytes will be read. If the instruction is longer than `len`, an error value is returned.
    - `mode`: architecture mode, either `32` or `64`.
    - `address`: set to `0`. (Obsolete use: virtual address of the decoded instruction.)
    - `out_instr`: Pointer to the instruction buffer, might get written partially in case of an error.
- `void fd_format(const FdInstr* instr, char* buf, size_t len)`
    - Format a single instruction to a human-readable format.
    - `instr`: decoded instruction.
    - `buf`/`len`: buffer for formatted instruction string
- Various accessor macros: see [fadec.h](fadec.h).

## Encoder Usage

### Example

```c
int failed = 0;
uint8_t buf[64];
uint8_t* cur = buf;

// xor eax, eax
failed |= fe_enc64(&cur, FE_XOR32rr, FE_AX, FE_AX);
// movzx ecx, byte ptr [rdi + 1*rax + 0]
failed |= fe_enc64(&cur, FE_MOVZXr32m8, FE_CX, FE_MEM(FE_DI, 1, FE_AX, 0));
// test ecx, ecx
failed |= fe_enc64(&cur, FE_TEST32rr, FE_CX, FE_CX);
// jz $
// This will be replaced later FE_JMPL enforces use of longest offset
uint8_t* fwd_jmp = cur;
failed |= fe_enc64(&cur, FE_JNZ|FE_JMPL, (intptr_t) cur);
uint8_t* loop_tgt = cur;
// add rax, rcx
failed |= fe_enc64(&cur, FE_ADD64rr, FE_AX, FE_CX);
// sub ecx, 1
failed |= fe_enc64(&cur, FE_SUB32ri, FE_CX, 1);
// jnz loop_tgt
failed |= fe_enc64(&cur, FE_JNZ, (intptr_t) loop_tgt);
// Update previous jump to jump here. Note that we _must_ specify FE_JMPL too.
failed |= fe_enc64(&fwd_jmp, FE_JNZ|FE_JMPL, (intptr_t) cur);
// ret
failed |= fe_enc64(&cur, FE_RET);
// cur now points to the end of the buffer, failed indicates any failures.
```

### API

The API consists of one function to handle encode requests, as well as some macros. More information can be found in [fadec-enc.h](fadec-enc.h). Usage of internals like enum values is not recommended.

- `int fe_enc64(uint8_t** buf, uint64_t mnem, int64_t operands...)`
    - Encodes an instruction for x86-64 into `*buf`.
    - Return value: `0` on success, a negative value in error cases.
    - `buf`: Pointer to the pointer to the instruction buffer. The pointer (`*buf`) will be advanced by the number of bytes written. The instruction buffer must have at least 15 bytes left.
    - `mnem`: Instruction mnemonic to encode combined with extra flags:
        - `FE_SEG(segreg)`: override segment to specified segment register.
        - `FE_ADDR32`: override address size to 32-bit.
        - `FE_JMPL`: use longest possible offset encoding, useful when jump target is not known.
    - `operands...`: Up to 4 instruction operands. The operand kinds must match the requirements of the mnemonic.
        - For register operands, use the register: `FE_AX`, `FE_AH`, `FE_XMM12`.
        - For immediate operands, use the constant: `12`, `-0xbeef`.
        - For memory operands, use: `FE_MEM(basereg,scale,indexreg,offset)`. Use `0` to specify _no register_. For RIP-relative addressing, the size of the instruction is added automatically.
        - For offset operands, specify the target address.

## Known issues
- The encoder doesn't support VEX encodings (yet).
- The EVEX prefix (AVX-512) is not supported (yet).
- Prefixes for indirect jumps and calls are not properly decoded, e.g. `notrack`, `bnd`.
- Low test coverage. (Help needed.)
- No Python API.

If you find any other issues, please report a bug. Or, even better, send a patch fixing the issue.

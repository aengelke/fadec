# Fadec — Fast Decoder for x86-32 and x86-64 and Encoder for x86-64

Fadec is a fast and lightweight decoder for x86-32 and x86-64. To meet the goal of speed, lookup tables are used to map the opcode the (internal) description of the instruction encoding. This table currently has a size of roughly 37 kiB (for 32/64-bit combined).

Fadec-Enc (or Faenc) is a small, lightweight and easy-to-use encoder, currently for x86-64 only.

## Key features

> **Q: Why not just use any other decoding/encoding library available out there?**
>
> A: I needed to embed a small and fast decoder in a project for a freestanding environment (i.e., no libc). Further, only very few plain encoding libraries are available for x86-64; and most of them are large or make heavy use of external dependencies.

- **Small size:** the entire library with the x86-64/32 decoder and the x86-64 encoder are only 95 kiB; for specific use cases, the size can be reduced even further (e.g., by dropping AVX-512). The main decode/encode routines are only a few hundreds lines of code.
- **Performance:** Fadec is significantly faster than libopcodes, Capstone, or Zydis due to the absence of high-level abstractions and the small lookup table.
- **Zero dependencies:** the entire library has no dependencies, even on the standard library, making it suitable for freestanding environments without a full libc or `malloc`-style memory allocation.
- **Correctness:** even corner cases should be handled correctly (if not, that's a bug), e.g., the order of prefixes, immediate sizes of jump instructions, the presence of the `lock` prefix, or properly handling VEX.W in 32-bit mode.

All components of this library target the Intel 64 implementations of x86. While AMD64 is _mostly similar_, there are some minor differences (e.g. operand sizes for jump instructions, more instructions, `cr8` can be accessed with `lock` prefix, `f34190` is `xchg`, not `pause`) which are currently not handled.

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
fd_format(&instr, fmtbuf, sizeof(fmtbuf));
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

The encoder has two API variants: "v1" has a single entry point (`fe_enc64`) and the instruction is specified as integer parameter. "v2" has one entry point per instruction. v2 is currently about 3x faster than v1, but also has much larger code size (v1: <10 kiB; v2: ~3 MiB) and takes much longer to compile. It is therefore off by default and can be enabled by passing `-Dwith_encode2=true` to Meson. Both variants are supported.

### Example (API v1)

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
// jnz $
// This will be replaced later; FE_JMPL enforces use of longest offset
uint8_t* fwd_jmp = cur;
failed |= fe_enc64(&cur, FE_JNZ|FE_JMPL, (intptr_t) cur);
uint8_t* loop_tgt = cur;
// add rax, rcx
failed |= fe_enc64(&cur, FE_ADD64rr, FE_AX, FE_CX);
// sub ecx, 1
failed |= fe_enc64(&cur, FE_SUB32ri, FE_CX, 1);
// jnz loop_tgt
failed |= fe_enc64(&cur, FE_JNZ, (intptr_t) loop_tgt);
// (alternatively: fe_enc64(&cur, FE_Jcc|FE_CC_NZ, (intptr_t) loop_tgt).)
// Update previous jump to jump here. Note that we _must_ specify FE_JMPL too.
failed |= fe_enc64(&fwd_jmp, FE_JNZ|FE_JMPL, (intptr_t) cur);
// ret
failed |= fe_enc64(&cur, FE_RET);
// cur now points to the end of the buffer, failed indicates any failures.
```

### Example (API v2)

```c
uint8_t buf[64];
uint8_t* cur = buf;

// xor eax, eax
cur += fe64_XOR32rr(cur, 0, FE_AX, FE_AX);
// movzx ecx, byte ptr [rdi + 1*rax + 0]
cur += fe64_MOVZXr32m8(cur, 0, FE_CX, FE_MEM(FE_DI, 1, FE_AX, 0));
// test ecx, ecx
cur += fe64_TEST32rr(cur, 0, FE_CX, FE_CX);
// jnz $
// This will be replaced later; FE_JMPL enforces use of longest offset
uint8_t* fwd_jmp = cur;
cur += fe64_JNZ(cur, FE_JMPL, cur);
uint8_t* loop_tgt = cur;
// add rax, rcx
cur += fe64_ADD64rr(cur, 0, FE_AX, FE_CX);
// sub ecx, 1
cur += fe64_SUB32ri(cur, 0, FE_CX, 1);
// jnz loop_tgt
cur += fe64_JNZ(cur, 0, loop_tgt);
// (alternatively: fe64_Jcc(cur, FE_CC_NZ, loop_tgt).)
// Update previous jump to jump here. Note that we _must_ specify FE_JMPL too.
fe64_JNZ(fwd_jmp, FE_JMPL, cur);
// ret
cur += fe64_RET(cur, 0);
// cur now points to the end of the buffer
// errors are ignored, this example should not cause any :-)
```

### API v1

The API consists of one function to handle encode requests, as well as some macros. More information can be found in [fadec-enc.h](fadec-enc.h). Usage of internals like enum values is not recommended.

- `int fe_enc64(uint8_t** buf, uint64_t mnem, int64_t operands...)`
    - Encodes an instruction for x86-64 into `*buf`. EVEX-encoded instructions will transparently encode with the shorter VEX prefix where permitted.
    - Return value: `0` on success, a negative value in error cases.
    - `buf`: Pointer to the pointer to the instruction buffer. The pointer (`*buf`) will be advanced by the number of bytes written. The instruction buffer must have at least 15 bytes left.
    - `mnem`: Instruction mnemonic to encode combined with extra flags:
        - `FE_SEG(segreg)`: override segment to specified segment register.
        - `FE_ADDR32`: override address size to 32-bit.
        - `FE_JMPL`: use longest possible offset encoding, useful when jump target is not known.
        - `FE_MASK(maskreg)`: specify non-zero mask register (1--7) for instructions that support masking (suffixed with `_mask` or `_maskz`) or require a mask (AVX-512 gather/scatter).
        - `FE_RC_RN/RD/RU/RZ`: set rounding mode for instructions with static rounding control (suffixed `_er`).
        - `FE_CC_O/NO/E/NE/...`: set condition code for instructions with unspecified condition code (`Jcc`, `SETcc`, `CMOVcc`, `CMPccXADD`).
    - `operands...`: Up to 4 instruction operands. The operand kinds must match the requirements of the mnemonic.
        - For register operands (`r`=non-mask register, `k`=mask register), use the register: `FE_AX`, `FE_AH`, `FE_XMM12`.
        - For immediate operands (`i`=regular, `a`=absolute address), use the constant: `12`, `-0xbeef`.
        - For memory operands (`m`=regular or `b`=broadcast), use: `FE_MEM(basereg,scale,indexreg,offset)`. Use `0` to specify _no register_. For RIP-relative addressing, the size of the instruction is added automatically.
        - For offset operands (`o`), specify the target address.

### API v2

The API consists of one function per instruction, as well as some macros. The API provides type safety for different register types as well as for memory operands (regular vs. VSIB). Besides a few details listed here, the usage is very similar to API v1. More information can be found in [fadec-enc2.h](fadec-enc2.h). Usage of internals like enum values is not recommended.

- `int fe64_<mnemonic>(uint8_t* buf, int flags, <operands...>)`
    - Encodes the specified instruction for x86-64 into `buf`. EVEX-encoded instructions will transparently encode with the shorter VEX prefix where permitted.
    - Return value: `0` on failure, otherwise the instruction length.
    - `buf`: Pointer to the instruction buffer. The instruction buffer must have at least 15 bytes left. Bytes beyond the returned instruction length can be overwritten.
    - `flags`: combination of extra flags, default to `0`:
        - `FE_SEG(segreg)`: override segment to specified segment register.
        - `FE_ADDR32`: override address size to 32-bit.
        - `FE_JMPL`: use longest possible offset encoding, useful when jump target is not known.
        - `FE_RC_RN/RD/RU/RZ`: set rounding mode for instructions with static rounding control (suffixed `_er`).
        - `FE_CC_O/NO/E/NE/...`: set condition code for instructions with unspecified condition code (`Jcc`, `SETcc`, `CMOVcc`, `CMPccXADD`).
    - `FeRegMASK opmask` (instructions with opmask only): specify non-zero mask register (1--7) for instructions suffixed with `_mask`/`_maskz` and AVX-512 gather/scatter.
    - `operands...`: up to four instruction operands.
        - Registers have types `FeRegGP`/`FeRegXMM`/`FeRegMASK`/etc.; byte registers accepting high-byte operands also accept `FeRegGPH`.
        - Immediate operands have an appropriately sized integer type.
        - Memory operands use a `FeMem` (VSIB: `FeMemV`) structure, use the macro `FE_MEM(basereg,scale,indexreg,offset)` (VSIB: `FE_MEMV(...)`). Use `FE_NOREG` to specify _no register_. For RIP-relative addressing, the size of the instruction is added automatically.
        - For offset operands (`o`), specify the target address relative to `buf`.
- `int fe64_NOP(uint8_t* buf, unsigned size)`
    - Encode a series of `nop`s of `size` bytes, but at least emit one byte. This will use larger the `nop` encodings to reduce the number of instructions and is intended for filling padding.

## Known issues
- Decoder/Encoder: register uniqueness constraints are not enforced. This affects:
    - VSIB-encoded instructions: no vector register may be used more than once
    - AMX instructions: no tile register may be used more than once
    - AVX-512 complex FP16 multiplication: destination must be not be equal to a source register
- Prefixes for indirect jumps and calls are not properly decoded, e.g. `notrack`, `bnd`.
- Low test coverage. (Help needed.)
- No Python API.

Some ISA extensions are not supported, often because they are deprecated or unsupported by recent hardware. These are unlikely to be implemented in the near future:

- (Intel) MPX: Intel lists MPX as deprecated.
- (Intel) HLE prefixes `xacquire`/`xrelease`: Intel lists HLE as deprecated. The formatter for decoded instructions is able to reconstruct these in most cases, though.
- (Intel) Xeon Phi (KNC/KNL/KNM) extensions, including the MVEX prefix: the hardware is discontinued/no longer available.
- (AMD) XOP: unsupported by newer hardware.
- (AMD) FMA4: unsupported by newer hardware.

If you find any other issues, please report a bug. Or, even better, send a patch fixing the issue.

# libx86decode

A fast and lightweight decoder for x86 and x86-64. *This is not a disassembler, it does not intend to produce valid assembly.* To meet the goal of speed, lookup tables are used to map the opcode the (internal) description of the instruction encoding. This table currently has a size of roughly 21 kiB.

### Known issues
- An implicit `FWAIT` in FPU instructions is decoded as a separate instruction. For example, the instruction `FINIT` is decoded as an `FWAIT` followed by an `FINIT` where as `FNINIT` is decoded as a plain `FINIT` instruction.
- The AVX VSIB encoding is not supported yet, all instructions using this will result in a decode error.
- A mandatory L0 or L1 in the VEX prefix is currently ignored to reduce the size of the prefix tables. The only instructions where this has an effect are `VZEROALL` (L1) and `VZEROUPPER` (L0) and are currently decoded as `VZERO`, the vector length prefix can be used to determine the actual instruction.
- The EVEX prefix (AVX-512) is not supported (yet).
- No ABI stability as the value associated with the mnemonics will change if further instructions are added. When using this library, please link it statically.
- The instruction formatter does not include prefixes. (Help needed.)
- The layout of entries in the tables can be improved to improve usage of caches. (Help needed.)
- Low test coverage. (Help needed.)
- No benchmarking has been performed yet. (Help needed.)
- Prefixes for indirect jumps and calls are not properly decoded, e.g. `notrack`, `bnd`. This requires additional information on the prefix ordering, which is currently not decoded. (Analysis of performance impact and help needed.)

If you find any other issues, please report a bug. Or, even better, send a patch fixing the issue.

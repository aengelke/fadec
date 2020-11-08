
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec.h>


#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

#define FD_DECODE_TABLE_DATA
static __attribute__((aligned(16))) const uint16_t _decode_table[] = {
#include <fadec-table.inc>
};
#undef FD_DECODE_TABLE_DATA

// Defines FD_TABLE_OFFSET_32 and FD_TABLE_OFFSET_64, if available
#define FD_DECODE_TABLE_DEFINES
#include <fadec-table.inc>
#undef FD_DECODE_TABLE_DEFINES

enum DecodeMode {
    DECODE_64 = 0,
    DECODE_32 = 1,
};

typedef enum DecodeMode DecodeMode;

#define ENTRY_NONE 0
#define ENTRY_INSTR 1
#define ENTRY_TABLE256 2
#define ENTRY_TABLE8 3
#define ENTRY_TABLE72 4
#define ENTRY_TABLE_PREFIX 5
#define ENTRY_TABLE_VEX 6
#define ENTRY_TABLE_ROOT 8
#define ENTRY_MASK 7

#define ENTRY_UNPACK(table,kind,entry) do { \
            uint16_t entry_copy = entry; \
            table = &_decode_table[(entry_copy & ~7) >> 1]; \
            kind = entry_copy & ENTRY_MASK; \
        } while (0)

#define LOAD_LE_1(buf) ((size_t) *(uint8_t*) (buf))
#define LOAD_LE_2(buf) (LOAD_LE_1(buf) | LOAD_LE_1((uint8_t*) (buf) + 1)<<8)
#define LOAD_LE_3(buf) (LOAD_LE_2(buf) | LOAD_LE_1((uint8_t*) (buf) + 2)<<16)
#define LOAD_LE_4(buf) (LOAD_LE_2(buf) | LOAD_LE_2((uint8_t*) (buf) + 2)<<16)
#define LOAD_LE_8(buf) (LOAD_LE_4(buf) | LOAD_LE_4((uint8_t*) (buf) + 4)<<32)

enum PrefixSet
{
    PREFIX_LOCK = FD_FLAG_LOCK,
    PREFIX_REP = FD_FLAG_REP,
    PREFIX_REPNZ = FD_FLAG_REPNZ,
    PREFIX_REX = 1 << 8,
    PREFIX_OPSZ = 1 << 13,
    PREFIX_ADDRSZ = 1 << 14,
    PREFIX_REXB = 1 << 15,
    PREFIX_REXX = 1 << 16,
    PREFIX_REXR = 1 << 17,
    PREFIX_REXW = 1 << 18,
    PREFIX_VEXL = 1 << 19,
    PREFIX_VEX = 1 << 20,
};

typedef enum PrefixSet PrefixSet;

static
int
decode_prefixes(const uint8_t* buffer, int len, DecodeMode mode,
                PrefixSet* out_prefixes, uint8_t* out_mandatory,
                uint8_t* out_segment, uint8_t* out_vex_operand,
                int* out_opcode_escape)
{
    int off = 0;
    PrefixSet prefixes = 0;
    PrefixSet rex_prefix = 0;
    int rex_off = -1;

    uint8_t rep = 0;
    *out_mandatory = 0;
    *out_segment = FD_REG_NONE;
    *out_opcode_escape = 0;

    while (LIKELY(off < len))
    {
        uint8_t prefix = buffer[off];
        switch (prefix)
        {
        default: goto out;
        // From segment overrides, the last one wins.
        case 0x26: *out_segment = FD_REG_ES; off++; break;
        case 0x2e: *out_segment = FD_REG_CS; off++; break;
        case 0x36: *out_segment = FD_REG_SS; off++; break;
        case 0x3e: *out_segment = FD_REG_DS; off++; break;
        case 0x64: *out_segment = FD_REG_FS; off++; break;
        case 0x65: *out_segment = FD_REG_GS; off++; break;
        case 0x67: prefixes |= PREFIX_ADDRSZ; off++; break;
        case 0xf0: prefixes |= PREFIX_LOCK;   off++; break;
        case 0x66: prefixes |= PREFIX_OPSZ;   off++; break;
        // From REP/REPE and REPNZ, the last one wins; and for mandatory
        // prefixes they have a higher priority than 66h (handled below).
        case 0xf3: rep = PREFIX_REP;   *out_mandatory = 2; off++; break;
        case 0xf2: rep = PREFIX_REPNZ; *out_mandatory = 3; off++; break;
#if defined(ARCH_X86_64)
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45:
        case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: case 0x4b:
        case 0x4c: case 0x4d: case 0x4e: case 0x4f:
            if (mode != DECODE_64)
                goto out;
            rex_prefix = PREFIX_REX;
            rex_prefix |= prefix & 0x1 ? PREFIX_REXB : 0;
            rex_prefix |= prefix & 0x2 ? PREFIX_REXX : 0;
            rex_prefix |= prefix & 0x4 ? PREFIX_REXR : 0;
            rex_prefix |= prefix & 0x8 ? PREFIX_REXW : 0;
            rex_off = off;
            off++;
            break;
#endif
        case 0xc4: case 0xc5: // VEX
            if (UNLIKELY(off + 1 >= len))
                return FD_ERR_PARTIAL;
            uint8_t byte = buffer[off + 1];
            if (mode == DECODE_32 && (byte & 0xc0) != 0xc0)
                goto out;

            // VEX + 66/F2/F3/LOCK will #UD.
            if (prefixes & (PREFIX_REP|PREFIX_REPNZ|PREFIX_OPSZ|PREFIX_LOCK))
                return FD_ERR_UD;
            // VEX + REX will #UD.
            if (rex_prefix)
                return FD_ERR_UD;

            prefixes |= PREFIX_VEX;
            prefixes |= byte & 0x80 ? 0 : PREFIX_REXR;
            if (prefix == 0xc4) // 3-byte VEX
            {
                prefixes |= byte & 0x40 ? 0 : PREFIX_REXX;
                // SDM Vol 2A 2-15 (Dec. 2016): Ignored in 32-bit mode
                prefixes |= mode == DECODE_64 || (byte & 0x20) ? 0 : PREFIX_REXB;
                *out_opcode_escape = (byte & 0x1f);

                // Load third byte of VEX prefix
                if (UNLIKELY(off + 2 >= len))
                    return FD_ERR_PARTIAL;
                byte = buffer[off + 2];
                // SDM Vol 2A 2-16 (Dec. 2016) says that:
                // - "In 32-bit modes, VEX.W is silently ignored."
                // - VEX.W either replaces REX.W, is don't care or is reserved.
                // This is actually incorrect, there are instructions that
                // use VEX.W as an opcode extension even in 32-bit mode.
                prefixes |= byte & 0x80 ? PREFIX_REXW : 0;
            }
            else // 2-byte VEX
                *out_opcode_escape = 1;
            prefixes |= byte & 0x04 ? PREFIX_VEXL : 0;
            *out_mandatory = byte & 0x03;
            *out_vex_operand = ((byte & 0x78) >> 3) ^ 0xf;

            // VEX prefix is always the last prefix.
            off += prefix == 0xc4 ? 3 : 2;
            goto out;
        }
    }

out:
    // REX prefix is only considered if it is the last prefix.
    if (rex_off == off - 1)
        prefixes |= rex_prefix;

    // If there is no REP/REPNZ prefix and implied opcode extension from a VEX
    // prefix, offer 66h as mandatory prefix. If there is a REP prefix, then the
    // 66h prefix is ignored when evaluating mandatory prefixes.
    if (*out_mandatory == 0 && (prefixes & PREFIX_OPSZ))
        *out_mandatory = 1;
    *out_prefixes = prefixes | rep;

    return off;
}

static
int
decode_modrm(const uint8_t* buffer, int len, DecodeMode mode, FdInstr* instr,
             PrefixSet prefixes, bool vsib, FdOp* out_o1, FdOp* out_o2)
{
    int off = 0;

    if (UNLIKELY(off >= len))
    {
        return FD_ERR_PARTIAL;
    }

    uint8_t modrm = buffer[off++];
    uint8_t mod = (modrm & 0xc0) >> 6;
    uint8_t mod_reg = (modrm & 0x38) >> 3;
    uint8_t rm = modrm & 0x07;

    bool is_seg = UNLIKELY(instr->type == FDI_MOV_G2S || instr->type == FDI_MOV_S2G);
    bool is_cr = UNLIKELY(instr->type == FDI_MOV_CR);
    bool is_dr = UNLIKELY(instr->type == FDI_MOV_DR);

    // Operand 2 may be NULL when reg field is used as opcode extension
    if (out_o2)
    {
        uint8_t reg_idx = mod_reg;
#if defined(ARCH_X86_64)
        if (!is_seg && !UNLIKELY(out_o2->misc == FD_RT_MMX))
            reg_idx += prefixes & PREFIX_REXR ? 8 : 0;
#endif

        if (is_seg && reg_idx >= 6)
            return FD_ERR_UD;
        else if (UNLIKELY(instr->type == FDI_MOV_G2S) && reg_idx == 1)
            return FD_ERR_UD;
        else if (is_cr && (~0x011d >> reg_idx) & 1)
            return FD_ERR_UD;
        else if (is_dr && reg_idx >= 8)
            return FD_ERR_UD;

        out_o2->type = FD_OT_REG;
        out_o2->reg = reg_idx;
        if (is_cr)
            out_o2->misc = FD_RT_CR;
        else if (is_dr)
            out_o2->misc = FD_RT_DR;
        else if (is_seg)
            out_o2->misc = FD_RT_SEG;
    }

    if (mod == 3 || is_cr || is_dr)
    {
        if (out_o1->misc == FD_RT_MEM)
            return FD_ERR_UD;

        uint8_t reg_idx = rm;
#if defined(ARCH_X86_64)
        if (!UNLIKELY(out_o1->misc == FD_RT_MMX || out_o1->misc == FD_RT_MASK))
            reg_idx += prefixes & PREFIX_REXB ? 8 : 0;
#endif
        out_o1->type = FD_OT_REG;
        out_o1->reg = reg_idx;
        return off;
    }

    // VSIB must have a memory operand with SIB byte.
    if (UNLIKELY(vsib) && rm != 4)
        return FD_ERR_UD;

    // SIB byte
    uint8_t scale = 0;
    uint8_t idx = 4;
    uint8_t base = rm;
    if (rm == 4)
    {
        if (UNLIKELY(off >= len))
            return FD_ERR_PARTIAL;
        uint8_t sib = buffer[off++];
        scale = (sib & 0xc0) >> 6;
        idx = (sib & 0x38) >> 3;
#if defined(ARCH_X86_64)
        idx += prefixes & PREFIX_REXX ? 8 : 0;
#endif
        base = sib & 0x07;
    }

    out_o1->type = FD_OT_MEM;
    out_o1->misc = (scale << 6) | (!vsib && idx == 4 ? FD_REG_NONE : idx);

    // RIP-relative addressing only if SIB-byte is absent
    if (mod == 0 && rm == 5 && mode == DECODE_64)
        out_o1->reg = FD_REG_IP;
    else if (mod == 0 && base == 5)
        out_o1->reg = FD_REG_NONE;
    else
        out_o1->reg = base + (prefixes & PREFIX_REXB ? 8 : 0);

    if (mod == 1)
    {
        if (UNLIKELY(off + 1 > len))
            return FD_ERR_PARTIAL;
        instr->disp = (int8_t) LOAD_LE_1(&buffer[off]);
        off += 1;
    }
    else if (mod == 2 || (mod == 0 && base == 5))
    {
        if (UNLIKELY(off + 4 > len))
            return FD_ERR_PARTIAL;
        instr->disp = (int32_t) LOAD_LE_4(&buffer[off]);
        off += 4;
    }
    else
    {
        instr->disp = 0;
    }

    return off;
}

struct InstrDesc
{
    uint16_t type;
    uint8_t operand_indices;
    uint8_t immediate;
    uint16_t operand_sizes;
    uint16_t reg_types;
} __attribute__((packed));

#define DESC_HAS_MODRM(desc) (((desc)->operand_indices & (3 << 0)) != 0)
#define DESC_MODRM_IDX(desc) ((((desc)->operand_indices >> 0) & 3) ^ 3)
#define DESC_HAS_MODREG(desc) (((desc)->operand_indices & (3 << 2)) != 0)
#define DESC_MODREG_IDX(desc) ((((desc)->operand_indices >> 2) & 3) ^ 3)
#define DESC_HAS_VEXREG(desc) (((desc)->operand_indices & (3 << 4)) != 0)
#define DESC_VEXREG_IDX(desc) ((((desc)->operand_indices >> 4) & 3) ^ 3)
#define DESC_HAS_IMPLICIT(desc) (((desc)->operand_indices & (3 << 6)) != 0)
#define DESC_IMPLICIT_IDX(desc) ((((desc)->operand_indices >> 6) & 3) ^ 3)
#define DESC_IMM_CONTROL(desc) (((desc)->immediate >> 4) & 0x7)
#define DESC_IMM_IDX(desc) (((desc)->immediate & 3) ^ 3)
#define DESC_IMPLICIT_VAL(desc) (((desc)->immediate >> 2) & 1)
#define DESC_LOCK(desc) (((desc)->immediate >> 3) & 1)
#define DESC_VSIB(desc) (((desc)->immediate >> 7) & 1)
#define DESC_SIZE8(desc) (((desc)->operand_sizes >> 8) & 1)
#define DESC_SIZED64(desc) (((desc)->operand_sizes >> 9) & 1)
#define DESC_SIZE_FIX1(desc) (((desc)->operand_sizes >> 10) & 7)
#define DESC_SIZE_FIX2(desc) (((desc)->operand_sizes >> 13) & 3)
#define DESC_INSTR_WIDTH(desc) (((desc)->operand_sizes >> 15) & 1)
#define DESC_IGN66(desc) (((desc)->reg_types >> 15) & 1)

int
fd_decode(const uint8_t* buffer, size_t len_sz, int mode_int, uintptr_t address,
          FdInstr* instr)
{
    const uint16_t* table = NULL;
    DecodeMode mode;

    int len = len_sz > 15 ? 15 : len_sz;

    // Ensure that we can actually handle the decode request
    if (mode_int == 32)
    {
#if defined(ARCH_386)
        table = &_decode_table[FD_TABLE_OFFSET_32];
        mode = DECODE_32;
#endif
    }
    else if (mode_int == 64)
    {
#if defined(ARCH_X86_64)
        table = &_decode_table[FD_TABLE_OFFSET_64];
        mode = DECODE_64;
#endif
    }

    if (UNLIKELY(table == NULL))
        return FD_ERR_INTERNAL;

    int retval;
    int off = 0;
    uint8_t vex_operand = 0;
    uint8_t mandatory_prefix;
    int opcode_escape;
    PrefixSet prefixes = 0;

    retval = decode_prefixes(buffer + off, len - off, mode, &prefixes,
                             &mandatory_prefix, &instr->segment, &vex_operand,
                             &opcode_escape);
    if (UNLIKELY(retval < 0))
        return retval;
    if (UNLIKELY(off + retval >= len))
        return FD_ERR_PARTIAL;
    off += retval;

    uint32_t kind = ENTRY_TABLE_ROOT;

    if (UNLIKELY(prefixes & PREFIX_VEX))
    {
        if (opcode_escape < 0 || opcode_escape > 3)
            return FD_ERR_UD;
        opcode_escape |= 4;
    }
    else if (buffer[off] == 0x0f)
    {
        if (UNLIKELY(off + 1 >= len))
            return FD_ERR_PARTIAL;
        if (buffer[off + 1] == 0x38)
            opcode_escape = 2;
        else if (buffer[off + 1] == 0x3a)
            opcode_escape = 3;
        else
            opcode_escape = 1;
        off += opcode_escape >= 2 ? 2 : 1;
    }

    ENTRY_UNPACK(table, kind, table[opcode_escape]);
    if (LIKELY(off < len))
        ENTRY_UNPACK(table, kind, table[buffer[off++]]);

    // Then, walk through ModR/M-encoded opcode extensions.
    if ((kind == ENTRY_TABLE8 || kind == ENTRY_TABLE72) && LIKELY(off < len))
    {
        if (kind == ENTRY_TABLE72 && (buffer[off] & 0xc0) == 0xc0)
            ENTRY_UNPACK(table, kind, table[buffer[off++] - 0xb8]);
        else
            ENTRY_UNPACK(table, kind, table[(buffer[off] >> 3) & 7]);
    }

    // Handle mandatory prefixes (which behave like an opcode ext.).
    if (kind == ENTRY_TABLE_PREFIX)
    {
        // If a prefix is mandatory and used as opcode extension, it has no
        // further effect on the instruction. This, however, does not completely
        // apply to the 66 prefix: in rare cases it may affect the size of
        // general purpose registers. The instruction descriptor encodes whether
        // the 66 prefix has an effect on the instruction (IGN66).
        prefixes &= ~(PREFIX_REPNZ | PREFIX_REP);
        ENTRY_UNPACK(table, kind, table[mandatory_prefix]);
    }

    // For VEX prefix, we have to distinguish between VEX.W and VEX.L which may
    // be part of the opcode.
    if (kind == ENTRY_TABLE_VEX)
    {
        uint8_t index = 0;
        index |= prefixes & PREFIX_REXW ? (1 << 0) : 0;
        index |= prefixes & PREFIX_VEXL ? (1 << 1) : 0;
        ENTRY_UNPACK(table, kind, table[index]);
    }

    if (UNLIKELY(kind != ENTRY_INSTR))
        return kind == 0 ? FD_ERR_UD : FD_ERR_PARTIAL;

    struct InstrDesc* desc = (struct InstrDesc*) table;

    if (DESC_IGN66(desc))
        prefixes &= ~PREFIX_OPSZ;

    instr->type = desc->type;
    instr->flags = prefixes & 0x7f;
    if (mode == DECODE_64)
        instr->flags |= FD_FLAG_64;
    instr->address = address;

    uint8_t op_size = 0;
    if (DESC_SIZE8(desc))
        op_size = 1;
    else if (mode == DECODE_64 && (prefixes & PREFIX_REXW))
        op_size = 8;
    else if (prefixes & PREFIX_OPSZ)
        op_size = 2;
    else if (mode == DECODE_64 && DESC_SIZED64(desc))
        op_size = 8;
    else
        op_size = 4;
    // Note: operand size is updates for jumps when handling immediate operands.

    uint8_t vec_size = 16;
    if (prefixes & PREFIX_VEXL)
        vec_size = 32;

    // Compute address size.
    uint8_t addr_size = mode == DECODE_64 ? 8 : 4;
    if (UNLIKELY(prefixes & PREFIX_ADDRSZ))
        addr_size >>= 1;
    instr->addrsz = addr_size;

    __builtin_memset(instr->operands, 0, sizeof(instr->operands));

    // Reg operand 4 is only possible with RVMR encoding, which implies VEC.
    for (int i = 0; i < 3; i++)
    {
        uint32_t reg_type = (desc->reg_types >> 3 * i) & 0x7;
        // GPL FPU VEC MSK MMX BND ??? NVR
        instr->operands[i].misc = (0xf0857641 >> (4 * reg_type)) & 0xf;
    }

    if (DESC_HAS_IMPLICIT(desc))
    {
        FdOp* operand = &instr->operands[DESC_IMPLICIT_IDX(desc)];
        operand->type = FD_OT_REG;
        operand->reg = DESC_IMPLICIT_VAL(desc);
    }

    if (DESC_HAS_MODRM(desc))
    {
        FdOp* operand1 = &instr->operands[DESC_MODRM_IDX(desc)];
        FdOp* operand2 = NULL;
        if (DESC_HAS_MODREG(desc))
            operand2 = &instr->operands[DESC_MODREG_IDX(desc)];

        retval = decode_modrm(buffer + off, len - off, mode, instr, prefixes,
                              DESC_VSIB(desc), operand1, operand2);
        if (UNLIKELY(retval < 0))
            return retval;
        off += retval;
    }
    else if (DESC_HAS_MODREG(desc))
    {
        // If there is no ModRM, but a Mod-Reg, its opcode-encoded.
        FdOp* operand = &instr->operands[DESC_MODREG_IDX(desc)];
        uint8_t reg_idx = buffer[off - 1] & 7;
        // FIXME: don't apply REX.B to FPU, MMX, and MASK registers.
#if defined(ARCH_X86_64)
        if (!UNLIKELY(operand->misc == FD_RT_FPU))
            reg_idx += prefixes & PREFIX_REXB ? 8 : 0;
#endif
        operand->type = FD_OT_REG;
        operand->reg = reg_idx;
    }

    if (UNLIKELY(DESC_HAS_VEXREG(desc)))
    {
        FdOp* operand = &instr->operands[DESC_VEXREG_IDX(desc)];
        operand->type = FD_OT_REG;
        if (mode == DECODE_32)
            vex_operand &= 0x7;
        operand->reg = vex_operand;
    }
    else if (vex_operand != 0)
    {
        return FD_ERR_UD;
    }

    uint32_t imm_control = DESC_IMM_CONTROL(desc);
    if (UNLIKELY(imm_control == 1))
    {
        // 1 = immediate constant 1, used for shifts
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_IMM;
        instr->imm = 1;
    }
    else if (UNLIKELY(imm_control == 2))
    {
        // 2 = memory, address-sized, used for mov with moffs operand
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_MEM;
        operand->reg = FD_REG_NONE;
        operand->misc = FD_REG_NONE;

        if (UNLIKELY(off + addr_size > len))
            return FD_ERR_PARTIAL;
        if (addr_size == 2)
            instr->disp = LOAD_LE_2(&buffer[off]);
        if (addr_size == 4)
            instr->disp = LOAD_LE_4(&buffer[off]);
        if (LIKELY(addr_size == 8))
            instr->disp = LOAD_LE_8(&buffer[off]);
        off += addr_size;
    }
    else if (UNLIKELY(imm_control == 3))
    {
        // 3 = register in imm8[7:4], used for RVMR encoding with VBLENDVP[SD]
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_REG;
        operand->misc = FD_RT_VEC;

        if (UNLIKELY(off + 1 > len))
            return FD_ERR_PARTIAL;
        uint8_t reg = (uint8_t) LOAD_LE_1(&buffer[off]);
        off += 1;

        if (mode == DECODE_32)
            reg &= 0x7f;
        operand->reg = reg >> 4;
    }
    else if (imm_control != 0)
    {
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_IMM;

        // 4/5 = immediate, operand-sized/8 bit
        // 6/7 = offset, operand-sized/8 bit (used for jumps/calls)
        int imm_byte = imm_control & 1;
        int imm_offset = imm_control & 2;
        // Jumps are always 8 or 32 bit on x86-64, and the operand size is
        // forced to 64 bit.
        if (mode == DECODE_64 && UNLIKELY(imm_offset))
            op_size = 8;

        uint8_t imm_size;
        if (imm_byte)
            imm_size = 1;
        else if (UNLIKELY(instr->type == FDI_RET || instr->type == FDI_RETF))
            imm_size = 2;
        else if (UNLIKELY(instr->type == FDI_ENTER))
            imm_size = 3;
        else if (op_size == 2)
            imm_size = 2;
        else if (mode == DECODE_64 && (prefixes & PREFIX_REXW) &&
                 instr->type == FDI_MOVABS)
            imm_size = 8;
        else
            imm_size = 4;

        if (UNLIKELY(off + imm_size > len))
            return FD_ERR_PARTIAL;

        if (imm_size == 1)
            instr->imm = (int8_t) LOAD_LE_1(&buffer[off]);
        else if (imm_size == 2)
            instr->imm = (int16_t) LOAD_LE_2(&buffer[off]);
        else if (imm_size == 3)
            instr->imm = LOAD_LE_3(&buffer[off]);
        else if (imm_size == 4)
            instr->imm = (int32_t) LOAD_LE_4(&buffer[off]);
        else if (imm_size == 8)
            instr->imm = (int64_t) LOAD_LE_8(&buffer[off]);
        off += imm_size;

        if (imm_offset)
        {
            if (instr->address != 0)
                instr->imm += instr->address + off;
            else
                operand->type = FD_OT_OFF;
        }
    }

    if (instr->type == FDI_XCHG_NOP)
    {
        // Only 4890, 90, and 6690 are true NOPs.
        if (instr->operands[0].reg == 0 && instr->operands[1].reg == 0)
        {
            instr->operands[0].type = FD_OT_NONE;
            instr->operands[1].type = FD_OT_NONE;
            instr->type = FDI_NOP;
        }
        else
        {
            instr->type = FDI_XCHG;
        }
    }

    if (UNLIKELY(prefixes & PREFIX_LOCK))
        if (!DESC_LOCK(desc) || instr->operands[0].type != FD_OT_MEM)
            return FD_ERR_UD;

    uint8_t operand_sizes[4] = {
        1 << DESC_SIZE_FIX1(desc) >> 1, 1 << DESC_SIZE_FIX2(desc), op_size, vec_size
    };

    for (int i = 0; i < 4; i++)
    {
        FdOp* operand = &instr->operands[i];
        if (operand->type == FD_OT_NONE)
            break;

        operand->size = operand_sizes[(desc->operand_sizes >> 2 * i) & 3];

        // if (operand->type == FD_OT_REG && operand->misc == FD_RT_GPL &&
        //     !(prefixes & PREFIX_REX) && operand->size == 1 && operand->reg >= 4)
        if (!(prefixes & PREFIX_REX) && (LOAD_LE_4(operand) & 0xfffcffff) == 0x01040101)
            operand->misc = FD_RT_GPH;
    }

    instr->size = off;
    instr->operandsz = DESC_INSTR_WIDTH(desc) ? op_size : 0;

    return off;
}

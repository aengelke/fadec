
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec.h>


#if defined(ARCH_X86_64) && __SIZEOF_POINTER__ < 8
#error "Decoding x86-64 requires a 64-bit architecture"
#endif

#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

#define FD_DECODE_TABLE_DATA
static __attribute__((aligned(16))) const uint8_t _decode_table[] = {
#include <fadec-decode-table.inc>
};
#undef FD_DECODE_TABLE_DATA

// Defines FD_TABLE_OFFSET_32 and FD_TABLE_OFFSET_64, if available
#define FD_DECODE_TABLE_DEFINES
#include <fadec-decode-table.inc>
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
#define ENTRY_TABLE_PREFIX_REP 7
#define ENTRY_MASK 7

#define ENTRY_UNPACK(table,kind,entry) do { \
            uint16_t entry_copy = entry; \
            table = &((uint16_t*) _decode_table)[(entry_copy & ~7) >> 1]; \
            kind = entry_copy & ENTRY_MASK; \
        } while (0)

#define LOAD_LE_1(buf) ((size_t) *(uint8_t*) (buf))
#define LOAD_LE_2(buf) (LOAD_LE_1(buf) | LOAD_LE_1((uint8_t*) (buf) + 1)<<8)
#define LOAD_LE_3(buf) (LOAD_LE_2(buf) | LOAD_LE_1((uint8_t*) (buf) + 2)<<16)
#define LOAD_LE_4(buf) (LOAD_LE_2(buf) | LOAD_LE_2((uint8_t*) (buf) + 2)<<16)
#if defined(ARCH_X86_64)
#define LOAD_LE_8(buf) (LOAD_LE_4(buf) | LOAD_LE_4((uint8_t*) (buf) + 4)<<32)
#endif

enum PrefixSet
{
    PREFIX_LOCK = FD_FLAG_LOCK,
    PREFIX_REP = FD_FLAG_REP,
    PREFIX_REPNZ = FD_FLAG_REPNZ,
    PREFIX_REX = FD_FLAG_REX,
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
    *out_opcode_escape = -1;

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
            rex_prefix |= PREFIX_REX;
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
                return -1;
            uint8_t byte = buffer[off + 1];
            if (mode == DECODE_32 && (byte & 0xc0) != 0xc0)
                goto out;

            // VEX + REX/66/F2/F3/LOCK will #UD.
            if (prefixes & (PREFIX_REX|PREFIX_REP|PREFIX_REPNZ|PREFIX_LOCK))
                return -1;

            prefixes |= PREFIX_VEX;
            prefixes |= byte & 0x80 ? 0 : PREFIX_REXR;
            if (prefix == 0xc4) // 3-byte VEX
            {
                prefixes |= byte & 0x80 ? 0 : PREFIX_REXR;
                prefixes |= byte & 0x40 ? 0 : PREFIX_REXX;
                // SDM Vol 2A 2-15 (Dec. 2016): Ignored in 32-bit mode
                prefixes |= mode == DECODE_64 || (byte & 0x20) ? 0 : PREFIX_REXB;
                *out_opcode_escape = (byte & 0x1f);

                // Load third byte of VEX prefix
                if (UNLIKELY(off + 2 >= len))
                    return -1;
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
        return -1;
    }

    uint8_t modrm = buffer[off++];
    uint8_t mod = (modrm & 0xc0) >> 6;
    uint8_t mod_reg = (modrm & 0x38) >> 3;
    uint8_t rm = modrm & 0x07;

    // Operand 2 may be NULL when reg field is used as opcode extension
    if (out_o2)
    {
        uint8_t reg_idx = mod_reg;
#if defined(ARCH_X86_64)
        reg_idx += prefixes & PREFIX_REXR ? 8 : 0;
#endif
        out_o2->type = FD_OT_REG;
        out_o2->reg = reg_idx;
    }

    if (mod == 3)
    {
        uint8_t reg_idx = rm;
#if defined(ARCH_X86_64)
        reg_idx += prefixes & PREFIX_REXB ? 8 : 0;
#endif
        out_o1->type = FD_OT_REG;
        out_o1->reg = reg_idx;
        return off;
    }

    // SIB byte
    uint8_t scale = 0;
    uint8_t idx = 4;
    uint8_t base = rm;
    if (rm == 4)
    {
        if (UNLIKELY(off >= len))
            return -1;
        uint8_t sib = buffer[off++];
        scale = (sib & 0xc0) >> 6;
        idx = (sib & 0x38) >> 3;
#if defined(ARCH_X86_64)
        idx += prefixes & PREFIX_REXX ? 8 : 0;
#endif
        base = sib & 0x07;
    }

    out_o1->type = FD_OT_MEM;
    instr->idx_scale = scale;
    instr->idx_reg = !vsib && idx == 4 ? FD_REG_NONE : idx;

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
            return -1;
        instr->disp = (int8_t) LOAD_LE_1(&buffer[off]);
        off += 1;
    }
    else if (mod == 2 || (mod == 0 && base == 5))
    {
        if (UNLIKELY(off + 4 > len))
            return -1;
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
    uint8_t operand_sizes;
    uint8_t immediate;

    uint8_t gp_size_8 : 1;
    uint8_t gp_size_def64 : 1;
    uint8_t gp_instr_width : 1;
    uint8_t gp_fixed_operand_size : 3;
    uint8_t lock : 1;
    uint8_t vsib : 1;
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
#define DESC_IMM_BYTE(desc) (((desc)->immediate >> 7) & 1)

int
fd_decode(const uint8_t* buffer, size_t len_sz, int mode_int, uintptr_t address,
          FdInstr* instr)
{
    const uint16_t* table = NULL;

    int len = len_sz > 15 ? 15 : len_sz;
    DecodeMode mode = mode_int == 32 ? DECODE_32 :
                      mode_int == 64 ? DECODE_64 : -1;

    // Ensure that we can actually handle the decode request
#if defined(ARCH_386)
    if (mode == DECODE_32)
        table = &((uint16_t*) _decode_table)[FD_TABLE_OFFSET_32 >> 1];
#endif
#if defined(ARCH_X86_64)
    if (mode == DECODE_64)
        table = &((uint16_t*) _decode_table)[FD_TABLE_OFFSET_64 >> 1];
#endif

    if (UNLIKELY(table == NULL))
        return -2;

    int retval;
    int off = 0;
    uint8_t vex_operand = 0;
    uint8_t mandatory_prefix;
    int opcode_escape;
    PrefixSet prefixes = 0;

    retval = decode_prefixes(buffer + off, len - off, mode, &prefixes,
                             &mandatory_prefix, &instr->segment, &vex_operand,
                             &opcode_escape);
    if (UNLIKELY(retval < 0 || off + retval >= len))
        return -1;
    off += retval;

    uint32_t kind = ENTRY_TABLE256;

    // "Legacy" walk through table and escape opcodes
    if (LIKELY(opcode_escape < 0))
        while (kind == ENTRY_TABLE256 && LIKELY(off < len))
            ENTRY_UNPACK(table, kind, table[buffer[off++]]);
    // VEX/EVEX compact escapes; the prefix precedes the single opcode byte
    else if (opcode_escape == 1 || opcode_escape == 2 || opcode_escape == 3)
    {
        ENTRY_UNPACK(table, kind, table[0x0F]);
        if (opcode_escape == 2)
            ENTRY_UNPACK(table, kind, table[0x38]);
        if (opcode_escape == 3)
            ENTRY_UNPACK(table, kind, table[0x3A]);
        if (LIKELY(off < len))
            ENTRY_UNPACK(table, kind, table[buffer[off++]]);
    }
    else
        return -1;

    // Then, walk through ModR/M-encoded opcode extensions.
    if ((kind == ENTRY_TABLE8 || kind == ENTRY_TABLE72) && LIKELY(off < len))
    {
        uint16_t entry = 0;
        if (kind == ENTRY_TABLE72 && (buffer[off] & 0xc0) == 0xc0)
        {
            entry = table[buffer[off] - 0xb8];
            if ((entry & ENTRY_MASK) != ENTRY_NONE)
                off++;
            else
                entry = table[(buffer[off] >> 3) & 7];
        }
        else
            entry = table[(buffer[off] >> 3) & 7];

        ENTRY_UNPACK(table, kind, entry);
    }

    // Handle mandatory prefixes (which behave like an opcode ext.).
    if (kind == ENTRY_TABLE_PREFIX)
    {
        uint8_t index = mandatory_prefix;
        index |= prefixes & PREFIX_VEX ? (1 << 2) : 0;
        // If a prefix is mandatory and used as opcode extension, it has no
        // further effect on the instruction. This is especially important
        // for the 0x66 prefix, which could otherwise override the operand
        // size of general purpose registers.
        prefixes &= ~(PREFIX_OPSZ | PREFIX_REPNZ | PREFIX_REP);
        ENTRY_UNPACK(table, kind, table[index]);
    }
    else if (prefixes & PREFIX_VEX)
    {
        return -1;
    }

    if (kind == ENTRY_TABLE_PREFIX_REP)
    {
        // Discard 66h mandatory prefix
        uint8_t index = mandatory_prefix != 1 ? mandatory_prefix : 0;
        prefixes &= ~(PREFIX_REPNZ | PREFIX_REP);
        ENTRY_UNPACK(table, kind, table[index]);
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
        return -1;

    struct InstrDesc* desc = (struct InstrDesc*) table;

    instr->type = desc->type;
    instr->flags = prefixes & 0x7f;
    if (mode == DECODE_64)
        instr->flags |= FD_FLAG_64;
    instr->address = address;

    uint8_t op_size = 0;
    if (desc->gp_size_8)
        op_size = 1;
    else if (mode == DECODE_64 && (prefixes & PREFIX_REXW))
        op_size = 8;
    else if (prefixes & PREFIX_OPSZ)
        op_size = 2;
    else if (mode == DECODE_64 && desc->gp_size_def64)
        op_size = 8;
    else
        op_size = 4;

    instr->operandsz = desc->gp_instr_width ? op_size : 0;

    uint8_t vec_size = 16;
    if (prefixes & PREFIX_VEXL)
        vec_size = 32;

    // Compute address size.
    uint8_t addr_size = mode == DECODE_64 ? 8 : 4;
    if (prefixes & PREFIX_ADDRSZ)
        addr_size >>= 1;
    instr->addrsz = addr_size;

    uint8_t operand_sizes[4] = {
        0, 1 << desc->gp_fixed_operand_size, op_size, vec_size
    };

    __builtin_memset(instr->operands, 0, sizeof(instr->operands));
    for (int i = 0; i < 4; i++)
    {
        uint8_t enc_size = (desc->operand_sizes >> 2 * i) & 3;
        instr->operands[i].size = operand_sizes[enc_size];
    }

    if (DESC_HAS_IMPLICIT(desc))
    {
        FdOp* operand = &instr->operands[DESC_IMPLICIT_IDX(desc)];
        operand->type = FD_OT_REG;
        operand->reg = 0;
    }

    if (DESC_HAS_MODRM(desc))
    {
        FdOp* operand1 = &instr->operands[DESC_MODRM_IDX(desc)];
        FdOp* operand2 = NULL;
        if (DESC_HAS_MODREG(desc))
            operand2 = &instr->operands[DESC_MODREG_IDX(desc)];

        retval = decode_modrm(buffer + off, len - off, mode, instr, prefixes,
                              desc->vsib, operand1, operand2);
        if (UNLIKELY(retval < 0))
            return -1;
        off += retval;
    }
    else if (DESC_HAS_MODREG(desc))
    {
        // If there is no ModRM, but a Mod-Reg, its opcode-encoded.
        FdOp* operand = &instr->operands[DESC_MODREG_IDX(desc)];
        uint8_t reg_idx = buffer[off - 1] & 7;
#if defined(ARCH_X86_64)
        reg_idx += prefixes & PREFIX_REXB ? 8 : 0;
#endif
        operand->type = FD_OT_REG;
        operand->reg = reg_idx;
    }

    if (UNLIKELY(DESC_HAS_VEXREG(desc)))
    {
        FdOp* operand = &instr->operands[DESC_VEXREG_IDX(desc)];
        operand->type = FD_OT_REG;
        operand->reg = vex_operand;
    }
    else if (vex_operand != 0)
    {
        return -1;
    }

    uint32_t imm_control = DESC_IMM_CONTROL(desc);
    if (imm_control == 1)
    {
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_IMM;
        operand->size = 1;
        instr->imm = 1;
    }
    else if (imm_control == 2)
    {
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_MEM;
        operand->reg = FD_REG_NONE;
        operand->size = op_size;
        instr->idx_reg = FD_REG_NONE;

        if (UNLIKELY(off + addr_size > len))
            return -1;
#if defined(ARCH_386)
        if (addr_size == 2)
            instr->disp = LOAD_LE_2(&buffer[off]);
#endif
        if (addr_size == 4)
            instr->disp = LOAD_LE_4(&buffer[off]);
#if defined(ARCH_X86_64)
        if (addr_size == 8)
            instr->disp = LOAD_LE_8(&buffer[off]);
#endif
        off += addr_size;
    }
    else if (imm_control != 0)
    {
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];

        uint8_t imm_size;
        if (DESC_IMM_BYTE(desc))
            imm_size = 1;
        else if (UNLIKELY(instr->type == FDI_RET_IMM || instr->type == FDI_RETF))
            imm_size = 2;
        else if (UNLIKELY(instr->type == FDI_ENTER))
            imm_size = 3;
#if defined(ARCH_X86_64)
        else if (mode == DECODE_64 && UNLIKELY(imm_control == 4))
            // Jumps are always 8 or 32 bit on x86-64.
            imm_size = 4;
#endif
        else if (op_size == 2)
            imm_size = 2;
#if defined(ARCH_X86_64)
        else if (mode == DECODE_64 && (prefixes & PREFIX_REXW) &&
                 instr->type == FDI_MOVABS_IMM)
            imm_size = 8;
#endif
        else
            imm_size = 4;

        if (UNLIKELY(off + imm_size > len))
            return -1;

        if (imm_size == 1)
            instr->imm = (int8_t) LOAD_LE_1(&buffer[off]);
        else if (imm_size == 2)
            instr->imm = (int16_t) LOAD_LE_2(&buffer[off]);
        else if (imm_size == 3)
            instr->imm = LOAD_LE_3(&buffer[off]);
        else if (imm_size == 4)
            instr->imm = (int32_t) LOAD_LE_4(&buffer[off]);
#if defined(ARCH_X86_64)
        else if (imm_size == 8)
            instr->imm = (int64_t) LOAD_LE_8(&buffer[off]);
#endif
        off += imm_size;

        if (imm_control == 4)
        {
            instr->imm += instr->address + off;
#if defined(ARCH_X86_64)
            // On x86-64, jumps always have an operand size of 64 bit.
            if (mode == DECODE_64)
                operand->size = 8;
#endif
        }

        if (UNLIKELY(imm_control == 5))
        {
            operand->type = FD_OT_REG;
            operand->reg = (instr->imm & 0xf0) >> 4;
        }
        else
        {
            operand->type = FD_OT_IMM;
        }
    }

    if ((prefixes & PREFIX_LOCK) && !desc->lock)
        return -1;
    if ((prefixes & PREFIX_LOCK) && instr->operands[0].type != FD_OT_MEM)
        return -1;

    for (int i = 0; i < 4; i++)
    {
        uint32_t reg_type = (desc->reg_types >> 4 * i) & 0xf;
        uint32_t reg_idx = instr->operands[i].reg;
        if (reg_type == FD_RT_MEM && instr->operands[i].type != FD_OT_MEM)
            return -1;
        if (instr->operands[i].type != FD_OT_REG)
            continue;
        if (reg_type == FD_RT_GPL && !(prefixes & PREFIX_REX) &&
            instr->operands[i].size == 1 && reg_idx >= 4)
            reg_type = FD_RT_GPH;
        // Reject invalid segment registers
        if (reg_type == FD_RT_SEG && reg_idx >= 6)
            return -1;
        // Reject invalid control registers
        if (reg_type == FD_RT_CR && reg_idx != 0 && reg_idx != 2 &&
                reg_idx != 3 && reg_idx != 4 && reg_idx != 8)
            return -1;
        // Reject invalid debug registers
        if (reg_type == FD_RT_DR && reg_idx >= 8)
            return -1;
        instr->operands[i].misc = reg_type;
    }

    instr->size = off;

    return off;
}

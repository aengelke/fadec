
#include <stddef.h>
#include <stdint.h>

#include <decode.h>


#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

#define DECODE_TABLE_DATA
static const uint8_t _decode_table[] = {
#include <decode-table.inc>
};
#undef DECODE_TABLE_DATA


#define ENTRY_NONE 0
#define ENTRY_INSTR 1
#define ENTRY_TABLE256 2
#define ENTRY_TABLE8 3
#define ENTRY_TABLE72 4
#define ENTRY_TABLE_PREFIX 5
#define ENTRY_MASK 7
#define ENTRY_IS_TABLE(kind) ((kind) >= ENTRY_TABLE256)

#define INSTR_ENC_ADDR 0x08
#define INSTR_ENC_IMM 0x10
#define INSTR_ENC_MODRM 0x80
#define INSTR_ENC_MODRM_BOTH 0x40
#define INSTR_ENC_FLIP 0x20
#define INSTR_ENC_OPCODE 0x40
#define INSTR_ENC_IMPLICIT_REG 0x04

#define LOAD_LE_1(buf) (((size_t) ((uint8_t*) buf)[0]))
#define LOAD_LE_2(buf) (((size_t) ((uint8_t*) buf)[0]) | \
                        ((size_t) ((uint8_t*) buf)[1] << 8))
#define LOAD_LE_4(buf) (((size_t) ((uint8_t*) buf)[0]) | \
                        ((size_t) ((uint8_t*) buf)[1] << 8) | \
                        ((size_t) ((uint8_t*) buf)[2] << 16) | \
                        ((size_t) ((uint8_t*) buf)[3] << 24))
#if defined(ARCH_X86_64)
#define LOAD_LE_8(buf) (((size_t) ((uint8_t*) buf)[0]) | \
                        ((size_t) ((uint8_t*) buf)[1] << 8) | \
                        ((size_t) ((uint8_t*) buf)[2] << 16) | \
                        ((size_t) ((uint8_t*) buf)[3] << 24) | \
                        ((size_t) ((uint8_t*) buf)[4] << 32) | \
                        ((size_t) ((uint8_t*) buf)[5] << 40) | \
                        ((size_t) ((uint8_t*) buf)[6] << 48) | \
                        ((size_t) ((uint8_t*) buf)[7] << 56))
#endif

static
int
decode_prefixes(const uint8_t* buffer, int len, PrefixSet* out_prefixes,
                uint8_t* out_vex_operand)
{
    int off = 0;
    PrefixSet prefixes = 0;

    while (LIKELY(off < len))
    {
        uint8_t prefix = buffer[off];
        if (prefix == 0x2E)
        {
            prefixes |= PREFIX_SEG_CS;
        }
        else if (prefix == 0x64)
        {
            prefixes |= PREFIX_SEG_FS;
        }
        else if (prefix == 0x65)
        {
            prefixes |= PREFIX_SEG_GS;
        }
        else if (prefix == 0x66)
        {
            prefixes |= PREFIX_OPSZ;
        }
        else if (prefix == 0x67)
        {
            prefixes |= PREFIX_ADDRSZ;
        }
        else if (prefix == 0xF0)
        {
            prefixes |= PREFIX_LOCK;
        }
        else if (prefix == 0xF2)
        {
            prefixes |= PREFIX_REPNZ;
        }
        else if (prefix == 0xF3)
        {
            prefixes |= PREFIX_REP;
        }
#if defined(ARCH_X86_64)
        else if (LIKELY(prefix >= 0x40 && prefix <= 0x4F))
        {
            prefixes |= PREFIX_REX;
            if (prefix & 0x1)
            {
                prefixes |= PREFIX_REXB;
            }
            if (prefix & 0x2)
            {
                prefixes |= PREFIX_REXX;
            }
            if (prefix & 0x4)
            {
                prefixes |= PREFIX_REXR;
            }
            if (prefix & 0x8)
            {
                prefixes |= PREFIX_REXW;
            }
            // REX prefix is the last prefix.
            off++;
            break;
        }
#endif
        else if (UNLIKELY(prefix == 0xc4))
        {
            // 3-byte VEX
            if (UNLIKELY(off + 2 >= len))
            {
                return -1;
            }
#if defined(ARCH_386)
            if ((buffer[off + 1] & 0xc0) != 0xc0)
            {
                break;
            }
#endif
            uint8_t byte2 = buffer[off + 1];
            uint8_t byte3 = buffer[off + 2];

            prefixes |= PREFIX_VEX;
#if defined(ARCH_X86_64)
            if ((byte2 & 0x80) == 0)
            {
                prefixes |= PREFIX_REXR;
            }
            if ((byte2 & 0x40) == 0)
            {
                prefixes |= PREFIX_REXX;
            }
            if ((byte2 & 0x20) == 0)
            {
                prefixes |= PREFIX_REXB;
            }
#endif
            switch (byte2 & 0x1f)
            {
                case 0x01: prefixes |= PREFIX_ESC_0F; break;
                case 0x02: prefixes |= PREFIX_ESC_0F38; break;
                case 0x03: prefixes |= PREFIX_ESC_0F3A; break;
                default: return -1;
            }
            if (byte3 & 0x04)
            {
                prefixes |= PREFIX_VEXL;
            }
#if defined(ARCH_X86_64)
            // SDM Vol 2A 2-16 (Dec. 2016)
            // - "In 32-bit modes, VEX.W is silently ignored."
            // - VEX.W either replaces REX.W, is don't care or is reserved.
            if (byte3 & 0x80)
            {
                prefixes |= PREFIX_REXW;
            }
#endif
            *out_vex_operand = ((byte3 & 0x78) >> 3) ^ 0xf;
            switch (byte3 & 0x03)
            {
                case 1: prefixes |= PREFIX_OPSZ; break;
                case 2: prefixes |= PREFIX_REP; break;
                case 3: prefixes |= PREFIX_REPNZ; break;
                default: break;
            }

            // VEX prefix is always the last prefix.
            off += 3;
            break;
        }
        else if (UNLIKELY(prefix == 0xc5))
        {
            // 2-byte VEX
            if (UNLIKELY(off + 1 >= len))
            {
                return -1;
            }
#if defined(ARCH_386)
            if ((buffer[off + 1] & 0xc0) != 0xc0)
            {
                break;
            }
#endif
            uint8_t byte = buffer[off + 1];

            prefixes |= PREFIX_VEX | PREFIX_ESC_0F;
#if defined(ARCH_X86_64)
            if ((byte & 0x80) == 0)
            {
                prefixes |= PREFIX_REXR;
            }
#endif
            if (byte & 0x04)
            {
                prefixes |= PREFIX_VEXL;
            }
            *out_vex_operand = ((byte & 0x78) >> 3) ^ 0xf;
            switch (byte & 0x03)
            {
                case 1: prefixes |= PREFIX_OPSZ; break;
                case 2: prefixes |= PREFIX_REP; break;
                case 3: prefixes |= PREFIX_REPNZ; break;
                default: break;
            }

            // VEX prefix is always the last prefix.
            off += 2;
            break;
        }
        else
        {
            break;
        }
        off++;
    }

    if (out_prefixes != NULL)
    {
        *out_prefixes = prefixes;
    }

    return off;
}

static
int
decode_modrm(const uint8_t* buffer, int len, Instr* instr,
             struct Operand* out_o1, struct Operand* out_o2)
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
        reg_idx += instr->prefixes & PREFIX_REXR ? 8 : 0;
#endif
        out_o2->type = OT_REG;
        out_o2->reg = reg_idx;
    }

    if (mod == 3)
    {
        uint8_t reg_idx = rm;
#if defined(ARCH_X86_64)
        reg_idx += instr->prefixes & PREFIX_REXB ? 8 : 0;
#endif
        out_o1->type = OT_REG;
        out_o1->reg = reg_idx;
        return off;
    }

    // SIB byte
    uint8_t scale = 0;
    uint8_t idx = 0;
    uint8_t base = 0;
    if (rm == 4)
    {
        if (UNLIKELY(off >= len))
        {
            return -1;
        }

        uint8_t sib = buffer[off++];
        scale = ((sib & 0xc0) >> 6) + 1;
        idx = (sib & 0x38) >> 3;
#if defined(ARCH_X86_64)
        idx += instr->prefixes & PREFIX_REXX ? 8 : 0;
#endif
        base = sib & 0x07;
    }

    if (mod == 1)
    {
        if (UNLIKELY(off + 1 > len))
        {
            return -1;
        }

        instr->disp = (int8_t) LOAD_LE_1(&buffer[off]);
        off += 1;
    }
    else if (mod == 2 || (mod == 0 && (rm == 5 || base == 5)))
    {
        if (UNLIKELY(off + 4 > len))
        {
            return -1;
        }

        instr->disp = (int32_t) LOAD_LE_4(&buffer[off]);
        off += 4;
    }
    else
    {
        instr->disp = 0;
    }

    out_o1->type = OT_MEM;
    instr->scale = scale;

    if (scale == 0)
    {
        if (mod == 0 && rm == 5)
        {
#if defined(ARCH_X86_64)
            out_o1->reg = RI_IP;
#else
            out_o1->reg = REG_NONE;
#endif
            return off;
        }

        uint8_t reg_idx = rm;
#if defined(ARCH_X86_64)
        reg_idx += instr->prefixes & PREFIX_REXB ? 8 : 0;
#endif
        out_o1->reg = reg_idx;
        return off;
    }

    if (idx == 4)
    {
        instr->scale = 0;
    }
    else
    {
        instr->sreg = idx;
    }

    if (base == 5 && mod == 0)
    {
        out_o1->reg = REG_NONE;
    }
    else
    {
        uint8_t reg_idx = base;
#if defined(ARCH_X86_64)
        reg_idx += instr->prefixes & PREFIX_REXB ? 8 : 0;
#endif
        out_o1->reg = reg_idx;
    }

    return off;
}

struct InstrDesc
{
    uint16_t type;
    uint8_t operand_indices;
    uint8_t operand_sizes;
    uint8_t immediate;

    uint32_t gp_size_8 : 1;
    uint32_t gp_size_def64 : 1;
    uint32_t gp_instr_width : 1;
    uint32_t gp_fixed_operand_size : 3;
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
decode(const uint8_t* buffer, int len, Instr* instr)
{
    int retval;
    int off = 0;
    uint8_t vex_operand = 0;
    PrefixSet prefixes = 0;

    __builtin_memset(instr->operands, 0, sizeof(instr->operands));

    retval = decode_prefixes(buffer + off, len - off, &prefixes, &vex_operand);
    if (UNLIKELY(retval < 0 || off + retval >= len))
    {
        return -1;
    }
    off += retval;

    uint16_t* table = (uint16_t*) _decode_table;
    uint32_t kind = ENTRY_TABLE256;

    if (UNLIKELY(prefixes & PREFIX_ESC_MASK))
    {
        uint32_t escape = prefixes & PREFIX_ESC_MASK;
        table = (uint16_t*) &_decode_table[table[0x0F] & ~7];
        if (escape == PREFIX_ESC_0F38)
        {
            table = (uint16_t*) &_decode_table[table[0x38] & ~7];
        }
        else if (escape == PREFIX_ESC_0F3A)
        {
            table = (uint16_t*) &_decode_table[table[0x3A] & ~7];
        }
    }

    do
    {
        uint16_t entry = 0;
        if (kind == ENTRY_TABLE256)
        {
            entry = table[buffer[off++]];
        }
        else if (kind == ENTRY_TABLE8)
        {
            entry = table[(buffer[off] >> 3) & 7];
        }
        else if (kind == ENTRY_TABLE72)
        {
            if ((buffer[off] & 0xc0) == 0xc0)
            {
                entry = table[buffer[off] - 0xb8];
                if ((entry & ENTRY_MASK) != ENTRY_NONE)
                {
                    off++;
                }
                else
                {
                    entry = table[(buffer[off] >> 3) & 7];
                }
            }
            else
            {
                entry = table[(buffer[off] >> 3) & 7];
            }
        }
        else if (kind == ENTRY_TABLE_PREFIX)
        {
            uint8_t index = 0;
            if (prefixes & PREFIX_OPSZ)
            {
                index = 1;
            }
            else if (prefixes & PREFIX_REP)
            {
                index = 2;
            }
            else if (prefixes & PREFIX_REPNZ)
            {
                index = 3;
            }
#if defined(ARCH_X86_64)
            index |= prefixes & PREFIX_REXW ? (1 << 2) : 0;
#endif
            index |= prefixes & PREFIX_VEX ? (1 << 3) : 0;
            // If a prefix is mandatory and used as opcode extension, it has no
            // further effect on the instruction. This is especially important
            // for the 0x66 prefix, which could otherwise override the operand
            // size of general purpose registers.
            prefixes &= ~(PREFIX_OPSZ | PREFIX_REPNZ | PREFIX_REP);
            entry = table[index];
        }
        else
        {
            break;
        }

        kind = entry & ENTRY_MASK;
        table = (uint16_t*) &_decode_table[entry & ~7];
    } while (LIKELY(off < len));

    if (UNLIKELY(kind != ENTRY_INSTR))
    {
        return -1;
    }

    struct InstrDesc* desc = (struct InstrDesc*) table;

    instr->type = desc->type;
    instr->prefixes = prefixes;
    instr->address = (uintptr_t) buffer;

    if (prefixes & PREFIX_SEG_FS)
    {
        instr->segment = RI_FS;
    }
    else if (prefixes & PREFIX_SEG_GS)
    {
        instr->segment = RI_GS;
    }
    else
    {
        instr->segment = RI_DS;
    }

    uint8_t op_size = 0;
    if (desc->gp_size_8)
    {
        op_size = 1;
    }
#if defined(ARCH_X86_64)
    else if (prefixes & PREFIX_REXW)
    {
        op_size = 8;
    }
#endif
    else if (prefixes & PREFIX_OPSZ)
    {
        op_size = 2;
    }
#if defined(ARCH_X86_64)
    else if (desc->gp_size_def64)
    {
        op_size = 8;
    }
#endif
    else
    {
        op_size = 4;
    }

    if (UNLIKELY(desc->gp_instr_width))
    {
        instr->width = op_size;
    }
    else
    {
        instr->width = 0;
    }

    uint8_t vec_size = 16;
    if (prefixes & PREFIX_VEXL)
    {
        vec_size = 32;
    }

    uint8_t operand_sizes[4] = {
        0, 1 << desc->gp_fixed_operand_size, op_size, vec_size
    };

    for (int i = 0; i < 4; i++)
    {
        uint8_t enc_size = (desc->operand_sizes >> 2 * i) & 3;
        instr->operands[i].size = operand_sizes[enc_size];
    }

    if (UNLIKELY(DESC_HAS_IMPLICIT(desc)))
    {
        struct Operand* operand = &instr->operands[DESC_IMPLICIT_IDX(desc)];
        operand->type = OT_REG;
        operand->reg = 0;
    }

    if (DESC_HAS_MODRM(desc))
    {
        struct Operand* operand1 = &instr->operands[DESC_MODRM_IDX(desc)];

        struct Operand* operand2 = NULL;
        if (DESC_HAS_MODREG(desc))
        {
            operand2 = &instr->operands[DESC_MODREG_IDX(desc)];
        }
        retval = decode_modrm(buffer + off, len - off, instr,
                              operand1, operand2);

        if (UNLIKELY(retval < 0))
        {
            return -1;
        }

        off += retval;
    }
    else if (UNLIKELY(DESC_HAS_MODREG(desc)))
    {
        // If there is no ModRM, but a Mod-Reg, its opcode-encoded.
        struct Operand* operand = &instr->operands[DESC_MODREG_IDX(desc)];
        uint8_t reg_idx = buffer[off - 1] & 7;
#if defined(ARCH_X86_64)
        reg_idx += prefixes & PREFIX_REXB ? 8 : 0;
#endif
        operand->type = OT_REG;
        operand->reg = reg_idx;
    }

    if (UNLIKELY(DESC_HAS_VEXREG(desc)))
    {
        struct Operand* operand = &instr->operands[DESC_VEXREG_IDX(desc)];
        operand->type = OT_REG;
        operand->reg = vex_operand;
    }

    uint32_t imm_control = DESC_IMM_CONTROL(desc);
    if (UNLIKELY(imm_control == 1))
    {
        struct Operand* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = OT_IMM;
        operand->size = 1;
        instr->immediate = 1;
    }
    else if (UNLIKELY(imm_control == 2))
    {
        struct Operand* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = OT_MEM;
        operand->reg = REG_NONE;
        operand->size = op_size;
        instr->scale = 0;
        // TODO: Address size overrides
#if defined(ARCH_386)
        if (UNLIKELY(off + 4 > len))
        {
            return -1;
        }
        instr->disp = LOAD_LE_4(&buffer[off]);
        off += 4;
#else
        if (UNLIKELY(off + 8 > len))
        {
            return -1;
        }
        instr->disp = LOAD_LE_8(&buffer[off]);
        off += 8;
#endif
    }
    else if (UNLIKELY(imm_control != 0))
    {
        uint8_t imm_size;
        if (DESC_IMM_BYTE(desc))
        {
            imm_size = 1;
        }
        else if (UNLIKELY(instr->type == IT_RET_IMM))
        {
            imm_size = 2;
        }
        else if (UNLIKELY(instr->type == IT_ENTER))
        {
            imm_size = 3;
        }
        else if (prefixes & PREFIX_OPSZ)
        {
            imm_size = 2;
        }
#if defined(ARCH_X86_64)
        else if (prefixes & PREFIX_REXW && instr->type == IT_MOVABS_IMM)
        {
            imm_size = 8;
        }
#endif
        else
        {
            imm_size = 4;
        }

        if (UNLIKELY(off + imm_size > len))
        {
            return -1;
        }

        if (imm_size == 1)
        {
            instr->immediate = (int8_t) LOAD_LE_1(&buffer[off]);
        }
        else if (imm_size == 2)
        {
            instr->immediate = (int16_t) LOAD_LE_2(&buffer[off]);
        }
        else if (imm_size == 3)
        {
            instr->immediate = LOAD_LE_2(&buffer[off]);
            instr->immediate |= LOAD_LE_1(&buffer[off + 2]) << 16;
        }
        else if (imm_size == 4)
        {
            instr->immediate = (int32_t) LOAD_LE_4(&buffer[off]);
        }
#if defined(ARCH_X86_64)
        else if (imm_size == 8)
        {
            instr->immediate = (int64_t) LOAD_LE_8(&buffer[off]);
        }
#endif
        off += imm_size;

        if (imm_control == 4)
        {
            instr->immediate += (uintptr_t) buffer + off;
        }

        struct Operand* operand = &instr->operands[DESC_IMM_IDX(desc)];
        if (UNLIKELY(imm_control == 5))
        {
            operand->type = OT_REG;
            operand->reg = (instr->immediate & 0xf0) >> 4;
        }
        else
        {
            operand->type = OT_IMM;
        }
    }

    instr->size = off;

    return off;
}

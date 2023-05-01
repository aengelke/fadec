
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec.h>


#ifdef __GNUC__
#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)
#define ASSUME(x) do { if (!(x)) __builtin_unreachable(); } while (0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#define ASSUME(x) ((void) 0)
#endif

// Defines FD_TABLE_OFFSET_32 and FD_TABLE_OFFSET_64, if available
#define FD_DECODE_TABLE_DEFINES
#include <fadec-decode-private.inc>
#undef FD_DECODE_TABLE_DEFINES

enum DecodeMode {
    DECODE_64 = 0,
    DECODE_32 = 1,
};

typedef enum DecodeMode DecodeMode;

#define ENTRY_NONE 0
#define ENTRY_INSTR 1
#define ENTRY_TABLE256 2
#define ENTRY_TABLE16 3
#define ENTRY_TABLE8E 4
#define ENTRY_TABLE_PREFIX 5
#define ENTRY_TABLE_VEX 6
#define ENTRY_TABLE_ROOT 8
#define ENTRY_MASK 7

static uint16_t
table_lookup(unsigned cur_idx, unsigned entry_idx) {
    static _Alignas(16) const uint16_t _decode_table[] = {
#define FD_DECODE_TABLE_DATA
#include <fadec-decode-private.inc>
#undef FD_DECODE_TABLE_DATA
    };
    return _decode_table[cur_idx + entry_idx];
}

static unsigned
table_walk(unsigned table_entry, unsigned entry_idx) {
    return table_lookup(table_entry & ~0x3, entry_idx);
}

#define LOAD_LE_1(buf) ((uint64_t) *(uint8_t*) (buf))
#define LOAD_LE_2(buf) (LOAD_LE_1(buf) | LOAD_LE_1((uint8_t*) (buf) + 1)<<8)
#define LOAD_LE_3(buf) (LOAD_LE_2(buf) | LOAD_LE_1((uint8_t*) (buf) + 2)<<16)
#define LOAD_LE_4(buf) (LOAD_LE_2(buf) | LOAD_LE_2((uint8_t*) (buf) + 2)<<16)
#define LOAD_LE_8(buf) (LOAD_LE_4(buf) | LOAD_LE_4((uint8_t*) (buf) + 4)<<32)

enum
{
    PREFIX_REXB = 0x01,
    PREFIX_REXX = 0x02,
    PREFIX_REXR = 0x04,
    PREFIX_REXW = 0x08,
    PREFIX_REX = 0x40,
    PREFIX_REXRR = 0x10,
    PREFIX_VEX = 0x20,
};

struct InstrDesc
{
    uint16_t type;
    uint16_t operand_indices;
    uint16_t operand_sizes;
    uint16_t reg_types;
};

#define DESC_HAS_MODRM(desc) (((desc)->operand_indices & (3 << 0)) != 0)
#define DESC_MODRM_IDX(desc) ((((desc)->operand_indices >> 0) & 3) ^ 3)
#define DESC_HAS_MODREG(desc) (((desc)->operand_indices & (3 << 2)) != 0)
#define DESC_MODREG_IDX(desc) ((((desc)->operand_indices >> 2) & 3) ^ 3)
#define DESC_HAS_VEXREG(desc) (((desc)->operand_indices & (3 << 4)) != 0)
#define DESC_VEXREG_IDX(desc) ((((desc)->operand_indices >> 4) & 3) ^ 3)
#define DESC_IMM_CONTROL(desc) (((desc)->operand_indices >> 12) & 0x7)
#define DESC_IMM_IDX(desc) ((((desc)->operand_indices >> 6) & 3) ^ 3)
#define DESC_EVEX_BCST(desc) (((desc)->operand_indices >> 8) & 1)
#define DESC_EVEX_MASK(desc) (((desc)->operand_indices >> 9) & 1)
#define DESC_ZEROREG_VAL(desc) (((desc)->operand_indices >> 10) & 1)
#define DESC_LOCK(desc) (((desc)->operand_indices >> 11) & 1)
#define DESC_VSIB(desc) (((desc)->operand_indices >> 15) & 1)
#define DESC_OPSIZE(desc) (((desc)->reg_types >> 11) & 7)
#define DESC_MODRM_SIZE(desc) (((desc)->operand_sizes >> 0) & 3)
#define DESC_MODREG_SIZE(desc) (((desc)->operand_sizes >> 2) & 3)
#define DESC_VEXREG_SIZE(desc) (((desc)->operand_sizes >> 4) & 3)
#define DESC_IMM_SIZE(desc) (((desc)->operand_sizes >> 6) & 3)
#define DESC_LEGACY(desc) (((desc)->operand_sizes >> 8) & 1)
#define DESC_SIZE_FIX1(desc) (((desc)->operand_sizes >> 10) & 7)
#define DESC_SIZE_FIX2(desc) (((desc)->operand_sizes >> 13) & 3)
#define DESC_INSTR_WIDTH(desc) (((desc)->operand_sizes >> 15) & 1)
#define DESC_MODRM(desc) (((desc)->reg_types >> 14) & 1)
#define DESC_IGN66(desc) (((desc)->reg_types >> 15) & 1)
#define DESC_EVEX_SAE(desc) (((desc)->reg_types >> 8) & 1)
#define DESC_EVEX_ER(desc) (((desc)->reg_types >> 9) & 1)
#define DESC_EVEX_BCST16(desc) (((desc)->reg_types >> 10) & 1)
#define DESC_REGTY_MODRM(desc) (((desc)->reg_types >> 0) & 7)
#define DESC_REGTY_MODREG(desc) (((desc)->reg_types >> 3) & 7)
#define DESC_REGTY_VEXREG(desc) (((desc)->reg_types >> 6) & 3)

int
fd_decode(const uint8_t* buffer, size_t len_sz, int mode_int, uintptr_t address,
          FdInstr* instr)
{
    int len = len_sz > 15 ? 15 : len_sz;

    // Ensure that we can actually handle the decode request
    DecodeMode mode;
    unsigned table_root_idx;
    switch (mode_int)
    {
#if defined(FD_TABLE_OFFSET_32)
    case 32: table_root_idx = FD_TABLE_OFFSET_32; mode = DECODE_32; break;
#endif
#if defined(FD_TABLE_OFFSET_64)
    case 64: table_root_idx = FD_TABLE_OFFSET_64; mode = DECODE_64; break;
#endif
    default: return FD_ERR_INTERNAL;
    }

    int off = 0;
    uint8_t vex_operand = 0;

    uint8_t addr_size = mode == DECODE_64 ? 3 : 2;
    unsigned prefix_rex = 0;
    uint8_t prefix_rep = 0;
    unsigned vexl = 0;
    unsigned prefix_evex = 0;
    instr->segment = FD_REG_NONE;

    // Values must match prefixes in parseinstrs.py.
    enum {
        PF_SEG1 = 0xfff8 - 0xfff8,
        PF_SEG2 = 0xfff9 - 0xfff8,
        PF_66 = 0xfffa - 0xfff8,
        PF_67 = 0xfffb - 0xfff8,
        PF_LOCK = 0xfffc - 0xfff8,
        PF_REP = 0xfffd - 0xfff8,
        PF_REX = 0xfffe - 0xfff8,
    };

    uint8_t prefixes[8] = {0};
    unsigned table_entry = 0;
    while (true) {
        if (UNLIKELY(off >= len))
            return FD_ERR_PARTIAL;
        uint8_t prefix = buffer[off];
        table_entry = table_lookup(table_root_idx, prefix);
        if (LIKELY(table_entry - 0xfff8 >= 8))
            break;
        prefixes[PF_REX] = 0;
        prefixes[table_entry - 0xfff8] = prefix;
        off++;
    }
    if (off) {
        if (UNLIKELY(prefixes[PF_SEG2])) {
            if (prefixes[PF_SEG2] & 0x02)
                instr->segment = prefixes[PF_SEG2] >> 3 & 3;
            else
                instr->segment = prefixes[PF_SEG2] & 7;
        }
        if (UNLIKELY(prefixes[PF_67]))
            addr_size--;
        prefix_rex = prefixes[PF_REX];
        prefix_rep = prefixes[PF_REP];
    }

    // table_entry kinds: INSTR(0), T16(1), ESCAPE_A(2), ESCAPE_B(3)
    if (LIKELY(!(table_entry & 2))) {
        off++;

        // Then, walk through ModR/M-encoded opcode extensions.
        if (table_entry & 1) {
            if (UNLIKELY(off >= len))
                return FD_ERR_PARTIAL;
            unsigned isreg = buffer[off] >= 0xc0;
            table_entry = table_walk(table_entry, ((buffer[off] >> 2) & 0xe) | isreg);
            // table_entry kinds: INSTR(0), T8E(1)
            if (table_entry & 1)
                table_entry = table_walk(table_entry, buffer[off] & 7);
        }

        // table_entry kinds: INSTR(0)
        goto direct;
    }

    if (UNLIKELY(off >= len))
        return FD_ERR_PARTIAL;

    unsigned opcode_escape = 0;
    uint8_t mandatory_prefix = 0; // without escape/VEX/EVEX, this is ignored.
    if (buffer[off] == 0x0f)
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

        // If there is no REP/REPNZ prefix offer 66h as mandatory prefix. If
        // there is a REP prefix, then the 66h prefix is ignored here.
        mandatory_prefix = prefix_rep ? prefix_rep ^ 0xf1 : !!prefixes[PF_66];
    }
    else if (UNLIKELY((unsigned) buffer[off] - 0xc4 < 2 || buffer[off] == 0x62))
    {
        unsigned vex_prefix = buffer[off];
        // VEX (C4/C5) or EVEX (62)
        if (UNLIKELY(off + 1 >= len))
            return FD_ERR_PARTIAL;
        if (UNLIKELY(mode == DECODE_32 && buffer[off + 1] < 0xc0)) {
            off++;
            table_entry = table_walk(table_entry, 0);
            // table_entry kinds: INSTR(0)
            goto direct;
        }

        // VEX/EVEX + 66/F3/F2/REX will #UD.
        // Note: REX is also here only respected if it immediately precedes the
        // opcode, in this case the VEX/EVEX "prefix".
        if (prefixes[PF_66] || prefixes[PF_REP] || prefix_rex)
            return FD_ERR_UD;

        uint8_t byte = buffer[off + 1];
        if (vex_prefix == 0xc5) // 2-byte VEX
        {
            opcode_escape = 1;
            prefix_rex = byte & 0x80 ? 0 : PREFIX_REXR;
        }
        else // 3-byte VEX or EVEX
        {
            // SDM Vol 2A 2-15 (Dec. 2016): Ignored in 32-bit mode
            if (mode == DECODE_64)
                prefix_rex = byte >> 5 ^ 0x7;
            if (vex_prefix == 0x62) // EVEX
            {
                if (byte & 0x08) // Bit 3 of opcode_escape must be clear.
                    return FD_ERR_UD;
                _Static_assert(PREFIX_REXRR == 0x10, "wrong REXRR value");
                if (mode == DECODE_64)
                    prefix_rex |= (byte & PREFIX_REXRR) ^ PREFIX_REXRR;
            }
            else // 3-byte VEX
            {
                if (byte & 0x18) // Bits 4:3 of opcode_escape must be clear.
                    return FD_ERR_UD;
            }

            opcode_escape = (byte & 0x07);
            if (UNLIKELY(opcode_escape == 0)) {
                int prefix_len = vex_prefix == 0x62 ? 4 : 3;
                // Pretend to decode the prefix plus one opcode byte.
                return off + prefix_len > len ? FD_ERR_PARTIAL : FD_ERR_UD;
            }

            // Load third byte of VEX prefix
            if (UNLIKELY(off + 2 >= len))
                return FD_ERR_PARTIAL;
            byte = buffer[off + 2];
            prefix_rex |= byte & 0x80 ? PREFIX_REXW : 0;
        }

        mandatory_prefix = byte & 3;
        vex_operand = ((byte & 0x78) >> 3) ^ 0xf;
        prefix_rex |= PREFIX_VEX;

        if (vex_prefix == 0x62) // EVEX
        {
            if (!(byte & 0x04)) // Bit 10 must be 1.
                return FD_ERR_UD;
            if (UNLIKELY(off + 3 >= len))
                return FD_ERR_PARTIAL;
            byte = buffer[off + 3];
            // prefix_evex is z:L'L/RC:b:V':aaa
            vexl = (byte >> 5) & 3;
            prefix_evex = byte | 0x100; // Ensure that prefix_evex is non-zero.
            if (mode == DECODE_64) // V' causes UD in 32-bit mode
                vex_operand |= byte & 0x08 ? 0 : 0x10; // V'
            else if (!(byte & 0x08))
                return FD_ERR_UD;
            off += 4;
        }
        else // VEX
        {
            vexl = byte & 0x04 ? 1 : 0;
            off += 0xc7 - vex_prefix; // 3 for c4, 2 for c5
        }
    }

    table_entry = table_walk(table_entry, opcode_escape);
    // table_entry kinds: INSTR(0) [only for invalid], T256(2)
    if (UNLIKELY(!table_entry))
        return FD_ERR_UD;
    if (UNLIKELY(off >= len))
        return FD_ERR_PARTIAL;
    table_entry = table_walk(table_entry, buffer[off++]);
    // table_entry kinds: INSTR(0), T16(1), TVEX(2), TPREFIX(3)

    // Handle mandatory prefixes (which behave like an opcode ext.).
    if ((table_entry & 3) == 3)
        table_entry = table_walk(table_entry, mandatory_prefix);
    // table_entry kinds: INSTR(0), T16(1), TVEX(2)

    // Then, walk through ModR/M-encoded opcode extensions.
    if (table_entry & 1) {
        if (UNLIKELY(off >= len))
            return FD_ERR_PARTIAL;
        unsigned isreg = buffer[off] >= 0xc0;
        table_entry = table_walk(table_entry, ((buffer[off] >> 2) & 0xe) | isreg);
        // table_entry kinds: INSTR(0), T8E(1), TVEX(2)
        if (table_entry & 1)
            table_entry = table_walk(table_entry, buffer[off] & 7);
    }
    // table_entry kinds: INSTR(0), TVEX(2)

    // For VEX prefix, we have to distinguish between VEX.W and VEX.L which may
    // be part of the opcode.
    if (UNLIKELY(table_entry & 2))
    {
        uint8_t index = 0;
        index |= prefix_rex & PREFIX_REXW ? (1 << 0) : 0;
        // When EVEX.L'L is the rounding mode, the instruction must not have
        // L'L constraints.
        index |= vexl << 1;
        table_entry = table_walk(table_entry, index);
    }
    // table_entry kinds: INSTR(0)

direct:
    // table_entry kinds: INSTR(0)
    if (UNLIKELY(!table_entry))
        return FD_ERR_UD;

    static _Alignas(16) const struct InstrDesc descs[] = {
#define FD_DECODE_TABLE_DESCS
#include <fadec-decode-private.inc>
#undef FD_DECODE_TABLE_DESCS
    };
    const struct InstrDesc* desc = &descs[table_entry >> 2];

    instr->type = desc->type;
    instr->addrsz = addr_size;
    instr->flags = ((prefix_rep + 1) & 6) + (mode == DECODE_64 ? FD_FLAG_64 : 0);
    instr->address = address;

    for (unsigned i = 0; i < sizeof(instr->operands) / sizeof(FdOp); i++)
        instr->operands[i] = (FdOp) {0};

    if (DESC_MODRM(desc) && UNLIKELY(off++ >= len))
        return FD_ERR_PARTIAL;
    unsigned op_byte = buffer[off - 1] | (!DESC_MODRM(desc) ? 0xc0 : 0);

    if (UNLIKELY(prefix_evex)) {
        // VSIB inst (gather/scatter) without mask register or w/EVEX.z is UD
        if (DESC_VSIB(desc) && (!(prefix_evex & 0x07) || (prefix_evex & 0x80)))
            return FD_ERR_UD;
        // Inst doesn't support masking, so EVEX.z or EVEX.aaa is UD
        if (!DESC_EVEX_MASK(desc) && (prefix_evex & 0x87))
            return FD_ERR_UD;
        // EVEX.z without EVEX.aaa is UD. The Intel SDM is rather unprecise
        // about this, but real hardware doesn't accept this.
        if ((prefix_evex & 0x87) == 0x80)
            return FD_ERR_UD;

        // Cases for SAE/RC (reg operands only):
        //  - ER supported -> all ok
        //  - SAE supported -> assume L'L is RC, but ignored (undocumented)
        //  - Neither supported -> b == 0
        if ((prefix_evex & 0x10) && (op_byte & 0xc0) == 0xc0) { // EVEX.b+reg
            if (!DESC_EVEX_SAE(desc))
                return FD_ERR_UD;
            vexl = 2;
            if (DESC_EVEX_ER(desc))
                instr->evex = prefix_evex;
            else
                instr->evex = (prefix_evex & 0x87) | 0x60; // set RC, clear B
        } else {
            if (UNLIKELY(vexl == 3)) // EVEX.L'L == 11b is UD
                return FD_ERR_UD;
            instr->evex = prefix_evex & 0x87; // clear RC, clear B
        }

        if (DESC_VSIB(desc))
            vex_operand &= 0xf; // EVEX.V' is used as index extension instead.
    } else {
        instr->evex = 0;
    }

    unsigned op_size;
    unsigned op_size_alt = 0;
    if (!(DESC_OPSIZE(desc) & 4)) {
        if (mode == DECODE_64)
            op_size = ((prefix_rex & PREFIX_REXW) || DESC_OPSIZE(desc) == 3) ? 4 :
                              UNLIKELY(prefixes[PF_66] && !DESC_IGN66(desc)) ? 2 :
                                                           DESC_OPSIZE(desc) ? 4 :
                                                                               3;
        else
            op_size = UNLIKELY(prefixes[PF_66] && !DESC_IGN66(desc)) ? 2 : 3;
    } else {
        op_size = 5 + vexl;
        op_size_alt = op_size - (DESC_OPSIZE(desc) & 3);
    }

    uint8_t operand_sizes[4] = {
        DESC_SIZE_FIX1(desc), DESC_SIZE_FIX2(desc) + 1, op_size, op_size_alt
    };

    if (UNLIKELY(instr->type == FDI_MOV_CR || instr->type == FDI_MOV_DR)) {
        unsigned modreg = (op_byte >> 3) & 0x7;
        unsigned modrm = op_byte & 0x7;

        FdOp* op_modreg = &instr->operands[DESC_MODREG_IDX(desc)];
        op_modreg->type = FD_OT_REG;
        op_modreg->size = op_size;
        op_modreg->reg = modreg | (prefix_rex & PREFIX_REXR ? 8 : 0);
        op_modreg->misc = instr->type == FDI_MOV_CR ? FD_RT_CR : FD_RT_DR;
        if (instr->type == FDI_MOV_CR && (~0x011d >> op_modreg->reg) & 1)
            return FD_ERR_UD;
        else if (instr->type == FDI_MOV_DR && prefix_rex & PREFIX_REXR)
            return FD_ERR_UD;

        FdOp* op_modrm = &instr->operands[DESC_MODRM_IDX(desc)];
        op_modrm->type = FD_OT_REG;
        op_modrm->size = op_size;
        op_modrm->reg = modrm | (prefix_rex & PREFIX_REXB ? 8 : 0);
        op_modrm->misc = FD_RT_GPL;
        goto skip_modrm;
    }

    if (DESC_HAS_MODREG(desc))
    {
        FdOp* op_modreg = &instr->operands[DESC_MODREG_IDX(desc)];
        unsigned reg_idx = (op_byte & 0x38) >> 3;
        unsigned reg_ty = DESC_REGTY_MODREG(desc);
        op_modreg->misc = reg_ty;
        if (LIKELY(reg_ty < 2))
            reg_idx += prefix_rex & PREFIX_REXR ? 8 : 0;
        else if (reg_ty == 7 && (prefix_rex & PREFIX_REXR || prefix_evex & 0x80))
            return FD_ERR_UD; // REXR in 64-bit mode or EVEX.z with mask as dest
        if (UNLIKELY(reg_ty == FD_RT_VEC)) // REXRR ignored above in 32-bit mode
            reg_idx += prefix_rex & PREFIX_REXRR ? 16 : 0;
        else if (UNLIKELY(prefix_rex & PREFIX_REXRR))
            return FD_ERR_UD;
        op_modreg->type = FD_OT_REG;
        op_modreg->size = operand_sizes[DESC_MODREG_SIZE(desc)];
        op_modreg->reg = reg_idx;
    }

    if (DESC_HAS_MODRM(desc))
    {
        FdOp* op_modrm = &instr->operands[DESC_MODRM_IDX(desc)];
        op_modrm->size = operand_sizes[DESC_MODRM_SIZE(desc)];

        unsigned rm = op_byte & 0x07;
        if (op_byte >= 0xc0)
        {
            uint8_t reg_idx = rm;
            unsigned reg_ty = DESC_REGTY_MODRM(desc);
            op_modrm->misc = reg_ty;
            if (LIKELY(reg_ty < 2))
                reg_idx += prefix_rex & PREFIX_REXB ? 8 : 0;
            if (prefix_evex && reg_ty == 0) // vector registers only
                reg_idx += prefix_rex & PREFIX_REXX ? 16 : 0;
            op_modrm->type = FD_OT_REG;
            op_modrm->reg = reg_idx;
        }
        else
        {
            unsigned dispscale = 0;

            if (UNLIKELY(prefix_evex)) {
                // EVEX.z for memory destination operand is UD.
                if (UNLIKELY(prefix_evex & 0x80) && DESC_MODRM_IDX(desc) == 0)
                    return FD_ERR_UD;

                // EVEX.b for memory-operand without broadcast support is UD.
                if (UNLIKELY(prefix_evex & 0x10)) {
                    if (UNLIKELY(!DESC_EVEX_BCST(desc)))
                        return FD_ERR_UD;
                    if (UNLIKELY(DESC_EVEX_BCST16(desc)))
                        dispscale = 1;
                    else
                        dispscale = prefix_rex & PREFIX_REXW ? 3 : 2;
                    instr->segment |= dispscale << 6; // Store broadcast size
                    op_modrm->type = FD_OT_MEMBCST;
                } else {
                    dispscale = op_modrm->size - 1;
                    op_modrm->type = FD_OT_MEM;
                }
            } else {
                op_modrm->type = FD_OT_MEM;
            }

            // 16-bit address size implies different ModRM encoding
            if (UNLIKELY(addr_size == 1)) {
                ASSUME(mode == DECODE_32);
                if (UNLIKELY(DESC_VSIB(desc))) // 16-bit addr size + VSIB is UD
                    return FD_ERR_UD;
                if (rm < 6)
                    op_modrm->misc = rm & 1 ? FD_REG_DI : FD_REG_SI;
                else
                    op_modrm->misc = FD_REG_NONE;

                if (rm < 4)
                    op_modrm->reg = rm & 2 ? FD_REG_BP : FD_REG_BX;
                else if (rm < 6 || (op_byte & 0xc7) == 0x06)
                    op_modrm->reg = FD_REG_NONE;
                else
                    op_modrm->reg = rm == 6 ? FD_REG_BP : FD_REG_BX;

                const uint8_t* dispbase = &buffer[off];
                if (op_byte & 0x40) {
                    if (UNLIKELY((off += 1) > len))
                        return FD_ERR_PARTIAL;
                    instr->disp = (int8_t) LOAD_LE_1(dispbase) << dispscale;
                } else if (op_byte & 0x80 || (op_byte & 0xc7) == 0x06) {
                    if (UNLIKELY((off += 2) > len))
                        return FD_ERR_PARTIAL;
                    instr->disp = (int16_t) LOAD_LE_2(dispbase);
                } else {
                    instr->disp = 0;
                }
                goto end_modrm;
            }

            // SIB byte
            uint8_t base = rm;
            if (rm == 4) {
                if (UNLIKELY(off >= len))
                    return FD_ERR_PARTIAL;
                uint8_t sib = buffer[off++];
                unsigned scale = sib & 0xc0;
                unsigned idx = (sib & 0x38) >> 3;
                idx += prefix_rex & PREFIX_REXX ? 8 : 0;
                base = sib & 0x07;
                if (idx == 4)
                    idx = FD_REG_NONE;
                op_modrm->misc = scale | idx;
            } else {
                op_modrm->misc = FD_REG_NONE;
            }

            if (UNLIKELY(DESC_VSIB(desc))) {
                // VSIB must have a memory operand with SIB byte.
                if (rm != 4)
                    return FD_ERR_UD;
                _Static_assert(FD_REG_NONE == 0x3f, "unexpected FD_REG_NONE");
                // idx 4 is valid for VSIB
                if ((op_modrm->misc & 0x3f) == FD_REG_NONE)
                    op_modrm->misc &= 0xc4;
                if (prefix_evex) // EVEX.V':EVEX.X:SIB.idx
                    op_modrm->misc |= prefix_evex & 0x8 ? 0 : 0x10;
            }

            // RIP-relative addressing only if SIB-byte is absent
            if (op_byte < 0x40 && rm == 5 && mode == DECODE_64)
                op_modrm->reg = FD_REG_IP;
            else if (op_byte < 0x40 && base == 5)
                op_modrm->reg = FD_REG_NONE;
            else
                op_modrm->reg = base + (prefix_rex & PREFIX_REXB ? 8 : 0);

            const uint8_t* dispbase = &buffer[off];
            if (op_byte & 0x40) {
                if (UNLIKELY((off += 1) > len))
                    return FD_ERR_PARTIAL;
                instr->disp = (int8_t) LOAD_LE_1(dispbase) << dispscale;
            } else if (op_byte & 0x80 || (op_byte < 0x40 && base == 5)) {
                if (UNLIKELY((off += 4) > len))
                    return FD_ERR_PARTIAL;
                instr->disp = (int32_t) LOAD_LE_4(dispbase);
            } else {
                instr->disp = 0;
            }
        end_modrm:;
        }
    }

    if (UNLIKELY(DESC_HAS_VEXREG(desc)))
    {
        FdOp* operand = &instr->operands[DESC_VEXREG_IDX(desc)];
        if (DESC_ZEROREG_VAL(desc)) {
            operand->type = FD_OT_REG;
            operand->size = 1;
            operand->reg = FD_REG_CL;
            operand->misc = FD_RT_GPL;
        } else {
            operand->type = FD_OT_REG;
            // Without VEX prefix, this encodes an implicit register
            operand->size = operand_sizes[DESC_VEXREG_SIZE(desc)];
            if (mode == DECODE_32)
                vex_operand &= 0x7;
            // Note: 32-bit will never UD here. EVEX.V' is caught above already.
            // Note: UD if > 16 for non-VEC. No EVEX-encoded instruction uses
            // EVEX.vvvv to refer to non-vector registers. Verified in parseinstrs.
            operand->reg = vex_operand;

            unsigned reg_ty = DESC_REGTY_VEXREG(desc); // VEC GPL MSK FPU/TMM
            if (prefix_rex & PREFIX_VEX) { // TMM with VEX, FPU otherwise
                // In 64-bit mode: UD if FD_RT_MASK and vex_operand&8 != 0
                if (reg_ty == 2 && vex_operand >= 8)
                    return FD_ERR_UD;
                if (UNLIKELY(reg_ty == 3)) // TMM
                    operand->reg &= 0x7; // TODO: verify
                operand->misc = (06710 >> (3 * reg_ty)) & 0x7;
            } else {
                operand->misc = (04710 >> (3 * reg_ty)) & 0x7;
            }
        }
    }
    else if (vex_operand != 0)
    {
        // TODO: bit 3 ignored in 32-bit mode? unverified
        return FD_ERR_UD;
    }

    uint32_t imm_control = UNLIKELY(DESC_IMM_CONTROL(desc));
    if (LIKELY(!imm_control)) {
    } else if (UNLIKELY(imm_control == 1))
    {
        // 1 = immediate constant 1, used for shifts
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_IMM;
        operand->size = 1;
        instr->imm = 1;
    }
    else if (UNLIKELY(imm_control == 2))
    {
        // 2 = memory, address-sized, used for mov with moffs operand
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_MEM;
        operand->size = operand_sizes[DESC_IMM_SIZE(desc)];
        operand->reg = FD_REG_NONE;
        operand->misc = FD_REG_NONE;

        int moffsz = 1 << addr_size;
        if (UNLIKELY(off + moffsz > len))
            return FD_ERR_PARTIAL;
        if (moffsz == 2)
            instr->disp = LOAD_LE_2(&buffer[off]);
        if (moffsz == 4)
            instr->disp = LOAD_LE_4(&buffer[off]);
        if (LIKELY(moffsz == 8))
            instr->disp = LOAD_LE_8(&buffer[off]);
        off += moffsz;
    }
    else if (UNLIKELY(imm_control == 3))
    {
        // 3 = register in imm8[7:4], used for RVMR encoding with VBLENDVP[SD]
        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_REG;
        operand->size = op_size;
        operand->misc = FD_RT_VEC;

        if (UNLIKELY(off + 1 > len))
            return FD_ERR_PARTIAL;
        uint8_t reg = (uint8_t) LOAD_LE_1(&buffer[off]);
        off += 1;

        if (mode == DECODE_32)
            reg &= 0x7f;
        operand->reg = reg >> 4;
        instr->imm = reg & 0x0f;
    }
    else if (imm_control != 0)
    {
        // 4/5 = immediate, operand-sized/8 bit
        // 6/7 = offset, operand-sized/8 bit (used for jumps/calls)
        int imm_byte = imm_control & 1;
        int imm_offset = imm_control & 2;

        FdOp* operand = &instr->operands[DESC_IMM_IDX(desc)];
        operand->type = FD_OT_IMM;

        if (imm_byte) {
            if (UNLIKELY(off + 1 > len))
                return FD_ERR_PARTIAL;
            instr->imm = (int8_t) LOAD_LE_1(&buffer[off++]);
            operand->size = DESC_IMM_SIZE(desc) & 1 ? 1 : op_size;
        } else {
            operand->size = operand_sizes[DESC_IMM_SIZE(desc)];

            uint8_t imm_size;
            if (UNLIKELY(instr->type == FDI_RET || instr->type == FDI_RETF ||
                         instr->type == FDI_SSE_EXTRQ ||
                         instr->type == FDI_SSE_INSERTQ))
                imm_size = 2;
            else if (UNLIKELY(instr->type == FDI_JMPF || instr->type == FDI_CALLF))
                imm_size = (1 << op_size >> 1) + 2;
            else if (UNLIKELY(instr->type == FDI_ENTER))
                imm_size = 3;
            else if (instr->type == FDI_MOVABS)
                imm_size = (1 << op_size >> 1);
            else
                imm_size = op_size == 2 ? 2 : 4;

            if (UNLIKELY(off + imm_size > len))
                return FD_ERR_PARTIAL;

            if (imm_size == 2)
                instr->imm = (int16_t) LOAD_LE_2(&buffer[off]);
            else if (imm_size == 3)
                instr->imm = LOAD_LE_3(&buffer[off]);
            else if (imm_size == 4)
                instr->imm = (int32_t) LOAD_LE_4(&buffer[off]);
            else if (imm_size == 6)
                instr->imm = LOAD_LE_4(&buffer[off]) | LOAD_LE_2(&buffer[off+4]) << 32;
            else if (imm_size == 8)
                instr->imm = (int64_t) LOAD_LE_8(&buffer[off]);
            off += imm_size;
        }

        if (imm_offset)
        {
            if (instr->address != 0)
                instr->imm += instr->address + off;
            else
                operand->type = FD_OT_OFF;
        }
    }

skip_modrm:
    if (UNLIKELY(prefixes[PF_LOCK])) {
        if (!DESC_LOCK(desc) || instr->operands[0].type != FD_OT_MEM)
            return FD_ERR_UD;
        instr->flags |= FD_FLAG_LOCK;
    }

    if (UNLIKELY(DESC_LEGACY(desc))) {
        // Without REX prefix, convert one-byte GP regs to high-byte regs
        // This actually only applies to SZ8/MOVSX/MOVZX; but no VEX-encoded
        // instructions have a byte-sized GP register in the first two operands.
        if (!(prefix_rex & PREFIX_REX)) {
            for (int i = 0; i < 2; i++) {
                FdOp* operand = &instr->operands[i];
                if (operand->type == FD_OT_NONE)
                    break;
                if (operand->type == FD_OT_REG && operand->misc == FD_RT_GPL &&
                    operand->size == 1 && operand->reg >= 4)
                    operand->misc = FD_RT_GPH;
            }
        }

        if (instr->type == FDI_XCHG_NOP) {
            // Only 4890, 90, and 6690 are true NOPs.
            if (instr->operands[0].reg == 0 && instr->operands[1].reg == 0) {
                instr->operands[0].type = FD_OT_NONE;
                instr->operands[1].type = FD_OT_NONE;
                instr->type = FDI_NOP;
            } else {
                instr->type = FDI_XCHG;
            }
        }

        if (UNLIKELY(instr->type == FDI_3DNOW)) {
            unsigned opc3dn = instr->imm;
            if (opc3dn & 0x40)
                return FD_ERR_UD;
            uint64_t msk = opc3dn & 0x80 ? 0x88d144d144d14400 : 0x30003000;
            if (!(msk >> (opc3dn & 0x3f) & 1))
                return FD_ERR_UD;
        }

        instr->operandsz = UNLIKELY(DESC_INSTR_WIDTH(desc)) ? op_size - 1 : 0;
    } else {
        instr->operandsz = 0;
    }

    instr->size = off;

    return off;
}

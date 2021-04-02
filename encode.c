
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec-enc.h>


#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

enum {
    // 16:17 = escape
    OPC_0F = 1 << 16,
    OPC_0F38 = 2 << 16,
    OPC_0F3A = 3 << 16,
    OPC_ESCAPE_MSK = 3 << 16,
    OPC_VSIB = 1 << 18,
    OPC_66 = 1 << 19,
    OPC_F2 = 1 << 20,
    OPC_F3 = 1 << 21,
    OPC_REXW = 1 << 22,
    OPC_LOCK = 1 << 23,
    OPC_VEX = 1 << 24,
    OPC_VEXL = 1 << 25,
    OPC_REXR = 1 << 28,
    OPC_REXX = 1 << 27,
    OPC_REXB = 1 << 26,
    OPC_REX = 1 << 29,
    OPC_67 = 1 << 30,
};

#define OPC_SEG_IDX 31
#define OPC_SEG_MSK (0x7l << OPC_SEG_IDX)
#define OPC_VEXOP_IDX 34
#define OPC_VEXOP_MSK (0xfl << OPC_VEXOP_IDX)

static bool op_mem(FeOp op) { return op < 0; }
static bool op_reg(FeOp op) { return op >= 0; }
static bool op_reg_gpl(FeOp op) { return (op & ~0xf) == 0x100; }
static bool op_reg_gph(FeOp op) { return (op & ~0x3) == 0x204; }
static bool op_reg_seg(FeOp op) { return (op & ~0x7) == 0x300 && (op & 7) < 6; }
static bool op_reg_fpu(FeOp op) { return (op & ~0x7) == 0x400; }
static bool op_reg_mmx(FeOp op) { return (op & ~0x7) == 0x500; }
static bool op_reg_xmm(FeOp op) { return (op & ~0xf) == 0x600; }
static int64_t op_mem_offset(FeOp op) { return (int32_t) op; }
static unsigned op_mem_base(FeOp op) { return (op >> 32) & 0xfff; }
static unsigned op_mem_idx(FeOp op) { return (op >> 44) & 0xfff; }
static unsigned op_mem_scale(FeOp op) { return (op >> 56) & 0xf; }
static unsigned op_reg_idx(FeOp op) { return op & 0xff; }
static bool op_imm_n(FeOp imm, unsigned immsz) {
    if (immsz == 0 && !imm) return true;
    if (immsz == 1 && (int8_t) imm == imm) return true;
    if (immsz == 2 && (int16_t) imm == imm) return true;
    if (immsz == 3 && (imm&0xffffff) == imm) return true;
    if (immsz == 4 && (int32_t) imm == imm) return true;
    if (immsz == 8 && (int64_t) imm == imm) return true;
    return false;
}

static
unsigned
opc_size(uint64_t opc)
{
    unsigned res = 1;
    if (opc & OPC_VEX) {
        if ((opc & (OPC_REXW|OPC_REXX|OPC_REXB|OPC_ESCAPE_MSK)) != OPC_0F)
            res += 3;
        else
            res += 2;
    } else {
        if (opc & OPC_LOCK) res++;
        if (opc & OPC_66) res++;
        if (opc & OPC_F2) res++;
        if (opc & OPC_F3) res++;
        if (opc & (OPC_REX|OPC_REXW|OPC_REXR|OPC_REXX|OPC_REXB)) res++;
        if (opc & OPC_ESCAPE_MSK) res++;
        if ((opc & OPC_ESCAPE_MSK) == OPC_0F38 || (opc & OPC_ESCAPE_MSK) == OPC_0F3A) res++;
    }
    if (opc & OPC_SEG_MSK) res++;
    if (opc & OPC_67) res++;
    if ((opc & 0xc000) == 0xc000) res++;
    return res;
}

static
int
enc_opc(uint8_t** restrict buf, uint64_t opc)
{
    if (opc & OPC_SEG_MSK)
        *(*buf)++ = (0x65643e362e2600 >> (8 * ((opc >> OPC_SEG_IDX) & 7))) & 0xff;
    if (opc & OPC_67) *(*buf)++ = 0x67;
    if (opc & OPC_VEX) {
        bool vex3 = (opc & (OPC_REXW|OPC_REXX|OPC_REXB|OPC_ESCAPE_MSK)) != OPC_0F;
        unsigned pp = 0;
        if (opc & OPC_66) pp = 1;
        if (opc & OPC_F3) pp = 2;
        if (opc & OPC_F2) pp = 3;
        *(*buf)++ = 0xc4 | !vex3;
        unsigned b2 = pp | (opc & OPC_VEXL ? 0x4 : 0);
        if (vex3) {
            unsigned b1 = (opc & OPC_ESCAPE_MSK) >> 16;
            if (!(opc & OPC_REXR)) b1 |= 0x80;
            if (!(opc & OPC_REXX)) b1 |= 0x40;
            if (!(opc & OPC_REXB)) b1 |= 0x20;
            *(*buf)++ = b1;
            if (opc & OPC_REXW) b2 |= 0x80;
        } else {
            if (!(opc & OPC_REXR)) b2 |= 0x80;
        }
        b2 |= (~((opc & OPC_VEXOP_MSK) >> OPC_VEXOP_IDX) & 0xf) << 3;
        *(*buf)++ = b2;
    } else {
        if (opc & OPC_LOCK) *(*buf)++ = 0xF0;
        if (opc & OPC_66) *(*buf)++ = 0x66;
        if (opc & OPC_F2) *(*buf)++ = 0xF2;
        if (opc & OPC_F3) *(*buf)++ = 0xF3;
        if (opc & (OPC_REX|OPC_REXW|OPC_REXR|OPC_REXX|OPC_REXB))
        {
            unsigned rex = 0x40;
            if (opc & OPC_REXW) rex |= 8;
            if (opc & OPC_REXR) rex |= 4;
            if (opc & OPC_REXX) rex |= 2;
            if (opc & OPC_REXB) rex |= 1;
            *(*buf)++ = rex;
        }
        if (opc & OPC_ESCAPE_MSK) *(*buf)++ = 0x0F;
        if ((opc & OPC_ESCAPE_MSK) == OPC_0F38) *(*buf)++ = 0x38;
        if ((opc & OPC_ESCAPE_MSK) == OPC_0F3A) *(*buf)++ = 0x3A;
    }
    *(*buf)++ = opc & 0xff;
    if ((opc & 0xc000) == 0xc000) *(*buf)++ = (opc >> 8) & 0xff;
    return 0;
}

static
int
enc_imm(uint8_t** restrict buf, uint64_t imm, unsigned immsz)
{
    if (!op_imm_n(imm, immsz)) return -1;
    for (unsigned i = 0; i < immsz; i++)
        *(*buf)++ = imm >> 8 * i;
    return 0;
}

static
int
enc_o(uint8_t** restrict buf, uint64_t opc, uint64_t op0)
{
    if (op_reg_idx(op0) & 0x8) opc |= OPC_REXB;

    bool has_rex = !!(opc & (OPC_REX|OPC_REXW|OPC_REXR|OPC_REXX|OPC_REXB));
    if (has_rex && op_reg_gph(op0)) return -1;

    if (enc_opc(buf, opc)) return -1;
    *(*buf - 1) = (*(*buf - 1) & 0xf8) | (op_reg_idx(op0) & 0x7);
    return 0;
}

static
int
enc_mr(uint8_t** restrict buf, uint64_t opc, uint64_t op0, uint64_t op1,
       unsigned immsz)
{
    // If !op_reg(op1), it is a constant value for ModRM.reg
    if (op_reg(op0) && (op_reg_idx(op0) & 0x8)) opc |= OPC_REXB;
    if (op_mem(op0) && (op_mem_base(op0) & 0x8)) opc |= OPC_REXB;
    if (op_mem(op0) && (op_mem_idx(op0) & 0x8)) opc |= OPC_REXX;
    if (op_reg(op1) && op_reg_idx(op1) & 0x8) opc |= OPC_REXR;

    bool has_rex = !!(opc & (OPC_REX|OPC_REXW|OPC_REXR|OPC_REXX|OPC_REXB));
    if (has_rex && (op_reg_gph(op0) || op_reg_gph(op1))) return -1;
    unsigned opcsz = opc_size(opc);

    int mod = 0, reg = op1 & 7, rm;
    int scale = 0, idx = 4, base = 0;
    int32_t off = 0;
    bool withsib = false, mod0off = false;
    if (op_reg(op0))
    {
        mod = 3;
        rm = op_reg_idx(op0) & 7;
    }
    else
    {
        off = op_mem_offset(op0);

        if (!!op_mem_idx(op0) != !!op_mem_scale(op0)) return -1;
        if (!op_mem_idx(op0) && (opc & OPC_VSIB)) return -1;
        if (op_mem_idx(op0))
        {
            if (opc & OPC_VSIB)
            {
                if (!op_reg_xmm(op_mem_idx(op0))) return -1;
            }
            else
            {
                if (!op_reg_gpl(op_mem_idx(op0))) return -1;
                if (op_reg_idx(op_mem_idx(op0)) == 4) return -1;
            }
            idx = op_mem_idx(op0) & 7;
            int scalabs = op_mem_scale(op0);
            if (scalabs & (scalabs - 1)) return -1;
            scale = (scalabs & 0xA ? 1 : 0) | (scalabs & 0xC ? 2 : 0);
            withsib = true;
        }

        if (!op_mem_base(op0))
        {
            rm = 5;
            mod0off = true;
            withsib = true;
        }
        else if (op_mem_base(op0) == FE_IP)
        {
            rm = 5;
            mod0off = true;
            // Adjust offset, caller doesn't know instruction length.
            off -= opcsz + 5 + immsz;
            if (withsib) return -1;
        }
        else
        {
            if (!op_reg_gpl(op_mem_base(op0))) return -1;
            rm = op_reg_idx(op_mem_base(op0)) & 7;
            if (rm == 5) mod = 1;
        }

        if (off && op_imm_n(off, 1) && !mod0off)
            mod = 1;
        else if (off && !mod0off)
            mod = 2;

        if (withsib || rm == 4)
        {
            base = rm;
            rm = 4;
        }
    }

    unsigned dispsz = mod == 1 ? 1 : (mod == 2 || mod0off) ? 4 : 0;
    if (opcsz + 1 + (mod != 3 && rm == 4) + dispsz + immsz > 15) return -1;

    if (enc_opc(buf, opc)) return -1;
    *(*buf)++ = (mod << 6) | (reg << 3) | rm;
    if (mod != 3 && rm == 4)
        *(*buf)++ = (scale << 6) | (idx << 3) | base;
    return enc_imm(buf, off, dispsz);
}

typedef enum {
    ENC_INVALID = 0,
    ENC_NP,
    ENC_M, ENC_M1, ENC_MI, ENC_MC, ENC_MR, ENC_RM, ENC_RMA, ENC_MRI, ENC_RMI, ENC_MRC,
    ENC_AM, ENC_MA,
    ENC_I, ENC_IA, ENC_O, ENC_OI, ENC_OA, ENC_S, ENC_A, ENC_D, ENC_FD, ENC_TD,
    ENC_RVM, ENC_RVMI, ENC_RVMR, ENC_RMV, ENC_VM, ENC_VMI, ENC_MVR,
    ENC_MAX
} Encoding;

struct EncodingInfo {
    uint8_t modrm : 2;
    uint8_t modreg : 2;
    uint8_t vexreg : 2;
    uint8_t immidx : 2;
    uint8_t immctl : 3;
    uint8_t zregidx : 2;
    uint8_t zregval : 1;
};

const struct EncodingInfo encoding_infos[ENC_MAX] = {
    [ENC_INVALID] = { 0 },
    [ENC_NP]      = { 0 },
    [ENC_M]       = { .modrm = 0^3 },
    [ENC_M1]      = { .modrm = 0^3, .immctl = 1, .immidx = 1 },
    [ENC_MI]      = { .modrm = 0^3, .immctl = 4, .immidx = 1 },
    [ENC_MC]      = { .modrm = 0^3, .zregidx = 1^3, .zregval = 1 },
    [ENC_MR]      = { .modrm = 0^3, .modreg = 1^3 },
    [ENC_RM]      = { .modrm = 1^3, .modreg = 0^3 },
    [ENC_RMA]     = { .modrm = 1^3, .modreg = 0^3, .zregidx = 2^3, .zregval = 0 },
    [ENC_MRI]     = { .modrm = 0^3, .modreg = 1^3, .immctl = 4, .immidx = 2 },
    [ENC_RMI]     = { .modrm = 1^3, .modreg = 0^3, .immctl = 4, .immidx = 2 },
    [ENC_MRC]     = { .modrm = 0^3, .modreg = 1^3, .zregidx = 2^3, .zregval = 1 },
    [ENC_AM]      = { .modrm = 1^3, .zregidx = 0^3, .zregval = 0 },
    [ENC_MA]      = { .modrm = 0^3, .zregidx = 1^3, .zregval = 0 },
    [ENC_I]       = { .immctl = 4, .immidx = 0 },
    [ENC_IA]      = { .zregidx = 0^3, .zregval = 0, .immctl = 4, .immidx = 1 },
    [ENC_O]       = { .modreg = 0^3 },
    [ENC_OI]      = { .modreg = 0^3, .immctl = 4, .immidx = 1 },
    [ENC_OA]      = { .modreg = 0^3, .zregidx = 1^3, .zregval = 0 },
    [ENC_S]       = { 0 },
    [ENC_A]       = { .zregidx = 0^3, .zregval = 0 },
    [ENC_D]       = { .immctl = 6, .immidx = 0 },
    [ENC_FD]      = { .zregidx = 0^3, .zregval = 0, .immctl = 2, .immidx = 1 },
    [ENC_TD]      = { .zregidx = 1^3, .zregval = 0, .immctl = 2, .immidx = 0 },
    [ENC_RVM]     = { .modrm = 2^3, .modreg = 0^3, .vexreg = 1^3 },
    [ENC_RVMI]    = { .modrm = 2^3, .modreg = 0^3, .vexreg = 1^3, .immctl = 4, .immidx = 3 },
    [ENC_RVMR]    = { .modrm = 2^3, .modreg = 0^3, .vexreg = 1^3, .immctl = 3, .immidx = 3 },
    [ENC_RMV]     = { .modrm = 1^3, .modreg = 0^3, .vexreg = 2^3 },
    [ENC_VM]      = { .modrm = 1^3, .vexreg = 0^3 },
    [ENC_VMI]     = { .modrm = 1^3, .vexreg = 0^3, .immctl = 4, .immidx = 2 },
    [ENC_MVR]     = { .modrm = 0^3, .modreg = 1^3, .vexreg = 1^3 },
};

struct EncodeDesc {
    uint64_t opc : 26;
    uint64_t enc : 5;
    uint64_t immsz : 4;
    uint64_t alt : 13;
    uint64_t tys : 16;
};

static const struct EncodeDesc descs[] = {
#include <fadec-enc-cases.inc>
};

int
fe_enc64_impl(uint8_t** restrict buf, uint64_t mnem, FeOp op0, FeOp op1,
              FeOp op2, FeOp op3)
{
    uint8_t* buf_start = *buf;
    uint64_t ops[4] = {op0, op1, op2, op3};

    uint64_t desc_idx = mnem & FE_MNEM_MASK;
    if (UNLIKELY(desc_idx >= FE_MNEM_MAX)) goto fail;

    do
    {
        const struct EncodeDesc* desc = &descs[desc_idx];
        const struct EncodingInfo* ei = &encoding_infos[desc->enc];
        uint64_t opc = desc->opc;
        int64_t imm = 0xcc;
        unsigned immsz = desc->immsz;

        if (UNLIKELY(desc->enc == ENC_INVALID)) goto fail;

        if (ei->zregidx)
            if (op_reg_idx(ops[ei->zregidx^3]) != ei->zregval) goto next;

        for (int i = 0; i < 4; i++) {
            unsigned ty = (desc->tys >> (4 * i)) & 0xf;
            FeOp op = ops[i];
            if (ty == 0x0) continue;
            if (ty == 0xf && !op_mem(op)) goto next;
            if (ty == 0x1 && !op_reg_gpl(op)) goto next;
            if (ty == 0x2 && !op_reg_gpl(op) && !op_reg_gph(op)) goto next;
            if (ty == 0x2 && op_reg_gpl(op) && op >= FE_SP) opc |= OPC_REX;
            if (ty == 0x3 && !op_reg_seg(op)) goto next;
            if (ty == 0x4 && !op_reg_fpu(op)) goto next;
            if (ty == 0x5 && !op_reg_mmx(op)) goto next;
            if (ty == 0x6 && !op_reg_xmm(op)) goto next;
            if (UNLIKELY(ty >= 7 && ty < 0xf)) goto next; // TODO: support BND, CR, DR
        }

        if (UNLIKELY(mnem & FE_ADDR32))
            opc |= OPC_67;
        if (UNLIKELY(mnem & FE_SEG_MASK))
            opc |= (mnem & FE_SEG_MASK) << (OPC_SEG_IDX - 16);
        if (UNLIKELY(desc->enc == ENC_S)) {
            if ((op_reg_idx(op0) << 3 & 0x20) != (opc & 0x20)) goto next;
            opc |= op_reg_idx(op0) << 3;
        }

        if (ei->immctl > 0) {
            imm = ops[ei->immidx];
            if (ei->immctl == 2) {
                immsz = UNLIKELY(mnem & FE_ADDR32) ? 4 : 8;
                if (immsz == 4) imm = (int32_t) imm; // address are zero-extended
            }
            if (ei->immctl == 3)
                imm = op_reg_idx(imm) << 4;
            if (ei->immctl == 6) {
                if (UNLIKELY(mnem & FE_JMPL) && desc->alt) goto next;
                imm -= (int64_t) *buf + opc_size(opc) + immsz;
            }
            if (UNLIKELY(ei->immctl == 1) && imm != 1) goto next;
            if (ei->immctl >= 2 && !op_imm_n(imm, immsz)) goto next;
        }

        // NOP has no operands, so this must be the 32-bit OA XCHG
        if ((desc->opc & ~7) == 0x90 && ops[0] == FE_AX) goto next;

        if (ei->vexreg)
            opc |= ((uint64_t) op_reg_idx(ops[ei->vexreg^3])) << OPC_VEXOP_IDX;

        if (ei->modrm) {
            FeOp modreg = ei->modreg ? ops[ei->modreg^3] : (opc & 0xff00) >> 8;
            if (enc_mr(buf, opc, ops[ei->modrm^3], modreg, immsz)) goto fail;
        } else if (ei->modreg) {
            if (enc_o(buf, opc, ops[ei->modreg^3])) goto fail;
        } else {
            if (enc_opc(buf, opc)) goto fail;
        }

        if (ei->immctl >= 2)
            if (enc_imm(buf, imm, immsz)) goto fail;

        return 0;

    next:
        desc_idx = desc->alt;
    } while (desc_idx != 0);

fail:
    // Don't advance buffer on error; though we shouldn't write anything.
    *buf = buf_start;
    return -1;
}

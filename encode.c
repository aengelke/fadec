
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec-enc.h>


#ifdef __GNUC__
#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

#define OPC_66 0x80000
#define OPC_F2 0x100000
#define OPC_F3 0x200000
#define OPC_REXW 0x400000
#define OPC_LOCK 0x800000
#define OPC_VEXL0 0x1000000
#define OPC_VEXL1 0x1800000
#define OPC_EVEXL0 0x2000000
#define OPC_EVEXL1 0x2800000
#define OPC_EVEXL2 0x3000000
#define OPC_EVEXL3 0x3800000
#define OPC_EVEXB 0x4000000
#define OPC_VSIB 0x8000000
#define OPC_67 FE_ADDR32
#define OPC_SEG_MSK 0xe0000000
#define OPC_JMPL FE_JMPL
#define OPC_MASK_MSK 0x1e00000000
#define OPC_USER_MSK (OPC_67|OPC_SEG_MSK|OPC_MASK_MSK)
#define OPC_FORCE_SIB 0x2000000000
#define OPC_GPH_OP0 0x200000000000
#define OPC_GPH_OP1 0x400000000000

#define EPFX_REX_MSK 0x0f
#define EPFX_REX 0x08
#define EPFX_REXR 0x04
#define EPFX_REXX 0x02
#define EPFX_REXB 0x01
#define EPFX_VVVV_IDX 4

static bool op_mem(FeOp op) { return op < 0; }
static bool op_reg(FeOp op) { return op >= 0; }
static bool op_reg_gpl(FeOp op) { return (op & ~0xf) == 0x100; }
static bool op_reg_gph(FeOp op) { return (op & ~0x3) == 0x204; }
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
opc_size(uint64_t opc, uint64_t epfx)
{
    unsigned res = 1;
    if (UNLIKELY(opc & OPC_EVEXL0)) {
        res += 4;
    } else if (UNLIKELY(opc & OPC_VEXL0)) {
        if (opc & (OPC_REXW|0x20000) || epfx & (EPFX_REXX|EPFX_REXB))
            res += 3;
        else
            res += 2;
    } else {
        if (opc & OPC_LOCK) res++;
        if (opc & OPC_66) res++;
        if (opc & (OPC_F2|OPC_F3)) res++;
        if (opc & OPC_REXW || epfx & EPFX_REX_MSK) res++;
        if (opc & 0x30000) res++;
        if (opc & 0x20000) res++;
    }
    if (opc & OPC_SEG_MSK) res++;
    if (opc & OPC_67) res++;
    if (opc & 0x8000) res++;
    return res;
}

static
int
enc_opc(uint8_t** restrict buf, uint64_t opc, uint64_t epfx)
{
    if (opc & OPC_SEG_MSK)
        *(*buf)++ = (0x65643e362e2600 >> (8 * ((opc >> 29) & 7))) & 0xff;
    if (opc & OPC_67) *(*buf)++ = 0x67;
    if (opc & OPC_EVEXL0) {
        return -1;
    } else if (opc & OPC_VEXL0) {
        bool vex3 = opc & (OPC_REXW|0x20000) || epfx & (EPFX_REXX|EPFX_REXB);
        unsigned pp = 0;
        if (opc & OPC_66) pp = 1;
        if (opc & OPC_F3) pp = 2;
        if (opc & OPC_F2) pp = 3;
        *(*buf)++ = 0xc4 | !vex3;
        unsigned b2 = pp | (opc & 0x800000 ? 0x4 : 0);
        if (vex3) {
            unsigned b1 = opc >> 16 & 3;
            if (!(epfx & EPFX_REXR)) b1 |= 0x80;
            if (!(epfx & EPFX_REXX)) b1 |= 0x40;
            if (!(epfx & EPFX_REXB)) b1 |= 0x20;
            *(*buf)++ = b1;
            if (opc & OPC_REXW) b2 |= 0x80;
        } else {
            if (!(epfx & EPFX_REXR)) b2 |= 0x80;
        }
        b2 |= (~(epfx >> EPFX_VVVV_IDX) & 0xf) << 3;
        *(*buf)++ = b2;
    } else {
        if (opc & OPC_LOCK) *(*buf)++ = 0xF0;
        if (opc & OPC_66) *(*buf)++ = 0x66;
        if (opc & OPC_F2) *(*buf)++ = 0xF2;
        if (opc & OPC_F3) *(*buf)++ = 0xF3;
        if (opc & OPC_REXW || epfx & (EPFX_REX_MSK)) {
            unsigned rex = 0x40;
            if (opc & OPC_REXW) rex |= 8;
            if (epfx & EPFX_REXR) rex |= 4;
            if (epfx & EPFX_REXX) rex |= 2;
            if (epfx & EPFX_REXB) rex |= 1;
            *(*buf)++ = rex;
        }
        if (opc & 0x30000) *(*buf)++ = 0x0F;
        if ((opc & 0x30000) == 0x20000) *(*buf)++ = 0x38;
        if ((opc & 0x30000) == 0x30000) *(*buf)++ = 0x3A;
    }
    *(*buf)++ = opc & 0xff;
    if (opc & 0x8000) *(*buf)++ = (opc >> 8) & 0xff;
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
enc_o(uint8_t** restrict buf, uint64_t opc, uint64_t epfx, uint64_t op0)
{
    if (op_reg_idx(op0) & 0x8) epfx |= EPFX_REXB;

    bool has_rex = opc & OPC_REXW || epfx & EPFX_REX_MSK;
    if (has_rex && op_reg_gph(op0)) return -1;

    if (enc_opc(buf, opc, epfx)) return -1;
    *(*buf - 1) = (*(*buf - 1) & 0xf8) | (op_reg_idx(op0) & 0x7);
    return 0;
}

static
int
enc_mr(uint8_t** restrict buf, uint64_t opc, uint64_t epfx, uint64_t op0,
       uint64_t op1, unsigned immsz)
{
    // If !op_reg(op1), it is a constant value for ModRM.reg
    if (op_reg(op0) && (op_reg_idx(op0) & 0x8)) epfx |= EPFX_REXB;
    if (op_mem(op0) && (op_mem_base(op0) & 0x8)) epfx |= EPFX_REXB;
    if (op_mem(op0) && (op_mem_idx(op0) & 0x8)) epfx |= EPFX_REXX;
    if (op_reg(op1) && op_reg_idx(op1) & 0x8) epfx |= EPFX_REXR;

    bool has_rex = opc & OPC_REXW || epfx & EPFX_REX_MSK;
    if (has_rex && (op_reg_gph(op0) || op_reg_gph(op1))) return -1;

    if (LIKELY(op_reg(op0))) {
        if (enc_opc(buf, opc, epfx)) return -1;
        *(*buf)++ = 0xc0 | ((op_reg_idx(op1) & 7) << 3) | (op_reg_idx(op0) & 7);
        return 0;
    }

    unsigned opcsz = opc_size(opc, epfx);

    int mod = 0, reg = op1 & 7, rm;
    int scale = 0, idx = 4, base = 0;
    int32_t off = op_mem_offset(op0);
    bool withsib = opc & OPC_FORCE_SIB;

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

    unsigned dispsz = 0;
    if (!op_mem_base(op0))
    {
        base = 5;
        rm = 4;
        dispsz = 4;
    }
    else if (op_mem_base(op0) == FE_IP)
    {
        rm = 5;
        dispsz = 4;
        // Adjust offset, caller doesn't know instruction length.
        off -= opcsz + 5 + immsz;
        if (withsib) return -1;
    }
    else
    {
        if (!op_reg_gpl(op_mem_base(op0))) return -1;
        rm = op_reg_idx(op_mem_base(op0)) & 7;
        if (withsib || rm == 4) {
            base = rm;
            rm = 4;
        }
        if (off) {
            mod = op_imm_n(off, 1) ? 0x40 : 0x80;
            dispsz = op_imm_n(off, 1) ? 1 : 4;
        } else if (rm == 5) {
            mod = 0x40;
            dispsz = 1;
        }
    }

    if (opcsz + 1 + (rm == 4) + dispsz + immsz > 15) return -1;

    if (enc_opc(buf, opc, epfx)) return -1;
    *(*buf)++ = mod | (reg << 3) | rm;
    if (UNLIKELY(rm == 4))
        *(*buf)++ = (scale << 6) | (idx << 3) | base;
    return enc_imm(buf, off, dispsz);
}

typedef enum {
    ENC_NP, ENC_M, ENC_R,
    ENC_M1, ENC_MI, ENC_MC, ENC_MR, ENC_RM, ENC_RMA, ENC_MRI, ENC_RMI, ENC_MRC,
    ENC_AM, ENC_MA,
    ENC_I, ENC_IA, ENC_O, ENC_OI, ENC_OA, ENC_S, ENC_A, ENC_D, ENC_FD, ENC_TD,
    ENC_RVM, ENC_RVMI, ENC_RVMR, ENC_RMV, ENC_VM, ENC_VMI, ENC_MVR, ENC_MRV,
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
    [ENC_NP]      = { 0 },
    [ENC_M]       = { .modrm = 0x0^3 },
    [ENC_R]       = { .modreg = 0x0^3 },
    [ENC_M1]      = { .modrm = 0x0^3, .immctl = 1, .immidx = 1 },
    [ENC_MI]      = { .modrm = 0x0^3, .immctl = 4, .immidx = 1 },
    [ENC_MC]      = { .modrm = 0x0^3, .zregidx = 0x1^3, .zregval = 1 },
    [ENC_MR]      = { .modrm = 0x0^3, .modreg = 0x1^3 },
    [ENC_RM]      = { .modrm = 0x1^3, .modreg = 0x0^3 },
    [ENC_RMA]     = { .modrm = 0x1^3, .modreg = 0x0^3, .zregidx = 0x2^3, .zregval = 0 },
    [ENC_MRI]     = { .modrm = 0x0^3, .modreg = 0x1^3, .immctl = 4, .immidx = 2 },
    [ENC_RMI]     = { .modrm = 0x1^3, .modreg = 0x0^3, .immctl = 4, .immidx = 2 },
    [ENC_MRC]     = { .modrm = 0x0^3, .modreg = 0x1^3, .zregidx = 0x2^3, .zregval = 1 },
    [ENC_AM]      = { .modrm = 0x1^3, .zregidx = 0x0^3, .zregval = 0 },
    [ENC_MA]      = { .modrm = 0x0^3, .zregidx = 0x1^3, .zregval = 0 },
    [ENC_I]       = { .immctl = 4, .immidx = 0 },
    [ENC_IA]      = { .zregidx = 0x0^3, .zregval = 0, .immctl = 4, .immidx = 1 },
    [ENC_O]       = { .modreg = 0x0^3 },
    [ENC_OI]      = { .modreg = 0x0^3, .immctl = 4, .immidx = 1 },
    [ENC_OA]      = { .modreg = 0x0^3, .zregidx = 0x1^3, .zregval = 0 },
    [ENC_S]       = { 0 },
    [ENC_A]       = { .zregidx = 0x0^3, .zregval = 0 },
    [ENC_D]       = { .immctl = 6, .immidx = 0 },
    [ENC_FD]      = { .zregidx = 0x0^3, .zregval = 0, .immctl = 2, .immidx = 1 },
    [ENC_TD]      = { .zregidx = 0x1^3, .zregval = 0, .immctl = 2, .immidx = 0 },
    [ENC_RVM]     = { .modrm = 0x2^3, .modreg = 0x0^3, .vexreg = 0x1^3 },
    [ENC_RVMI]    = { .modrm = 0x2^3, .modreg = 0x0^3, .vexreg = 0x1^3, .immctl = 4, .immidx = 3 },
    [ENC_RVMR]    = { .modrm = 0x2^3, .modreg = 0x0^3, .vexreg = 0x1^3, .immctl = 3, .immidx = 3 },
    [ENC_RMV]     = { .modrm = 0x1^3, .modreg = 0x0^3, .vexreg = 0x2^3 },
    [ENC_VM]      = { .modrm = 0x1^3, .vexreg = 0x0^3 },
    [ENC_VMI]     = { .modrm = 0x1^3, .vexreg = 0x0^3, .immctl = 4, .immidx = 2 },
    [ENC_MVR]     = { .modrm = 0x0^3, .modreg = 0x2^3, .vexreg = 0x1^3 },
    [ENC_MRV]     = { .modrm = 0x0^3, .modreg = 0x1^3, .vexreg = 0x2^3 },
};

static const uint64_t alt_tab[] = {
#include <fadec-encode-private.inc>
};

int
fe_enc64_impl(uint8_t** restrict buf, uint64_t opc, FeOp op0, FeOp op1,
              FeOp op2, FeOp op3)
{
    uint8_t* buf_start = *buf;
    uint64_t ops[4] = {op0, op1, op2, op3};

    uint64_t epfx = 0;
    // Doesn't change between variants
    if ((opc & OPC_GPH_OP0) && op_reg_gpl(op0) && op0 >= FE_SP)
        epfx |= EPFX_REX;
    else if (!(opc & OPC_GPH_OP0) && op_reg_gph(op0))
        goto fail;
    if ((opc & OPC_GPH_OP1) && op_reg_gpl(op1) && op1 >= FE_SP)
        epfx |= EPFX_REX;
    else if (!(opc & OPC_GPH_OP1) && op_reg_gph(op1))
        goto fail;

try_encode:;
    unsigned enc = (opc >> 51) & 0x1f;
    const struct EncodingInfo* ei = &encoding_infos[enc];

    int64_t imm = 0xcc;
    unsigned immsz = (opc >> 47) & 0xf;

    if (UNLIKELY(ei->zregidx && op_reg_idx(ops[ei->zregidx^3]) != ei->zregval))
        goto next;

    if (UNLIKELY(enc == ENC_S)) {
        if ((op_reg_idx(op0) << 3 & 0x20) != (opc & 0x20)) goto next;
        opc |= op_reg_idx(op0) << 3;
    }

    if (ei->immctl > 0) {
        imm = ops[ei->immidx];
        if (ei->immctl == 2) {
            immsz = UNLIKELY(opc & OPC_67) ? 4 : 8;
            if (immsz == 4) imm = (int32_t) imm; // address are zero-extended
        }
        if (ei->immctl == 3) {
            if (!op_reg_xmm(imm)) goto fail;
            imm = op_reg_idx(imm) << 4;
        }
        if (ei->immctl == 6) {
            if (UNLIKELY(opc & FE_JMPL) && opc >> 56) goto next;
            imm -= (int64_t) *buf + opc_size(opc, epfx) + immsz;
        }
        if (UNLIKELY(ei->immctl == 1) && imm != 1) goto next;
        if (ei->immctl >= 2 && !op_imm_n(imm, immsz)) goto next;
    }

    // NOP has no operands, so this must be the 32-bit OA XCHG
    if ((opc & 0xfffffff) == 0x90 && ops[0] == FE_AX) goto next;

    if (UNLIKELY(enc == ENC_R)) {
        if (enc_mr(buf, opc, epfx, 0, ops[0], immsz)) goto fail;
    } else if (ei->modrm) {
        FeOp modreg = ei->modreg ? ops[ei->modreg^3] : (opc & 0xff00) >> 8;
        if (ei->vexreg)
            epfx |= ((uint64_t) op_reg_idx(ops[ei->vexreg^3])) << EPFX_VVVV_IDX;
        if (enc_mr(buf, opc, epfx, ops[ei->modrm^3], modreg, immsz)) goto fail;
    } else if (ei->modreg) {
        if (enc_o(buf, opc, epfx, ops[ei->modreg^3])) goto fail;
    } else {
        if (enc_opc(buf, opc, epfx)) goto fail;
    }

    if (ei->immctl >= 2)
        if (enc_imm(buf, imm, immsz)) goto fail;

    return 0;

next:;
    uint64_t alt = opc >> 56;
    if (alt) { // try alternative encoding, if available
        opc = alt_tab[alt] | (opc & OPC_USER_MSK);
        goto try_encode;
    }

fail:
    // Don't advance buffer on error; though we shouldn't write anything.
    *buf = buf_start;
    return -1;
}

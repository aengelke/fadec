
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec-enc.h>


#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

enum {
    OPC_0F = 1 << 16,
    OPC_0F38 = (1 << 17) | OPC_0F,
    OPC_0F3A = (1 << 18) | OPC_0F,
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
};

static bool op_mem(uint64_t op) { return (op & 0x8000000000000000) != 0; }
static bool op_reg(uint64_t op) { return (op & 0x8000000000000000) == 0; }
static bool op_reg_gpl(uint64_t op) { return (op & 0xfffffffffffffff0) == 0x100; }
static bool op_reg_gph(uint64_t op) { return (op & 0xfffffffffffffffc) == 0x204; }
static int64_t op_mem_offset(uint64_t op) { return (int32_t) (op & 0x00000000ffffffff); }
static unsigned op_mem_base(uint64_t op) { return (op & 0x00000fff00000000) >> 32; }
static unsigned op_mem_idx(uint64_t op) { return (op & 0x00fff00000000000) >> 44; }
static unsigned op_mem_scale(uint64_t op) { return (op & 0x0f00000000000000) >> 56; }
static unsigned op_reg_idx(uint64_t op) { return (op & 0x00000000000000ff); }
static bool op_imm_n(uint64_t imm, unsigned immsz) {
    if (immsz == 1 && (uint64_t) (int64_t) (int8_t) imm != imm) return false;
    if (immsz == 2 && (uint64_t) (int64_t) (int16_t) imm != imm) return false;
    if (immsz == 4 && (uint64_t) (int64_t) (int32_t) imm != imm) return false;
    return true;
}

static
unsigned
opc_size(uint64_t opc)
{
    if (opc & OPC_VEX) return 0; // TODO: support VEX encoding
    unsigned res = 1;
    if (opc & OPC_66) res++;
    if (opc & OPC_F2) res++;
    if (opc & OPC_F3) res++;
    if (opc & (OPC_REX|OPC_REXW|OPC_REXR|OPC_REXX|OPC_REXB)) res++;
    if (opc & OPC_0F) res++;
    if ((opc & OPC_0F38) == OPC_0F38) res++;
    if ((opc & OPC_0F3A) == OPC_0F3A) res++;
    if ((opc & 0xc000) == 0xc000) res++;
    return res;
}

static
int
enc_opc(uint8_t** restrict buf, uint64_t opc)
{
    if (opc & OPC_VEX) return -1; // TODO: support VEX encoding
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
    if (opc & OPC_0F) *(*buf)++ = 0x0F;
    if ((opc & OPC_0F38) == OPC_0F38) *(*buf)++ = 0x38;
    if ((opc & OPC_0F3A) == OPC_0F3A) *(*buf)++ = 0x3A;
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
enc_mr(uint8_t** restrict buf, uint64_t opc, uint64_t op0, uint64_t op1)
{
    // If !op_reg(op1), it is a constant value for ModRM.reg
    if (op_reg(op0) && (op_reg_idx(op0) & 0x8)) opc |= OPC_REXB;
    if (op_mem(op0) && (op_mem_base(op0) & 0x8)) opc |= OPC_REXB;
    if (op_mem(op0) && (op_mem_idx(op0) & 0x8)) opc |= OPC_REXX;
    if (op_reg(op1) && op_reg_idx(op1) & 0x8) opc |= OPC_REXR;

    bool has_rex = !!(opc & (OPC_REX|OPC_REXW|OPC_REXR|OPC_REXX|OPC_REXB));
    if (has_rex && (op_reg_gph(op0) || op_reg_gph(op1))) return -1;

    int mod = 0, reg = op1 & 7, rm;
    int scale = 0, idx = 4, base = 0;
    bool withsib = false, mod0off = false;
    if (op_reg(op0))
    {
        mod = 3;
        rm = op_reg_idx(op0) & 7;
    }
    else
    {
        if (!!op_mem_idx(op0) != !!op_mem_scale(op0)) return -1;
        if (op_mem_idx(op0))
        {
            if (!op_reg_gpl(op_mem_idx(op0))) return -1;
            if (op_reg_idx(op_mem_idx(op0)) == 4) return -1;
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
            if (withsib) return -1;
        }
        else
        {
            if (!op_reg_gpl(op_mem_base(op0))) return -1;
            rm = op_reg_idx(op_mem_base(op0)) & 7;
            if (rm == 5) mod = 1;
        }

        if (op_mem_offset(op0) && op_imm_n(op_mem_offset(op0), 1) && !mod0off)
            mod = 1;
        else if (op_mem_offset(op0) && !mod0off)
            mod = 2;

        if (withsib || rm == 4)
        {
            base = rm;
            rm = 4;
        }
    }

    if (enc_opc(buf, opc)) return -1;
    *(*buf)++ = (mod << 6) | (reg << 3) | rm;
    if (mod != 3 && rm == 4)
        *(*buf)++ = (scale << 6) | (idx << 3) | base;
    if (mod == 1) return enc_imm(buf, op_mem_offset(op0), 1);
    if (mod == 2 || mod0off) return enc_imm(buf, op_mem_offset(op0), 4);
    return 0;
}

typedef enum {
    ENC_INVALID = 0,
    ENC_NP,
    ENC_M, ENC_M1, ENC_MI, ENC_MC, ENC_MR, ENC_RM, ENC_RMA, ENC_MRI, ENC_RMI, ENC_MRC,
    ENC_I, ENC_IA, ENC_O, ENC_OI, ENC_OA, ENC_AO, ENC_A, ENC_D, ENC_FD, ENC_TD,
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
    [ENC_I]       = { .immctl = 4, .immidx = 0 },
    [ENC_IA]      = { .zregidx = 0^3, .zregval = 0, .immctl = 4, .immidx = 1 },
    [ENC_O]       = { .modreg = 0^3 },
    [ENC_OI]      = { .modreg = 0^3, .immctl = 4, .immidx = 1 },
    [ENC_OA]      = { .modreg = 0^3, .zregidx = 1^3, .zregval = 0 },
    [ENC_AO]      = { .modreg = 1^3, .zregidx = 0^3, .zregval = 0 },
    [ENC_A]       = { .zregidx = 0^3, .zregval = 0 },
    [ENC_D]       = { .immctl = 6, .immidx = 0 },
    [ENC_FD]      = { .immctl = 2, .immidx = 1 },
    [ENC_TD]      = { .immctl = 2, .immidx = 0 },
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
fe_enc64_impl(uint8_t** restrict buf, uint64_t mnem, FeOp op0, FeOp op1, FeOp op2, FeOp op3)
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
        int64_t imm;

        if (UNLIKELY(desc->enc == ENC_INVALID)) goto fail;

        if (ei->zregidx)
            if (op_reg_idx(ops[ei->zregidx^3]) != ei->zregval) goto next;

        for (int i = 0; i < 4; i++) {
            unsigned ty = (desc->tys >> (4 * i)) & 0xf;
            if (ty == 0x0) continue;
            if (ty == 0xf && !op_mem(ops[i])) goto next;
            if (ty == 0x1 && !op_reg_gpl(ops[i])) goto next;
            if (ty == 0x2 && !op_reg_gpl(ops[i]) && !op_reg_gph(ops[i])) goto next;
            if (ty == 0x2 && op_reg_gpl(ops[i]) && ops[i] >= FE_SP && ops[i] <= FE_DI) opc |= OPC_REX;
        }

        if (ei->immctl && ei->immctl != 3)
            imm = ops[ei->immidx];
        if (ei->immctl == 6) {
            if (imm == FE_JMP_RESERVE)
                imm = 0;
            else
                imm -= (int64_t) *buf + opc_size(opc) + desc->immsz;
        }
        if (UNLIKELY(ei->immctl == 1) && imm != 1) goto next;
        if (ei->immctl && !op_imm_n(imm, desc->immsz)) goto next;

        if (UNLIKELY(mnem & FE_ADDR32))
            *(*buf)++ = 0x67;
        if (UNLIKELY(mnem & 0x70000))
            *(*buf)++ = (0x65643e362e2600 >> (8 * ((mnem & 0x70000) >> 16))) & 0xff;

        if (ei->modrm) {
            FeOp modreg = ei->modreg ? ops[ei->modreg^3] : (opc & 0xff00) >> 8;
            if (enc_mr(buf, opc, ops[ei->modrm^3], modreg)) goto fail;
        } else if (ei->modreg) {
            if (enc_o(buf, opc, ops[ei->modreg^3])) goto fail;
        } else {
            if (enc_opc(buf, opc)) goto fail;
        }

        if (ei->immctl >= 2)
            if (enc_imm(buf, imm, desc->immsz)) goto fail;

        return 0;

    next:
        desc_idx = desc->alt;
    } while (desc_idx != 0);

fail:
    *buf = buf_start; // Don't advance buffer on error
    return -1;
}

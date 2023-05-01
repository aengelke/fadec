
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec-enc2.h>


#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

#define op_reg_idx(op) (op).idx
#define op_reg_gph(op) (((op).idx & ~0x3) == 0x24)
#define op_mem_base(mem) op_reg_idx((mem).base)
#define op_mem_idx(mem) op_reg_idx((mem).idx)

static bool
op_imm_n(int64_t imm, unsigned immsz) {
    if (immsz == 0 && !imm) return true;
    if (immsz == 1 && (int8_t) imm == imm) return true;
    if (immsz == 2 && (int16_t) imm == imm) return true;
    if (immsz == 3 && (imm&0xffffff) == imm) return true;
    if (immsz == 4 && (int32_t) imm == imm) return true;
    if (immsz == 8 && (int64_t) imm == imm) return true;
    return false;
}

static __attribute__((cold)) __attribute__((const)) uint8_t
enc_seg(int flags) {
    return (0x65643e362e2600 >> (8 * (flags & FE_SEG_MASK))) & 0xff;
}

static int
enc_imm(uint8_t* restrict buf, uint64_t imm, unsigned immsz) {
    if (!op_imm_n(imm, immsz))
        return -1;
    for (unsigned i = 0; i < immsz; i++)
        *buf++ = imm >> 8 * i;
    return 0;
}

static int
enc_mem_common(uint8_t* restrict buf, unsigned bufidx, FeMem op0, uint64_t op1,
               unsigned immsz, unsigned sibidx) {
    int mod = 0, reg = op1 & 7, rm;
    int scale = 0, idx = 4, base = 0;
    bool withsib = false, mod0off = false;
    unsigned dispsz = 0;
    int32_t off = op0.off;

    if (sibidx < 8) {
        idx = sibidx;
        int scalabs = op0.scale;
        if (scalabs & (scalabs - 1))
            return 0;
        scale = (scalabs & 0xA ? 1 : 0) | (scalabs & 0xC ? 2 : 0);
        withsib = true;
    }

    if (op0.base.idx == op_reg_idx(FE_NOREG)) {
        rm = 5;
        mod0off = true;
        withsib = true;
    } else if (op0.base.idx == FE_IP.idx) {
        if (withsib)
            return 0;
        rm = 5;
        mod0off = true;
        // Adjust offset, caller doesn't know instruction length.
        off -= bufidx + 5 + immsz;
    } else {
        rm = op_reg_idx(op0.base) & 7;
        if (rm == 5)
            mod = 1;
    }

    if (off && op_imm_n(off, 1) && !mod0off)
        mod = 1;
    else if (off && !mod0off)
        mod = 2;

    if (withsib || rm == 4) {
        base = rm;
        rm = 4;
    }

    dispsz = mod == 1 ? 1 : (mod == 2 || mod0off) ? 4 : 0;
    if (bufidx + 1 + (mod != 3 && rm == 4) + dispsz + immsz > 15)
        return 0;

    buf[bufidx++] = (mod << 6) | (reg << 3) | rm;
    if (mod != 3 && rm == 4)
        buf[bufidx++] = (scale << 6) | (idx << 3) | base;
    if (enc_imm(buf + bufidx, off, dispsz))
        return 0;
    return 1 + (mod != 3 && rm == 4) + dispsz;
}

static int
enc_mem(uint8_t* restrict buf, unsigned bufidx, FeMem op0, uint64_t op1,
        unsigned immsz, unsigned forcesib) {
    if ((op_reg_idx(op0.idx) != op_reg_idx(FE_NOREG)) != !!op0.scale)
        return 0;
    unsigned sibidx = forcesib ? 4 : 8;
    if (op_reg_idx(op0.idx) != op_reg_idx(FE_NOREG)) {
        if (op_reg_idx(op0.idx) == 4)
            return 0;
        sibidx = op_reg_idx(op0.idx) & 7;
    }
    return enc_mem_common(buf, bufidx, op0, op1, immsz, sibidx);
}

static int
enc_mem_vsib(uint8_t* restrict buf, unsigned bufidx, FeMemV op0, uint64_t op1,
             unsigned immsz, unsigned forcesib) {
    (void) forcesib;
    if (!op0.scale)
        return 0;
    FeMem mem = FE_MEM(op0.base, op0.scale, FE_NOREG, op0.off);
    return enc_mem_common(buf, bufidx, mem, op1, immsz, op_reg_idx(op0.idx) & 7);
}

unsigned fe64_NOP(uint8_t* buf, unsigned flags) {
    unsigned len = flags ? flags : 1;
    // Taken from Intel SDM
    static const uint8_t tbl[] = {
        0x90,
        0x66, 0x90,
        0x0f, 0x1f, 0x00,
        0x0f, 0x1f, 0x40, 0x00,
        0x0f, 0x1f, 0x44, 0x00, 0x00,
        0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
        0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    unsigned remain = len;
    for (; remain > 9; remain -= 9)
        for (unsigned i = 0; i < 9; i++)
            *(buf++) = tbl[36 + i];
    const uint8_t* src = tbl + (remain * (remain - 1)) / 2;
    for (unsigned i = 0; i < remain; i++)
        *(buf++) = src[i];
    return len;
}

#include <fadec-encode2-private.inc>

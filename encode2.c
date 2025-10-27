
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec-enc2.h>


#ifdef __GNUC__
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#if __has_attribute(cold) && __has_attribute(preserve_most)
#define HINT_COLD __attribute__((cold,preserve_most,noinline))
#elif  __has_attribute(cold)
#define HINT_COLD __attribute__((cold,noinline))
#else
#define HINT_COLD
#endif
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#define HINT_COLD
#endif

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

HINT_COLD static unsigned
enc_seg67(uint8_t* buf, unsigned flags) {
    unsigned idx = 0;
    if (UNLIKELY(flags & FE_SEG_MASK)) {
        unsigned seg = (0x65643e362e2600 >> (8 * (flags & FE_SEG_MASK))) & 0xff;
        buf[idx++] = seg;
    }
    if (UNLIKELY(flags & FE_ADDR32)) buf[idx++] = 0x67;
    return idx;
}

static unsigned
enc_rex_mem(FeMem op0, uint64_t op1) {
    // Essentially just an and+or due to struct layout.
    uint32_t val = op1 | op0.flags | (op_mem_base(op0) << 8) |
                   ((uint32_t)op_mem_idx(op0) << 24);
    // Combine REX.RXB using multiplication for branch-less code.
    uint32_t masked = val & 0x08000808;
    return masked ? (uint8_t) (masked * (1|(1<<15)|(1<<25)) >> 26) + 0x40 : 0;
}

static void
enc_imm(uint8_t* buf, uint64_t imm, unsigned immsz) {
#ifdef __GNUC__
    // Clang doesn't fold the loop into a single store.
    // See: https://github.com/llvm/llvm-project/issues/154696
    if (__builtin_constant_p(immsz)) {
        __builtin_memcpy(buf, &imm, immsz);
        return;
    }
#endif
    for (unsigned i = 0; i < immsz; i++)
        *buf++ = imm >> 8 * i;
}

static int
enc_mem_common(uint8_t* buf, unsigned ripoff, FeMem op0, uint64_t op1,
               unsigned disp8scale) {
    int mod = 0, reg = op1 & 7, rm;
    unsigned sib = 0x20;
    bool withsib = false;
    unsigned dispsz = 0;
    int32_t off = op0.off;

    if (op_reg_idx(op0.idx) < 0x80) {
        int scalabs = op0.scale;
        if (UNLIKELY((unsigned) (op0.scale - 1) >= 8 ||
                     (op0.scale & (op0.scale - 1))))
            return 0;
        unsigned scale = (scalabs & 0xA ? 1 : 0) | (scalabs & 0xC ? 2 : 0);
        sib = scale << 6 | (op_reg_idx(op0.idx) & 7) << 3;
        withsib = true;
    } else if (UNLIKELY(op0.scale != 0)) {
        return 0;
    }

    if (UNLIKELY(op0.base.idx >= 0x20)) {
        if (UNLIKELY(op0.base.idx >= op_reg_idx(FE_NOREG))) {
            *buf++ = (reg << 3) | 4;
            *buf++ = sib | 5;
            enc_imm(buf, off, 4);
            return ripoff + 6;
        } else if (LIKELY(op0.base.idx == FE_IP.idx)) {
            if (withsib)
                return 0;
            *buf++ = (reg << 3) | 5;
            // Adjust offset, caller doesn't know instruction length.
            enc_imm(buf, off - ripoff - 5, 4);
            return ripoff + 5;
        } else {
            return 0;
        }
    }

    rm = op_reg_idx(op0.base) & 7;

    if (off) {
        if (LIKELY(!disp8scale)) {
            mod = (int8_t) off == off ? 0x40 : 0x80;
            dispsz = (int8_t) off == off ? 1 : 4;
        } else {
            if (!(off & ((1 << disp8scale) - 1)) && op_imm_n(off >> disp8scale, 1))
                off >>= disp8scale, mod = 0x40, dispsz = 1;
            else
                mod = 0x80, dispsz = 4;
        }
    } else if (rm == 5) {
        dispsz = 1;
        mod = 0x40;
    }

    // Always write four bytes of displacement. The buffer is always large
    // enough, and we truncate by returning a smaller "written bytes" count.
    if (withsib || rm == 4) {
        *buf++ = mod | (reg << 3) | 4;
        *buf++ = sib | rm;
        enc_imm(buf, off, 4);
        return ripoff + 2 + dispsz;
    } else {
        *buf++ = mod | (reg << 3) | rm;
        enc_imm(buf, off, 4);
        return ripoff + 1 + dispsz;
    }
}

static int
enc_mem(uint8_t* buf, unsigned ripoff, FeMem op0, uint64_t op1, bool forcesib,
        unsigned disp8scale) {
    if (UNLIKELY(op_reg_idx(op0.idx) == 4))
        return 0;
    if (forcesib && op_reg_idx(op0.idx) == op_reg_idx(FE_NOREG)) {
        op0.scale = 1;
        op0.idx = FE_GP(4);
    }
    return enc_mem_common(buf, ripoff, op0, op1, disp8scale);
}

static int
enc_mem_vsib(uint8_t* buf, unsigned ripoff, FeMemV op0, uint64_t op1,
             bool forcesib, unsigned disp8scale) {
    (void) forcesib;
    FeMem mem = FE_MEM(op0.base, op0.scale, FE_GP(op_reg_idx(op0.idx)), op0.off);
    return enc_mem_common(buf, ripoff, mem, op1, disp8scale);
}

// EVEX/VEX "Opcode" format:
//
// | EVEX byte 4 | P P M M M - - W | Opcode byte | VEX-D VEX-D-FLIPW
// 0             8                 16            24

enum {
    FE_OPC_VEX_WPP_SHIFT = 8,
    FE_OPC_VEX_WPP_MASK = 0x83 << FE_OPC_VEX_WPP_SHIFT,
    FE_OPC_VEX_MMM_SHIFT = 10,
    FE_OPC_VEX_MMM_MASK = 0x1f << FE_OPC_VEX_MMM_SHIFT,
    FE_OPC_VEX_DOWNGRADE_VEX = 1 << 24,
    FE_OPC_VEX_DOWNGRADE_VEX_FLIPW = 1 << 25,
};

static int
enc_vex_common(uint8_t* buf, unsigned opcode, unsigned base,
               unsigned idx, unsigned reg, unsigned vvvv) {
    if ((base | idx | reg | vvvv) & 0x10) return 0;
    bool vex3 = ((base | idx) & 0x08) || (opcode & 0xfc00) != 0x0400;
    if (vex3) {
        *buf++ = 0xc4;
        unsigned b1 = (opcode & FE_OPC_VEX_MMM_MASK) >> FE_OPC_VEX_MMM_SHIFT;
        if (!(reg & 0x08)) b1 |= 0x80;
        if (!(idx & 0x08)) b1 |= 0x40;
        if (!(base & 0x08)) b1 |= 0x20;
        *buf++ = b1;
        unsigned b2 = (opcode & FE_OPC_VEX_WPP_MASK) >> FE_OPC_VEX_WPP_SHIFT;
        if (opcode & 0x20) b2 |= 0x04;
        b2 |= (vvvv ^ 0xf) << 3;
        *buf++ = b2;
    } else {
        *buf++ = 0xc5;
        unsigned b2 = opcode >> FE_OPC_VEX_WPP_SHIFT & 3;
        if (opcode & 0x20) b2 |= 0x04;
        if (!(reg & 0x08)) b2 |= 0x80;
        b2 |= (vvvv ^ 0xf) << 3;
        *buf++ = b2;
    }
    *buf++ = (opcode & 0xff0000) >> 16;
    return 3 + vex3;
}

static int
enc_vex_reg(uint8_t* buf, unsigned opcode, uint64_t rm, uint64_t reg,
            uint64_t vvvv) {
    unsigned off = enc_vex_common(buf, opcode, rm, 0, reg, vvvv);
    buf[off] = 0xc0 | (reg << 3 & 0x38) | (rm & 7);
    return off ? off + 1 : 0;
}

static int
enc_vex_mem(uint8_t* buf, unsigned opcode, FeMem rm, uint64_t reg,
            uint64_t vvvv, unsigned ripoff, bool forcesib, unsigned disp8scale) {
    unsigned off = enc_vex_common(buf, opcode, op_reg_idx(rm.base), op_reg_idx(rm.idx), reg, vvvv);
    unsigned memoff = enc_mem(buf + off, ripoff + off, rm, reg, forcesib, disp8scale);
    return off && memoff ? memoff : 0;
}

static int
enc_vex_vsib(uint8_t* buf, unsigned opcode, FeMemV rm, uint64_t reg,
             uint64_t vvvv, unsigned ripoff, bool forcesib, unsigned disp8scale) {
    unsigned off = enc_vex_common(buf, opcode, op_reg_idx(rm.base), op_reg_idx(rm.idx), reg, vvvv);
    unsigned memoff = enc_mem_vsib(buf + off, ripoff + off, rm, reg, forcesib, disp8scale);
    return off && memoff ? memoff : 0;
}

static int
enc_evex_common(uint8_t* buf, unsigned opcode, unsigned base,
                unsigned idx, unsigned reg, unsigned vvvv) {
    *buf++ = 0x62;
    bool evexr3 = reg & 0x08;
    bool evexr4 = reg & 0x10;
    bool evexb3 = base & 0x08;
    bool evexb4 = base & 0x10; // evexb4 is unused in AVX-512 encoding
    bool evexx3 = idx & 0x08;
    bool evexx4 = idx & 0x10;
    bool evexv4 = vvvv & 0x10;
    unsigned b1 = (opcode & FE_OPC_VEX_MMM_MASK) >> FE_OPC_VEX_MMM_SHIFT;
    if (!evexr3) b1 |= 0x80;
    if (!evexx3) b1 |= 0x40;
    if (!evexb3) b1 |= 0x20;
    if (!evexr4) b1 |= 0x10;
    if (evexb4) b1 |= 0x08;
    *buf++ = b1;
    unsigned b2 = (opcode & FE_OPC_VEX_WPP_MASK) >> FE_OPC_VEX_WPP_SHIFT;
    if (!evexx4) b2 |= 0x04;
    b2 |= (~vvvv & 0xf) << 3;
    *buf++ = b2;
    unsigned b3 = opcode & 0xff;
    if (!evexv4) b3 |= 0x08;
    *buf++ = b3;
    *buf++ = (opcode & 0xff0000) >> 16;
    return 5;
}

static unsigned
enc_evex_to_vex(unsigned opcode) {
    return opcode & FE_OPC_VEX_DOWNGRADE_VEX_FLIPW ? opcode ^ 0x8000 : opcode;
}

// Encode AVX-512 EVEX r/m-reg, non-xmm reg, vvvv, prefer vex
static int
enc_evex_reg(uint8_t* buf, unsigned opcode, unsigned rm,
             unsigned reg, unsigned vvvv) {
    unsigned off;
    if (!((rm | reg | vvvv) & 0x10) && (opcode & FE_OPC_VEX_DOWNGRADE_VEX))
        off = enc_vex_common(buf, enc_evex_to_vex(opcode), rm, 0, reg, vvvv);
    else
        off = enc_evex_common(buf, opcode, rm, 0, reg, vvvv);
    buf[off] = 0xc0 | (reg << 3 & 0x38) | (rm & 7);
    return off + 1;
}

// Encode AVX-512 EVEX r/m-reg, xmm reg, vvvv, prefer vex
static int
enc_evex_xmm(uint8_t* buf, unsigned opcode, unsigned rm,
             unsigned reg, unsigned vvvv) {
    unsigned off;
    if (!((rm | reg | vvvv) & 0x10) && (opcode & FE_OPC_VEX_DOWNGRADE_VEX))
        off = enc_vex_common(buf, enc_evex_to_vex(opcode), rm, 0, reg, vvvv);
    else
        // AVX-512 XMM reg encoding uses X3 instead of B4.
        off = enc_evex_common(buf, opcode, rm & 0x0f, rm >> 1, reg, vvvv);
    buf[off] = 0xc0 | (reg << 3 & 0x38) | (rm & 7);
    return off + 1;
}

static int
enc_evex_mem(uint8_t* buf, unsigned opcode, FeMem rm, uint64_t reg,
             uint64_t vvvv, unsigned ripoff, bool forcesib, unsigned disp8scale) {
    unsigned off;
    if (!((op_reg_idx(rm.base) | op_reg_idx(rm.idx) | reg | vvvv) & 0x10) &&
        (opcode & FE_OPC_VEX_DOWNGRADE_VEX)) {
        disp8scale = 0; // Only AVX-512 EVEX compresses displacement
        off = enc_vex_common(buf, enc_evex_to_vex(opcode), op_reg_idx(rm.base), op_reg_idx(rm.idx), reg, vvvv);
    } else {
        off = enc_evex_common(buf, opcode, op_reg_idx(rm.base), op_reg_idx(rm.idx), reg, vvvv);
    }
    unsigned memoff = enc_mem(buf + off, ripoff + off, rm, reg, forcesib, disp8scale);
    return off && memoff ? memoff : 0;
}

static int
enc_evex_vsib(uint8_t* buf, unsigned opcode, FeMemV rm, uint64_t reg,
             uint64_t vvvv, unsigned ripoff, bool forcesib, unsigned disp8scale) {
    (void) vvvv;
    // EVEX VSIB requires non-zero mask operand
    if (!(opcode & 0x7)) return 0;
    // EVEX.X4 is encoded in EVEX.V4
    unsigned idx = op_reg_idx(rm.idx);
    unsigned off = enc_evex_common(buf, opcode, op_reg_idx(rm.base), idx & 0x0f, reg, idx & 0x10);
    unsigned memoff = enc_mem_vsib(buf + off, ripoff + off, rm, reg, forcesib, disp8scale);
    return off && memoff ? memoff : 0;
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

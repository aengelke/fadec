
#ifndef FD_FADEC_ENC2_H_
#define FD_FADEC_ENC2_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define FE_STRUCT(name) name
#else
#define FE_STRUCT(name) (name)
#endif

// Flags
#define FE_JMPL 0x8
#define FE_ADDR32 0x10
#define FE_SEG_MASK 0x7
#define FE_SEG(seg) (((seg).idx + 1) & FE_SEG_MASK)

typedef struct FeRegGP { unsigned char idx; } FeRegGP;
#define FE_GP(idx) (FE_STRUCT(FeRegGP) { idx })
#define FE_AX FE_GP(0)
#define FE_CX FE_GP(1)
#define FE_DX FE_GP(2)
#define FE_BX FE_GP(3)
#define FE_SP FE_GP(4)
#define FE_BP FE_GP(5)
#define FE_SI FE_GP(6)
#define FE_DI FE_GP(7)
#define FE_R8 FE_GP(8)
#define FE_R9 FE_GP(9)
#define FE_R10 FE_GP(10)
#define FE_R11 FE_GP(11)
#define FE_R12 FE_GP(12)
#define FE_R13 FE_GP(13)
#define FE_R14 FE_GP(14)
#define FE_R15 FE_GP(15)
#define FE_IP FE_GP(16)
#define FE_NOREG FE_GP(0x80)
typedef struct FeRegGPH { unsigned char idx; } FeRegGPH;
#define FE_GPH(idx) (FE_STRUCT(FeRegGPH) { idx })
#define FE_AH FE_GPH(4)
#define FE_CH FE_GPH(5)
#define FE_DH FE_GPH(6)
#define FE_BH FE_GPH(7)
typedef struct FeRegSREG { unsigned char idx; } FeRegSREG;
#define FE_SREG(idx) (FE_STRUCT(FeRegSREG) { idx })
#define FE_ES FE_SREG(0)
#define FE_CS FE_SREG(1)
#define FE_SS FE_SREG(2)
#define FE_DS FE_SREG(3)
#define FE_FS FE_SREG(4)
#define FE_GS FE_SREG(5)
typedef struct FeRegST { unsigned char idx; } FeRegST;
#define FE_ST(idx) (FE_STRUCT(FeRegST) { idx })
#define FE_ST0 FE_ST(0)
#define FE_ST1 FE_ST(1)
#define FE_ST2 FE_ST(2)
#define FE_ST3 FE_ST(3)
#define FE_ST4 FE_ST(4)
#define FE_ST5 FE_ST(5)
#define FE_ST6 FE_ST(6)
#define FE_ST7 FE_ST(7)
typedef struct FeRegMM { unsigned char idx; } FeRegMM;
#define FE_MM(idx) (FE_STRUCT(FeRegMM) { idx })
#define FE_MM0 FE_MM(0)
#define FE_MM1 FE_MM(1)
#define FE_MM2 FE_MM(2)
#define FE_MM3 FE_MM(3)
#define FE_MM4 FE_MM(4)
#define FE_MM5 FE_MM(5)
#define FE_MM6 FE_MM(6)
#define FE_MM7 FE_MM(7)
typedef struct FeRegXMM { unsigned char idx; } FeRegXMM;
#define FE_XMM(idx) (FE_STRUCT(FeRegXMM) { idx })
#define FE_XMM0 FE_XMM(0)
#define FE_XMM1 FE_XMM(1)
#define FE_XMM2 FE_XMM(2)
#define FE_XMM3 FE_XMM(3)
#define FE_XMM4 FE_XMM(4)
#define FE_XMM5 FE_XMM(5)
#define FE_XMM6 FE_XMM(6)
#define FE_XMM7 FE_XMM(7)
#define FE_XMM8 FE_XMM(8)
#define FE_XMM9 FE_XMM(9)
#define FE_XMM10 FE_XMM(10)
#define FE_XMM11 FE_XMM(11)
#define FE_XMM12 FE_XMM(12)
#define FE_XMM13 FE_XMM(13)
#define FE_XMM14 FE_XMM(14)
typedef struct FeRegCR { unsigned char idx; } FeRegCR;
#define FE_CR(idx) (FE_STRUCT(FeRegCR) { idx })
typedef struct FeRegDR { unsigned char idx; } FeRegDR;
#define FE_DR(idx) (FE_STRUCT(FeRegDR) { idx })

// Internal only
typedef struct FeRegGPLH { unsigned char idx; } FeRegGPLH;
#define FE_GPLH(idx) (FE_STRUCT(FeRegGPLH) { idx })
// Disambiguate GP and GPH -- C++ uses overloading; C uses _Generic.
#ifdef __cplusplus
}
namespace {
    static constexpr inline FeRegGPLH FE_MAKE_GPLH(FeRegGP reg) {
        return FE_GPLH(reg.idx);
    }
    static constexpr inline FeRegGPLH FE_MAKE_GPLH(FeRegGPH reg) {
        return FE_GPLH(reg.idx + 0x20);
    }
}
extern "C" {
#else
#define FE_MAKE_GPLH(reg) FE_GPLH(_Generic((reg), FeRegGPH: 0x20, FeRegGP: 0) | (reg).idx)
#endif

typedef struct FeMem {
    uint8_t flags;
    FeRegGP base;
    unsigned char scale;
    // union {
        FeRegGP idx;
    //     FeRegXMM idx_xmm;
    // };
    int32_t off;
} FeMem;
#define FE_MEM(base,sc,idx,off) (FE_STRUCT(FeMem) { 0, base, sc, idx, off })
typedef struct FeMemV {
    uint8_t flags;
    FeRegGP base;
    unsigned char scale;
    FeRegXMM idx;
    int32_t off;
} FeMemV;
#define FE_MEMV(base,sc,idx,off) (FE_STRUCT(FeMemV) { 0, base, sc, idx, off })

// NOP is special: flags is interpreted as the length in bytes, 0 = 1 byte, too.
unsigned fe64_NOP(uint8_t* buf, unsigned flags);

#include <fadec-encode2-public.inc>

#ifdef __cplusplus
}
#endif

#endif

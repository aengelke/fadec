
#ifndef FD_FADEC_ENC_H_
#define FD_FADEC_ENC_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FE_AX = 0x100, FE_CX, FE_DX, FE_BX, FE_SP, FE_BP, FE_SI, FE_DI,
    FE_R8, FE_R9, FE_R10, FE_R11, FE_R12, FE_R13, FE_R14, FE_R15, FE_IP,
    FE_AH = 0x204, FE_CH, FE_DH, FE_BH,
    FE_ES = 0x300, FE_CS, FE_SS, FE_DS, FE_FS, FE_GS,
    FE_ST0 = 0x400, FE_ST1, FE_ST2, FE_ST3, FE_ST4, FE_ST5, FE_ST6, FE_ST7,
    FE_MM0 = 0x500, FE_MM1, FE_MM2, FE_MM3, FE_MM4, FE_MM5, FE_MM6, FE_MM7,
    FE_XMM0 = 0x600, FE_XMM1, FE_XMM2, FE_XMM3, FE_XMM4, FE_XMM5, FE_XMM6, FE_XMM7,
    FE_XMM8, FE_XMM9, FE_XMM10, FE_XMM11, FE_XMM12, FE_XMM13, FE_XMM14, FE_XMM15,
} FeReg;

typedef int64_t FeOp;

#define FE_MEM(base,sc,idx,off) (INT64_MIN | ((int64_t) ((base) & 0xfff) << 32) | ((int64_t) ((idx) & 0xfff) << 44) | ((int64_t) ((sc) & 0xf) << 56) | ((off) & 0xffffffff))

#define FE_SEG(seg) ((((seg) & 0x7) + 1) << 16)
#define FE_SEG_MASK 0x70000
#define FE_ADDR32 0x80000
/** Used together with a RIP-relative (conditional) jump, this will force the
 * use of the encoding with the largest distance. Useful for reserving a jump
 * when the target offset is still unknown; if the jump is re-encoded later on,
 * FE_JMPL must be specified there, too, so that the encoding lengths match. **/
#define FE_JMPL 0x100000
#define FE_MNEM_MASK 0xffff

enum {
#define FE_MNEMONIC(name,value) name = value,
#include <fadec-enc-mnems.inc>
#undef FE_MNEMONIC
    FE_MNEM_MAX
};

#define fe_enc64_1(buf, mnem, op0, op1, op2, op3, ...) fe_enc64_impl(buf, mnem, op0, op1, op2, op3)
#define fe_enc64(buf, ...) fe_enc64_1(buf, __VA_ARGS__, 0, 0, 0, 0, 0)
int fe_enc64_impl(uint8_t** buf, uint64_t mnem, FeOp op0, FeOp op1, FeOp op2, FeOp op3);

#ifdef __cplusplus
}
#endif

#endif

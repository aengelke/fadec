
#include "fadec.h"
#include <stdint.h>

#if defined(__has_attribute)
#if __has_attribute(fallthrough)
#define FALLTHROUGH() __attribute__((fallthrough))
#endif
#endif
#if !defined(FALLTHROUGH)
#define FALLTHROUGH() ((void)0)
#endif

uint64_t fd_effects(const FdInstr* instr) {
  static const uint32_t effects_table[] = {
#define FD_DECODE_TABLE_EFFECTS_TABLE
#include <fadec-decode-private.inc>
#undef FD_DECODE_TABLE_EFFECTS_TABLE
  };
  static const uint8_t effect_indices[] = {
#define FD_DECODE_TABLE_EFFECTS_INDICES
#include <fadec-decode-private.inc>
#undef FD_DECODE_TABLE_EFFECTS_INDICES
  };
  uint64_t effects = effects_table[effect_indices[FD_TYPE(instr)]];
  // For some instructions, the operands impact the effects.
  const uint64_t FDE_FLAGSRD =
      FDE_CFRD | FDE_PFRD | FDE_AFRD | FDE_ZFRD | FDE_SFRD | FDE_OFRD;
  const uint64_t FDE_FLAGSWR =
      FDE_CFWR | FDE_PFWR | FDE_AFWR | FDE_ZFWR | FDE_SFWR | FDE_OFWR;
  switch (FD_TYPE(instr)) {
  default: break;
  case FDI_IMUL:
    // IMUL with 2/3 operands has no implicit operands.
    if (FD_OP_TYPE(instr, 2) != FD_OT_NONE)
      return FDE_OP0WR | FDE_OP1RD | FDE_OP2RD | FDE_FLAGSWR;
    if (FD_OP_TYPE(instr, 1) != FD_OT_NONE)
      return FDE_OP0RD | FDE_OP0WR | FDE_OP1RD | FDE_FLAGSWR;
    FALLTHROUGH();
  case FDI_MUL:
    // MUL/IMUL updates AX; DX is written only for 16/32/64 bit operands.
    if (FD_OP_SIZELG(instr, 0) == 0)
      return FDE_OP0RD | FDE_AXRD | FDE_AXWR | FDE_FLAGSWR;
    return FDE_OP0RD | FDE_AXRD | FDE_AXWR | FDE_DXWR | FDE_FLAGSWR;
  case FDI_IDIV:
  case FDI_DIV:
    // DIV/IDIV updates AX; DX only updated for 16/32/64 bit operands.
    if (FD_OP_SIZELG(instr, 0) == 0)
      return FDE_OP0RD | FDE_AXRD | FDE_AXWR | FDE_FLAGSWR;
    return FDE_OP0RD | FDE_AXRD | FDE_AXWR | FDE_DXRD | FDE_DXWR | FDE_FLAGSWR;
  case FDI_SHL:
  case FDI_SHR:
  case FDI_SAR:
  case FDI_ROL:
  case FDI_ROR:
  case FDI_RCL:
  case FDI_RCR:
    // Shift/rotate flag is modified for non-zero shift amounts, for immediates,
    // there is no false dependency.
    if (FD_OP_TYPE(instr, 1) == FD_OT_IMM) {
      if (FD_TYPE(instr) != FDI_RCL && FD_TYPE(instr) != FDI_RCR)
        effects &= ~FDE_FLAGSRD;
      else
        effects &= ~(uint64_t)FDE_OFRD;
      unsigned mask = FD_OP_SIZELG(instr, 0) < 3 ? 0x1f : 0x3f;
      if ((FD_OP_IMM(instr, 1) & mask) == 0)
        effects &= ~FDE_FLAGSWR;
    }
    break;
  case FDI_BT:
  case FDI_BTS:
  case FDI_BTR:
  case FDI_BTC:
    // BT/BTS/BTR/BTC without mem/reg combination will only access the memory
    // operand as specified.
    if (FD_OP_TYPE(instr, 0) != FD_OT_MEM || FD_OP_TYPE(instr, 1) != FD_OT_REG)
      effects &= ~(uint64_t)(FDE_MEMRD | FDE_MEMWR);
    break;
  case FDI_SSE_MOVSS:
  case FDI_SSE_MOVSD:
    // MOVSD/MOVSS reg,reg merges with the previous value.
    if (FD_OP_TYPE(instr, 0) == FD_OT_REG && FD_OP_TYPE(instr, 1) == FD_OT_REG)
      return FDE_OP0RD | FDE_OP0WR | FDE_OP1RD;
    return FDE_OP0WR | FDE_OP1RD;
  case FDI_XOR:         // Documented by Intel, AMD.
  case FDI_SUB:         // Documented by Intel, AMD.
  case FDI_SSE_XORPS:   // Documented by Intel, AMD.
  case FDI_SSE_XORPD:   // Documented by Intel, AMD.
  case FDI_SSE_PXOR:    // Documented by Intel, AMD.
  case FDI_SSE_PSUBB:   // Documented by Intel, AMD.
  case FDI_SSE_PSUBW:   // Documented by Intel, AMD.
  case FDI_SSE_PSUBD:   // Documented by Intel, AMD.
  case FDI_SSE_PSUBQ:   // Documented by Intel, AMD.
  case FDI_SSE_PCMPGTB: // Documented by AMD, but also implemented on Intel.
  case FDI_SSE_PCMPGTW: // Documented by AMD, but also implemented on Intel.
  case FDI_SSE_PCMPGTD: // Documented by AMD, but also implemented on Intel.
  case FDI_SSE_PCMPGTQ: // Documented by AMD, but also implemented on Intel.
  case FDI_SSE_PCMPEQB: // Documented by AMD, but also implemented on Intel.
  case FDI_SSE_PCMPEQW: // Documented by AMD, but also implemented on Intel.
  case FDI_SSE_PCMPEQD: // Documented by AMD, but also implemented on Intel.
  case FDI_SSE_PCMPEQQ: // Documented by AMD, but also implemented on Intel.
    // Zero-idioms that break dependencies on recent AMD and Intel cores. For
    // the most important ones, don't report read dependencies.
    // Intel also documents SUBP[SD], but this seems incorrect and I could not
    // reproduce dependency-breaking behavior on Tiger Lake. It also seems
    // wrong as the output is not guaranteed to be zero.
    // Intel doesn't document PCMP{GT,EQ}[BWDQ], but in practice, they break
    // dependencies as well.
    // AMD also documents CMP, SBB, ANDNP[SD], and PANDN.
    if (FD_OP_TYPE(instr, 0) == FD_OT_REG &&
        FD_OP_TYPE(instr, 1) == FD_OT_REG &&
        FD_OP_REG(instr, 0) == FD_OP_REG(instr, 1))
      effects &= ~(uint64_t)(FDE_OP0RD | FDE_OP1RD);
    break;
  case FDI_VXORPS:    // Documented by Intel, AMD.
  case FDI_VXORPD:    // Documented by Intel, AMD.
  case FDI_VPXOR:     // Documented by Intel, AMD.
  case FDI_VPSUBB:    // Documented by Intel, AMD.
  case FDI_VPSUBW:    // Documented by Intel, AMD.
  case FDI_VPSUBD:    // Documented by Intel, AMD.
  case FDI_VPSUBQ:    // Documented by Intel, AMD.
  case FDI_VPCMPGTB:  // Documented by AMD, but also implemented on Intel.
  case FDI_VPCMPGTW:  // Documented by AMD, but also implemented on Intel.
  case FDI_VPCMPGTD:  // Documented by AMD, but also implemented on Intel.
  case FDI_VPCMPGTQ:  // Documented by AMD, but also implemented on Intel.
  case FDI_VPCMPEQB:  // Documented by AMD, but also implemented on Intel.
  case FDI_VPCMPEQW:  // Documented by AMD, but also implemented on Intel.
  case FDI_VPCMPEQD:  // Documented by AMD, but also implemented on Intel.
  case FDI_VPCMPEQQ:  // Documented by AMD, but also implemented on Intel.
  case FDI_EVX_XORPS: // Documented by Intel, AMD.
  case FDI_EVX_XORPD: // Documented by Intel, AMD.
  case FDI_EVX_PXORD: // Documented by Intel, AMD.
  case FDI_EVX_PXORQ: // Documented by Intel, AMD.
  case FDI_EVX_PSUBB: // Documented by Intel, AMD.
  case FDI_EVX_PSUBW: // Documented by Intel, AMD.
  case FDI_EVX_PSUBD: // Documented by Intel, AMD.
  case FDI_EVX_PSUBQ: // Documented by Intel, AMD.
    // AMD also documents EVEX-encoded PCMP{GT,EQ}[BWDQ], with a zmm
    // destination, but these instructions don't exist. (Zen 4 optimization
    // guide #57647 v1.0.1; Zen 5 optimization guide #58455 v1.00.)
    if (FD_MASKREG(instr) == 0 && FD_OP_TYPE(instr, 2) == FD_OT_REG &&
        FD_OP_REG(instr, 0) == FD_OP_REG(instr, 1) &&
        FD_OP_REG(instr, 0) == FD_OP_REG(instr, 2))
      effects &= ~(uint64_t)(FDE_OP1RD | FDE_OP2RD);
    break;
  }
  return effects;
}

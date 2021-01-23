
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec.h>


static const char*
reg_name(unsigned rt, unsigned ri, unsigned size)
{
    unsigned max;
    const char (* table)[6];

#define TABLE(name, ...) \
        case name: { \
            static const char tab[][6] = { __VA_ARGS__ }; \
            table = tab; max = sizeof(tab) / sizeof(*tab); \
            break; \
        }

    switch (rt) {
    default: return "(inv-ty)";
    case FD_RT_GPL:
        switch (size) {
        default: return "(inv-sz)";
        TABLE(1,
            "al","cl","dl","bl","spl","bpl","sil","dil",
            "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b")
        TABLE(2,
            "ax","cx","dx","bx","sp","bp","si","di",
            "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w","ip")
        TABLE(4,
            "eax","ecx","edx","ebx","esp","ebp","esi","edi",
            "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d","eip")
        TABLE(8,
            "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
            "r8","r9","r10","r11","r12","r13","r14","r15","rip")
        }
        break;

    TABLE(FD_RT_GPH, "(inv)","(inv)","(inv)","(inv)","ah","ch","dh","bh")
    TABLE(FD_RT_SEG, "es","cs","ss","ds","fs","gs")
    TABLE(FD_RT_FPU, "st(0)","st(1)","st(2)","st(3)","st(4)","st(5)","st(6)","st(7)")
    TABLE(FD_RT_MMX, "mm0","mm1","mm2","mm3","mm4","mm5","mm6","mm7")
    TABLE(FD_RT_CR, "cr0","(inv)","cr2","cr3","cr4","(inv)","(inv)","(inv)","cr8")
    TABLE(FD_RT_DR, "dr0","dr1","dr2","dr3","dr4","dr5","dr6","dr7")
    TABLE(FD_RT_BND, "bnd0","bnd1","bnd2","bnd3")

    case FD_RT_VEC:
        switch (size) {
        default: return "(inv-sz)";
        case 1:
        case 2:
        case 4:
        case 8:
        TABLE(16,
            "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
            "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15")
        TABLE(32,
            "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
            "ymm8","ymm9","ymm10","ymm11","ymm12","ymm13","ymm14","ymm15")
        }
        break;
    }

    return ri < max ? table[ri] : "(inv-idx)";
}

static char*
fd_strplcpy(char* dst, const char* src, size_t size)
{
    while (*src && size > 1)
        *dst++ = *src++, size--;
    if (size)
        *dst = 0;
    return dst;
}

static char*
fd_format_hex(uint64_t val, char buf[static 19]) {
    unsigned idx = 19;
    buf[--idx] = 0;
    do {
        buf[--idx] = "0123456789abcdef"[val % 16];
        val /= 16;
    } while (val);
    buf[--idx] = 'x', buf[--idx] = '0';
    return &buf[idx];
}

const char*
fdi_name(FdInstrType ty) {
#define FD_DECODE_TABLE_STRTAB1
    static const char* mnemonic_str =
#include <fadec-table.inc>
    ;
#undef FD_DECODE_TABLE_STRTAB1

#define FD_DECODE_TABLE_STRTAB2
    static const uint16_t mnemonic_offs[] = {
#include <fadec-table.inc>
    };
#undef FD_DECODE_TABLE_STRTAB2

    if (ty >= sizeof(mnemonic_offs) / sizeof(mnemonic_offs[0]))
        return "(invalid)";
    return &mnemonic_str[mnemonic_offs[ty]];
}

void
fd_format(const FdInstr* instr, char* buffer, size_t len)
{
    fd_format_abs(instr, 0, buffer, len);
}

void
fd_format_abs(const FdInstr* instr, uint64_t addr, char* buffer, size_t len)
{
    char tmp[21];

    char* buf = buffer;
    char* end = buffer + len;

    if (FD_HAS_REP(instr))
        buf = fd_strplcpy(buf, "rep ", end-buf);
    if (FD_HAS_REPNZ(instr))
        buf = fd_strplcpy(buf, "repnz ", end-buf);
    if (FD_HAS_LOCK(instr))
        buf = fd_strplcpy(buf, "lock ", end-buf);

    const char* mnemonic = fdi_name(FD_TYPE(instr));

    bool prefix_addrsize = false;
    bool prefix_segment = false;

    char sizesuffix[3] = {0, 0, 0};
    switch (FD_OPSIZE(instr)) {
    default: break;
    case 1: sizesuffix[0] = 'b'; break;
    case 2: sizesuffix[0] = 'w'; break;
    case 4: sizesuffix[0] = 'd'; break;
    case 8: sizesuffix[0] = 'q'; break;
    }

    if (FD_OP_TYPE(instr, 0) == FD_OT_OFF && FD_OP_SIZE(instr, 0) == 2)
        sizesuffix[0] = 'w';

    switch (FD_TYPE(instr)) {
    case FDI_C_SEP:
        switch (FD_OPSIZE(instr)) {
        default: break;
        case 2: mnemonic = "cwd"; break;
        case 4: mnemonic = "cdq"; break;
        case 8: mnemonic = "cqo"; break;
        }
        sizesuffix[0] = 0;
        break;
    case FDI_C_EX:
        switch (FD_OPSIZE(instr)) {
        default: break;
        case 2: mnemonic = "cbw"; break;
        case 4: mnemonic = "cwde"; break;
        case 8: mnemonic = "cdqe"; break;
        }
        sizesuffix[0] = 0;
        break;
    case FDI_CMPXCHGD:
        switch (FD_OPSIZE(instr)) {
        default: break;
        case 4: mnemonic = "cmpxchg8b"; break;
        case 8: mnemonic = "cmpxchg16b"; break;
        }
        sizesuffix[0] = 0;
        break;
    case FDI_JCXZ:
        switch (FD_ADDRSIZE(instr)) {
        default: break;
        case 4: mnemonic = "jecxz"; break;
        case 8: mnemonic = "jrcxz"; break;
        }
        break;
    case FDI_PUSH:
        if (FD_OP_SIZE(instr, 0) == 2 && FD_OP_TYPE(instr, 0) == FD_OT_IMM)
            sizesuffix[0] = 'w';
        // FALLTHROUGH
    case FDI_POP:
        if (FD_OP_SIZE(instr, 0) == 2 && FD_OP_TYPE(instr, 0) == FD_OT_REG &&
            FD_OP_REG_TYPE(instr, 0) == FD_RT_SEG)
            sizesuffix[0] = 'w';
        break;
    case FDI_FXSAVE:
    case FDI_FXRSTOR:
    case FDI_XSAVE:
    case FDI_XSAVEC:
    case FDI_XSAVEOPT:
    case FDI_XSAVES:
    case FDI_XRSTOR:
    case FDI_XRSTORS:
        if (FD_OPSIZE(instr) == 8)
            sizesuffix[0] = '6', sizesuffix[1] = '4';
        else
            sizesuffix[0] = 0;
        break;
    case FDI_RET:
    case FDI_ENTER:
    case FDI_LEAVE:
        if (FD_OPSIZE(instr) == (FD_IS64(instr) ? 8 : 4))
            sizesuffix[0] = 0;
        break;
    case FDI_LODS:
    case FDI_MOVS:
    case FDI_CMPS:
    case FDI_OUTS:
        prefix_segment = true;
        // FALLTHROUGH
    case FDI_STOS:
    case FDI_SCAS:
    case FDI_INS:
        prefix_addrsize = true;
        break;
    default: break;
    }

    if (prefix_addrsize) {
        if (FD_IS64(instr) && FD_ADDRSIZE(instr) == 4)
            buf = fd_strplcpy(buf, "addr32 ", end-buf);
        if (!FD_IS64(instr) && FD_ADDRSIZE(instr) == 2)
            buf = fd_strplcpy(buf, "addr16 ", end-buf);
    }
    if (prefix_segment && FD_SEGMENT(instr) != FD_REG_NONE) {
        buf = fd_strplcpy(buf, reg_name(FD_RT_SEG, FD_SEGMENT(instr), 2), end-buf);
        buf = fd_strplcpy(buf, " ", end-buf);
    }

    buf = fd_strplcpy(buf, mnemonic, end-buf);
    buf = fd_strplcpy(buf, sizesuffix, end-buf);

    for (int i = 0; i < 4; i++)
    {
        FdOpType op_type = FD_OP_TYPE(instr, i);
        if (op_type == FD_OT_NONE)
            break;
        buf = fd_strplcpy(buf, &", "[i == 0], end-buf);

        unsigned size = FD_OP_SIZE(instr, i);

        if (op_type == FD_OT_REG) {
            unsigned type = FD_OP_REG_TYPE(instr, i);
            unsigned idx = FD_OP_REG(instr, i);
            buf = fd_strplcpy(buf, reg_name(type, idx, size), end-buf);
        } else if (op_type == FD_OT_MEM) {
            unsigned idx_rt = FD_RT_GPL;
            unsigned idx_sz = FD_ADDRSIZE(instr);
            switch (FD_TYPE(instr)) {
            case FDI_CMPXCHGD: size = 2 * FD_OPSIZE(instr); break;
            case FDI_BOUND: size = 2 * size; break;
            case FDI_JMPF:
            case FDI_CALLF:
            case FDI_LDS:
            case FDI_LES:
            case FDI_LFS:
            case FDI_LGS:
            case FDI_LSS:
                size += 2;
                break;
            case FDI_FLD:
            case FDI_FSTP:
            case FDI_FBLD:
            case FDI_FBSTP:
                size = size != 0 ? size : 10;
                break;
            case FDI_VPGATHERQD:
            case FDI_VGATHERQPS:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZE(instr, 0) * 2;
                break;
            case FDI_VPGATHERDQ:
            case FDI_VGATHERDPD:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZE(instr, 0) / 2;
                break;
            case FDI_VPGATHERDD:
            case FDI_VPGATHERQQ:
            case FDI_VGATHERDPS:
            case FDI_VGATHERQPD:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZE(instr, 0);
                break;
            default: break;
            }
            const char* ptrsize = NULL;
            switch (size) {
            default: break;
            case 1: ptrsize = "byte"; break;
            case 2: ptrsize = "word"; break;
            case 4: ptrsize = "dword"; break;
            case 6: ptrsize = "fword"; break;
            case 8: ptrsize = "qword"; break;
            case 10: ptrsize = "tbyte"; break;
            case 16: ptrsize = "xmmword"; break;
            case 32: ptrsize = "ymmword"; break;
            case 64: ptrsize = "zmmword"; break;
            }
            if (ptrsize) {
                buf = fd_strplcpy(buf, ptrsize, end-buf);
                buf = fd_strplcpy(buf, " ptr ", end-buf);
            }
            unsigned seg = FD_SEGMENT(instr);
            if (seg != FD_REG_NONE) {
                buf = fd_strplcpy(buf, reg_name(FD_RT_SEG, seg, 2), end-buf);
                buf = fd_strplcpy(buf, ":", end-buf);
            }
            buf = fd_strplcpy(buf, "[", end-buf);

            bool has_base = FD_OP_BASE(instr, i) != FD_REG_NONE;
            bool has_idx = FD_OP_INDEX(instr, i) != FD_REG_NONE;
            if (has_base)
                buf = fd_strplcpy(buf, reg_name(FD_RT_GPL, FD_OP_BASE(instr, i), FD_ADDRSIZE(instr)), end-buf);
            if (has_idx) {
                if (has_base)
                    buf = fd_strplcpy(buf, "+", end-buf);
                buf = fd_strplcpy(buf, "1*\0002*\0004*\0008*" + 3*FD_OP_SCALE(instr, i), end-buf);
                buf = fd_strplcpy(buf, reg_name(idx_rt, FD_OP_INDEX(instr, i), idx_sz), end-buf);
            }
            uint64_t disp = FD_OP_DISP(instr, i);
            if (disp && (has_base || has_idx)) {
                buf = fd_strplcpy(buf, (int64_t) disp < 0 ? "-" : "+", end-buf);
                if ((int64_t) disp < 0)
                    disp = -disp;
            }
            if (FD_ADDRSIZE(instr) == 2)
                disp &= 0xffff;
            else if (FD_ADDRSIZE(instr) == 4)
                disp &= 0xffffffff;
            if (disp || (!has_base && !has_idx))
                buf = fd_strplcpy(buf, fd_format_hex(disp, tmp), end-buf);
            buf = fd_strplcpy(buf, "]", end-buf);
        } else if (op_type == FD_OT_IMM || op_type == FD_OT_OFF) {
            size_t immediate = FD_OP_IMM(instr, i);
            // Some instructions have actually two immediate operands which are
            // decoded as a single operand. Split them here appropriately.
            size_t splitimm = 0;
            const char* splitsep = ", ";
            switch (FD_TYPE(instr)) {
            default:
                goto nosplitimm;
            case FDI_SSE_EXTRQ:
            case FDI_SSE_INSERTQ:
                splitimm = immediate & 0xff;
                immediate = (immediate >> 8) & 0xff;
                break;
            case FDI_ENTER:
                splitimm = immediate & 0xffff;
                immediate = (immediate >> 16) & 0xff;
                break;
            case FDI_JMPF:
            case FDI_CALLF:
                splitsep = ":";
                splitimm = (immediate >> 8*size) & 0xffff;
                // immediate is masked below.
                break;
            }
            buf = fd_strplcpy(buf, fd_format_hex(splitimm, tmp), end-buf);
            buf = fd_strplcpy(buf, splitsep, end-buf);

        nosplitimm:
            if (op_type == FD_OT_OFF)
                immediate += addr + FD_SIZE(instr);
            if (size == 1)
                immediate &= 0xff;
            else if (size == 2)
                immediate &= 0xffff;
            else if (size == 4)
                immediate &= 0xffffffff;
            buf = fd_strplcpy(buf, fd_format_hex(immediate, tmp), end-buf);
        }
    }
}

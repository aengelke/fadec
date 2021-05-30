
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <fadec.h>


#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

struct FdStr {
    const char* s;
    unsigned sz;
};

#define fd_stre(s) ((struct FdStr) { (s "\0\0\0\0\0\0\0\0\0\0"), sizeof (s)-1 })

static char*
fd_strplcpy(char* restrict dst, const char* src, size_t size) {
    while (*src && size > 1)
        *dst++ = *src++, size--;
    if (size)
        *dst = 0;
    return dst;
}

static char*
fd_strpcat(char* restrict dst, struct FdStr src) {
    unsigned lim = __builtin_constant_p(src.sz) && src.sz <= 8 ? 8 : 16;
    for (unsigned i = 0; i < lim; i++)
        dst[i] = src.s[i];
    // __builtin_memcpy(dst, src.s, 16);
    return dst + src.sz;
}

static unsigned
fd_clz64(uint64_t v) {
    return __builtin_clzl(v);
}

#if defined(__SSE2__)
#include <immintrin.h>
#endif

static char*
fd_strpcatnum(char dst[static 18], uint64_t val) {
    unsigned lz = fd_clz64(val|1);
    unsigned numbytes = 16 - (lz / 4);
#if defined(__SSE2__)
    __m128i mv = _mm_set_epi64x(0, val << (lz & -4));
    __m128i mvp = _mm_unpacklo_epi8(mv, mv);
    __m128i mva = _mm_srli_epi16(mvp, 12);
    __m128i mvb = _mm_and_si128(mvp, _mm_set1_epi16(0x0f00u));
    __m128i ml = _mm_or_si128(mva, mvb);
    __m128i mn = _mm_or_si128(ml, _mm_set1_epi8(0x30));
    __m128i mgt = _mm_cmpgt_epi8(ml, _mm_set1_epi8(9));
    __m128i mgtm = _mm_and_si128(mgt, _mm_set1_epi8(0x61 - 0x3a));
    __m128i ma = _mm_add_epi8(mn, mgtm);
    __m128i msw = _mm_shufflehi_epi16(_mm_shufflelo_epi16(ma, 0x1b), 0x1b);
    __m128i ms = _mm_shuffle_epi32(msw, 0x4e);
    _mm_storeu_si128((__m128i*) (dst + 2), ms);
#else
    unsigned idx = numbytes + 2;
    do {
        dst[--idx] = "0123456789abcdef"[val % 16];
        val /= 16;
    } while (val);
#endif
    dst[0] = '0';
    dst[1] = 'x';
    return dst + numbytes + 2;
}

static char*
fd_strpcatreg(char* restrict dst, unsigned rt, unsigned ri, unsigned size) {
    static const char nametabidx[] = {
        [FD_RT_GPL] = 0, // 1, 2, 4
        [FD_RT_GPH] = 3,
        [FD_RT_SEG] = 5,
        [FD_RT_FPU] = 6,
        [FD_RT_MMX] = 7,
        [FD_RT_VEC] = 8,
        [FD_RT_CR]  = 9,
        [FD_RT_DR]  = 10,
    };
    static const char nametab[11][17][9] = {
        [0] = { "\2al","\2cl","\2dl","\2bl","\3spl","\3bpl","\3sil","\3dil",
                "\3r8b","\3r9b","\4r10b","\4r11b","\4r12b","\4r13b","\4r14b","\4r15b" },
        [1] = { "\2ax","\2cx","\2dx","\2bx","\2sp","\2bp","\2si","\2di",
                "\3r8w","\3r9w","\4r10w","\4r11w","\4r12w","\4r13w","\4r14w","\4r15w","\2ip" },
        [2] = { "\3eax","\3ecx","\3edx","\3ebx","\3esp","\3ebp","\3esi","\3edi",
                "\3r8d","\3r9d","\4r10d","\4r11d","\4r12d","\4r13d","\4r14d","\4r15d","\3eip" },
        [4] = { "\3rax","\3rcx","\3rdx","\3rbx","\3rsp","\3rbp","\3rsi","\3rdi",
                "\2r8","\2r9","\3r10","\3r11","\3r12","\3r13","\3r14","\3r15","\3rip" },
        [3] = { "","","","","\2ah","\2ch","\2dh","\2bh" },
        [5] = { "\2es","\2cs","\2ss","\2ds","\2fs","\2gs" },
        [6] = { "\5st(0)","\5st(1)","\5st(2)","\5st(3)","\5st(4)","\5st(5)","\5st(6)","\5st(7)" },
        [7] = { "\3mm0","\3mm1","\3mm2","\3mm3","\3mm4","\3mm5","\3mm6","mm7" },
        [8] = { "\4xmm0","\4xmm1","\4xmm2","\4xmm3","\4xmm4","\4xmm5","\4xmm6","\4xmm7",
                "\4xmm8","\4xmm9","\5xmm10","\5xmm11","\5xmm12","\5xmm13","\5xmm14","\5xmm15" },
        [9] = { "\3cr0","","\3cr2","\3cr3","\3cr4","","","","\3cr8" },
        [10] = { "\3dr0","\3dr1","\3dr2","\3dr3","\3dr4","\3dr5","\3dr6","\3dr7" },
    };
    unsigned idx = nametabidx[rt] + (rt == FD_RT_GPL ? size >> 1 : 0);
    const char* name = nametab[idx][ri];
    for (unsigned i = 0; i < 8; i++)
        dst[i] = name[i+1];
    if (UNLIKELY(rt == FD_RT_VEC))
        dst[0] += size >> 5;
    return dst + *name;
}

const char*
fdi_name(FdInstrType ty) {
    return "(invalid)";
}

static char*
fd_mnemonic(char buf[restrict static 48], const FdInstr* instr) {
#define FD_DECODE_TABLE_STRTAB1
    static const char* mnemonic_str =
#include <fadec-table.inc>
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"; // 15 NULL Bytes to prevent overflow
#undef FD_DECODE_TABLE_STRTAB1

#define FD_DECODE_TABLE_STRTAB2
    static const uint16_t mnemonic_offs[] = {
#include <fadec-table.inc>
    };
#undef FD_DECODE_TABLE_STRTAB2

#define FD_DECODE_TABLE_STRTAB3
    static const uint8_t mnemonic_lens[] = {
#include <fadec-table.inc>
    };
#undef FD_DECODE_TABLE_STRTAB3

    const char* mnem = &mnemonic_str[mnemonic_offs[FD_TYPE(instr)]];
    unsigned mnemlen = mnemonic_lens[FD_TYPE(instr)];

    bool prefix_xacq_xrel = false;
    bool prefix_segment = false;

    char sizesuffix[4] = {0};
    unsigned sizesuffixlen = 0;

    if (UNLIKELY(FD_OP_TYPE(instr, 0) == FD_OT_OFF && FD_OP_SIZE(instr, 0) == 2))
        sizesuffix[0] = 'w', sizesuffixlen = 1;

    switch (UNLIKELY(FD_TYPE(instr))) {
    case FDI_C_SEP:
        mnem += FD_OPSIZE(instr) & 0xc;
        mnemlen = 3;
        break;
    case FDI_C_EX:
        mnem += FD_OPSIZE(instr) & 0xc;
        mnemlen = FD_OPSIZE(instr) < 4 ? 3 : 4;
        break;
    case FDI_CMPXCHGD:
        switch (FD_OPSIZE(instr)) {
        default: break;
        case 4: sizesuffix[0] = '8', sizesuffix[1] = 'b', sizesuffixlen = 2; break;
        case 8: sizesuffix[0] = '1', sizesuffix[1] = '6', sizesuffix[2] = 'b', sizesuffixlen = 3; break;
        }
        break;
    case FDI_JCXZ:
        mnemlen = FD_ADDRSIZE(instr) < 4 ? 4 : 5;
        mnem += 5 * (FD_ADDRSIZE(instr) >> 2);
        break;
    case FDI_PUSH:
        if (FD_OP_SIZE(instr, 0) == 2 && FD_OP_TYPE(instr, 0) == FD_OT_IMM)
            sizesuffix[0] = 'w', sizesuffixlen = 1;
        // FALLTHROUGH
    case FDI_POP:
        if (FD_OP_SIZE(instr, 0) == 2 && FD_OP_TYPE(instr, 0) == FD_OT_REG &&
            FD_OP_REG_TYPE(instr, 0) == FD_RT_SEG)
            sizesuffix[0] = 'w', sizesuffixlen = 1;
        break;
    case FDI_XCHG:
        if (FD_OP_TYPE(instr, 0) == FD_OT_MEM)
            prefix_xacq_xrel = true;
        break;
    case FDI_MOV:
        // MOV C6h/C7h can have XRELEASE prefix.
        if (FD_HAS_REP(instr) && FD_OP_TYPE(instr, 0) == FD_OT_MEM &&
            FD_OP_TYPE(instr, 1) == FD_OT_IMM)
            prefix_xacq_xrel = true;
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
            sizesuffix[0] = '6', sizesuffix[1] = '4', sizesuffixlen = 2;
        break;
    case FDI_RET:
    case FDI_ENTER:
    case FDI_LEAVE:
        if (FD_OPSIZE(instr) == 2)
            sizesuffix[0] = 'w', sizesuffixlen = 1;
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
        if (FD_HAS_REP(instr))
            buf = fd_strpcat(buf, fd_stre("rep "));
        if (FD_HAS_REPNZ(instr))
            buf = fd_strpcat(buf, fd_stre("repnz "));
        if (FD_IS64(instr) && FD_ADDRSIZE(instr) == 4)
            buf = fd_strpcat(buf, fd_stre("addr32 "));
        if (!FD_IS64(instr) && FD_ADDRSIZE(instr) == 2)
            buf = fd_strpcat(buf, fd_stre("addr16 "));
        // FALLTHROUGH
    case FDI_PUSHA:
    case FDI_POPA:
    case FDI_PUSHF:
    case FDI_POPF:
    case FDI_RETF:
    case FDI_IRET:
    case FDI_IN:
    case FDI_OUT:
        switch (FD_OPSIZE(instr)) {
        default: break;
        case 1: sizesuffix[0] = 'b'; sizesuffixlen = 1; break;
        case 2: sizesuffix[0] = 'w'; sizesuffixlen = 1; break;
        case 4: sizesuffix[0] = 'd'; sizesuffixlen = 1; break;
        case 8: sizesuffix[0] = 'q'; sizesuffixlen = 1; break;
        }
        break;
    default: break;
    }

    if (UNLIKELY(prefix_xacq_xrel || FD_HAS_LOCK(instr))) {
        if (FD_HAS_REP(instr))
            buf = fd_strpcat(buf, fd_stre("xrelease "));
        if (FD_HAS_REPNZ(instr))
            buf = fd_strpcat(buf, fd_stre("xacquire "));
    }
    if (UNLIKELY(FD_HAS_LOCK(instr)))
        buf = fd_strpcat(buf, fd_stre("lock "));
    if (UNLIKELY(prefix_segment && FD_SEGMENT(instr) != FD_REG_NONE)) {
        *buf++ = "ecsdfg\0"[FD_SEGMENT(instr) & 7];
        *buf++ = 's';
        *buf++ = ' ';
    }

    for (unsigned i = 0; i < 16; i++)
        buf[i] = mnem[i];
    buf += mnemlen;
    for (unsigned i = 0; i < 4; i++)
        buf[i] = sizesuffix[i];
    buf += sizesuffixlen;

    return buf;
}

static char*
fd_format_impl(char buf[restrict static 128], const FdInstr* instr, uint64_t addr) {
    buf = fd_mnemonic(buf, instr);

    for (int i = 0; i < 4; i++)
    {
        FdOpType op_type = FD_OP_TYPE(instr, i);
        if (op_type == FD_OT_NONE)
            break;
        if (i > 0)
            *buf++ = ',';
        *buf++ = ' ';

        unsigned size = FD_OP_SIZE(instr, i);

        if (op_type == FD_OT_REG) {
            unsigned type = FD_OP_REG_TYPE(instr, i);
            unsigned idx = FD_OP_REG(instr, i);
            buf = fd_strpcatreg(buf, type, idx, size);
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

            // 0=0h,1=1h,2=2h,4=5h,6=7h,8=bh,10=9h,16=6h,32=ch,64=8h
            unsigned ptrszidx = (size ^ (size >> 2) ^ (size >> 3)) & 0xf;
            const char* ptrsizes =
                "\00               "  // 0x0
                "\11byte ptr       "  // 0x1
                "\11word ptr       "  // 0x2
                "\00               "  // 0x3
                "\00               "  // 0x4
                "\12dword ptr      "  // 0x5
                "\14xmmword ptr    "  // 0x6
                "\12fword ptr      "  // 0x7
                "\14zmmword ptr    "  // 0x8
                "\12tbyte ptr      "  // 0x9
                "\00               "  // 0xa
                "\12qword ptr      "  // 0xb
                "\14ymmword ptr    "; // 0xc
            const char* ptrsize = ptrsizes + 16 * ptrszidx;
            buf = fd_strpcat(buf, (struct FdStr) { ptrsize+1, *ptrsize });

            unsigned seg = FD_SEGMENT(instr);
            if (seg != FD_REG_NONE) {
                *buf++ = "ecsdfg\0"[seg & 7];
                *buf++ = 's';
                *buf++ = ':';
            }
            *buf++ = '[';

            bool has_base = FD_OP_BASE(instr, i) != FD_REG_NONE;
            bool has_idx = FD_OP_INDEX(instr, i) != FD_REG_NONE;
            if (has_base)
                buf = fd_strpcatreg(buf, FD_RT_GPL, FD_OP_BASE(instr, i), FD_ADDRSIZE(instr));
            if (has_idx) {
                if (has_base)
                    *buf++ = '+';
                *buf++ = '0' + (1 << FD_OP_SCALE(instr, i));
                *buf++ = '*';
                buf = fd_strpcatreg(buf, idx_rt, FD_OP_INDEX(instr, i), idx_sz);
            }
            uint64_t disp = FD_OP_DISP(instr, i);
            if (disp && (has_base || has_idx)) {
                *buf++ = (int64_t) disp < 0 ? '-' : '+';
                if ((int64_t) disp < 0)
                    disp = -disp;
            }
            if (FD_ADDRSIZE(instr) == 2)
                disp &= 0xffff;
            else if (FD_ADDRSIZE(instr) == 4)
                disp &= 0xffffffff;
            if (disp || (!has_base && !has_idx))
                buf = fd_strpcatnum(buf, disp);
            *buf++ = ']';
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
            buf = fd_strpcatnum(buf, splitimm);
            buf = fd_strplcpy(buf, splitsep, 4);

        nosplitimm:
            if (op_type == FD_OT_OFF)
                immediate += addr + FD_SIZE(instr);
            if (size == 1)
                immediate &= 0xff;
            else if (size == 2)
                immediate &= 0xffff;
            else if (size == 4)
                immediate &= 0xffffffff;
            buf = fd_strpcatnum(buf, immediate);
        }
    }
    *buf++ = '\0';
    return buf;
}

void
fd_format(const FdInstr* instr, char* buffer, size_t len)
{
    fd_format_abs(instr, 0, buffer, len);
}

void
fd_format_abs(const FdInstr* instr, uint64_t addr, char* restrict buffer, size_t len) {
    char tmp[128];
    char* buf = buffer;
    if (UNLIKELY(len < 128)) {
        if (!len)
            return;
        buf = tmp;
    }

    char* end = fd_format_impl(buf, instr, addr);

    if (buf != buffer) {
        unsigned i;
        for (i = 0; i < (end - tmp) && i < len-1; i++)
            buffer[i] = tmp[i];
        buffer[i] = '\0';
    }
}

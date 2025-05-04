
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

#include <fadec.h>


#ifdef __GNUC__
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define DECLARE_ARRAY_SIZE(n) static n
#define DECLARE_RESTRICTED_ARRAY_SIZE(n) restrict static n
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#define DECLARE_ARRAY_SIZE(n) n
#define DECLARE_RESTRICTED_ARRAY_SIZE(n) n
#endif

#if defined(__has_attribute)
#if __has_attribute(fallthrough)
#define FALLTHROUGH() __attribute__((fallthrough))
#endif
#endif
#if !defined(FALLTHROUGH)
#define FALLTHROUGH() ((void)0)
#endif

struct FdStr {
    const char* s;
    unsigned sz;
};

#define fd_stre(s) ((struct FdStr) { (s "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"), sizeof (s)-1 })

static char*
fd_strpcat(char* restrict dst, struct FdStr src) {
#ifdef __GNUC__
    unsigned lim = __builtin_constant_p(src.sz) && src.sz <= 8 ? 8 : 16;
#else
    unsigned lim = 16;
#endif
    for (unsigned i = 0; i < lim; i++)
        dst[i] = src.s[i];
    // __builtin_memcpy(dst, src.s, 16);
    return dst + src.sz;
}

static unsigned
fd_clz64(uint64_t v) {
#if defined(__GNUC__)
    return __builtin_clzll(v);
#elif defined(_MSC_VER)
    unsigned long index;

    // 32-bit MSVC doesn't support _BitScanReverse64. This is an attempt to
    // identify this case.
#if INTPTR_MAX == INT64_MAX
    _BitScanReverse64(&index, v);
#else
    if (_BitScanReverse(&index, v >> 32))
        return 31 - index;

    _BitScanReverse(&index, v & 0xffffffff);
#endif

    return 63 - index;
#else
#error Unsupported compiler.
#endif
}

#if defined(__SSE2__)
#include <immintrin.h>
#endif

static char*
fd_strpcatnum(char dst[DECLARE_ARRAY_SIZE(18)], uint64_t val) {
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
    _mm_storeu_si128((__m128i_u*) (dst + 2), ms);
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
fd_strpcatreg(char* restrict dst, size_t rt, size_t ri, unsigned size) {
    const char* nametab =
        "\2al\4bnd0\2cl\4bnd1\2dl\4bnd2\2bl\4bnd3"
        "\3spl\0   \3bpl\0   \3sil\0   \3dil\0   "
        "\3r8b\0   \3r9b\0   \4r10b\0  \4r11b\0  "
        "\4r12b\2ah\4r13b\2ch\4r14b\2dh\4r15b\2bh\0\0      "

        "\2ax\4tmm0\2cx\4tmm1\2dx\4tmm2\2bx\4tmm3"
        "\2sp\4tmm4\2bp\4tmm5\2si\4tmm6\2di\4tmm7"
        "\3r8w \2es\3r9w \2cs\4r10w\2ss\4r11w\2ds"
        "\4r12w\2fs\4r13w\2gs\4r14w\0  \4r15w\0  \2ip\0    "

        "\3eax\3mm0\3ecx\3mm1\3edx\3mm2\3ebx\3mm3"
        "\3esp\3mm4\3ebp\3mm5\3esi\3mm6\3edi\3mm7"
        "\3r8d \2k0\3r9d \2k1\4r10d\2k2\4r11d\2k3"
        "\4r12d\2k4\4r13d\2k5\4r14d\2k6\4r15d\2k7\3eip\0   "

        "\3rax\3cr0\3rcx\0   \3rdx\3cr2\3rbx\3cr3"
        "\3rsp\3cr4\3rbp\0   \3rsi\0   \3rdi\0   "
        "\2r8 \3cr8\2r9 \3dr0\3r10\3dr1\3r11\3dr2"
        "\3r12\3dr3\3r13\3dr4\3r14\3dr5\3r15\3dr6\3rip\3dr7"

        "\5st(0)\0 \5st(1)\0 \5st(2)\0 \5st(3)\0 "
        "\5st(4)\0 \5st(5)\0 \5st(6)\0 \5st(7)\0 "

        "\4xmm0\0  \4xmm1\0  \4xmm2\0  \4xmm3\0  "
        "\4xmm4\0  \4xmm5\0  \4xmm6\0  \4xmm7\0  "
        "\4xmm8\0  \4xmm9\0  \5xmm10\0 \5xmm11\0 "
        "\5xmm12\0 \5xmm13\0 \5xmm14\0 \5xmm15\0 "
        "\5xmm16\0 \5xmm17\0 \5xmm18\0 \5xmm19\0 "
        "\5xmm20\0 \5xmm21\0 \5xmm22\0 \5xmm23\0 "
        "\5xmm24\0 \5xmm25\0 \5xmm26\0 \5xmm27\0 "
        "\5xmm28\0 \5xmm29\0 \5xmm30\0 \5xmm31\0 ";

    static const uint16_t nametabidx[] = {
        [FD_RT_GPL] = 0 * 17*8 + 0 * 8 + 0,
        [FD_RT_GPH] = 0 * 17*8 + 8 * 8 + 5,
        [FD_RT_SEG] = 1 * 17*8 + 8 * 8 + 5,
        [FD_RT_FPU] = 4 * 17*8 + 0 * 8 + 0,
        [FD_RT_MMX] = 2 * 17*8 + 0 * 8 + 4,
        [FD_RT_VEC] = 4 * 17*8 + 8 * 8 + 0,
        [FD_RT_MASK]= 2 * 17*8 + 8 * 8 + 5,
        [FD_RT_BND] = 0 * 17*8 + 0 * 8 + 3,
        [FD_RT_CR]  = 3 * 17*8 + 0 * 8 + 4,
        [FD_RT_DR]  = 3 * 17*8 + 9 * 8 + 4,
        [FD_RT_TMM] = 1 * 17*8 + 0 * 8 + 3,
    };

    unsigned idx = rt == FD_RT_GPL ? size * 17*8 : nametabidx[rt];
    const char* name = nametab + idx + 8*ri;
    for (unsigned i = 0; i < 8; i++)
        dst[i] = name[i+1];
    if (UNLIKELY(rt == FD_RT_VEC && size > 4))
        dst[0] += size - 4;
    return dst + *name;
}

const char*
fdi_name(FdInstrType ty) {
    (void) ty;
    return "(invalid)";
}

static char*
fd_mnemonic(char buf[DECLARE_RESTRICTED_ARRAY_SIZE(48)], const FdInstr* instr) {
#define FD_DECODE_TABLE_STRTAB1
    static const char* mnemonic_str =
#include <fadec-decode-private.inc>
        // 20 NULL Bytes to prevent out-of-bounds reads
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
#undef FD_DECODE_TABLE_STRTAB1

#define FD_DECODE_TABLE_STRTAB2
    static const uint16_t mnemonic_offs[] = {
#include <fadec-decode-private.inc>
    };
#undef FD_DECODE_TABLE_STRTAB2

#define FD_DECODE_TABLE_STRTAB3
    static const uint8_t mnemonic_lens[] = {
#include <fadec-decode-private.inc>
    };
#undef FD_DECODE_TABLE_STRTAB3

    const char* mnem = &mnemonic_str[mnemonic_offs[FD_TYPE(instr)]];
    unsigned mnemlen = mnemonic_lens[FD_TYPE(instr)];

    bool prefix_xacq_xrel = false;
    bool prefix_segment = false;

    char sizesuffix[4] = {0};
    unsigned sizesuffixlen = 0;

    if (UNLIKELY(FD_OP_TYPE(instr, 0) == FD_OT_OFF && FD_OP_SIZELG(instr, 0) == 1))
        sizesuffix[0] = 'w', sizesuffixlen = 1;

    switch (FD_TYPE(instr)) {
    case FDI_C_SEP:
        mnem += FD_OPSIZE(instr) & 0xc;
        mnemlen = 3;
        break;
    case FDI_C_EX:
        mnem += FD_OPSIZE(instr) & 0xc;
        mnemlen = FD_OPSIZE(instr) < 4 ? 3 : 4;
        break;
    case FDI_CMPXCHGD:
        switch (FD_OPSIZELG(instr)) {
        default: break;
        case 2: sizesuffix[0] = '8', sizesuffix[1] = 'b', sizesuffixlen = 2; break;
        case 3: sizesuffix[0] = '1', sizesuffix[1] = '6', sizesuffix[2] = 'b', sizesuffixlen = 3; break;
        }
        break;
    case FDI_JCXZ:
        mnemlen = FD_ADDRSIZELG(instr) == 1 ? 4 : 5;
        mnem += 5 * (FD_ADDRSIZELG(instr) - 1);
        break;
    case FDI_PUSH:
        if (FD_OP_SIZELG(instr, 0) == 1 && FD_OP_TYPE(instr, 0) == FD_OT_IMM)
            sizesuffix[0] = 'w', sizesuffixlen = 1;
        FALLTHROUGH();
    case FDI_POP:
        if (FD_OP_SIZELG(instr, 0) == 1 && FD_OP_TYPE(instr, 0) == FD_OT_REG &&
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
        if (FD_OPSIZELG(instr) == 3)
            sizesuffix[0] = '6', sizesuffix[1] = '4', sizesuffixlen = 2;
        break;
    case FDI_EVX_MOV_G2X:
    case FDI_EVX_MOV_X2G:
    case FDI_EVX_PEXTR:
        sizesuffix[0] = "bwdq"[FD_OP_SIZELG(instr, 0)];
        sizesuffixlen = 1;
        break;
    case FDI_EVX_PBROADCAST:
        sizesuffix[0] = "bwdq"[FD_OP_SIZELG(instr, 1)];
        sizesuffixlen = 1;
        break;
    case FDI_EVX_PINSR:
        sizesuffix[0] = "bwdq"[FD_OP_SIZELG(instr, 2)];
        sizesuffixlen = 1;
        break;
    case FDI_RET:
    case FDI_ENTER:
    case FDI_LEAVE:
        if (FD_OPSIZELG(instr) == 1)
            sizesuffix[0] = 'w', sizesuffixlen = 1;
        break;
    case FDI_LODS:
    case FDI_MOVS:
    case FDI_CMPS:
    case FDI_OUTS:
        prefix_segment = true;
        FALLTHROUGH();
    case FDI_STOS:
    case FDI_SCAS:
    case FDI_INS:
        if (FD_HAS_REP(instr))
            buf = fd_strpcat(buf, fd_stre("rep "));
        if (FD_HAS_REPNZ(instr))
            buf = fd_strpcat(buf, fd_stre("repnz "));
        if (FD_IS64(instr) && FD_ADDRSIZELG(instr) == 2)
            buf = fd_strpcat(buf, fd_stre("addr32 "));
        if (!FD_IS64(instr) && FD_ADDRSIZELG(instr) == 1)
            buf = fd_strpcat(buf, fd_stre("addr16 "));
        FALLTHROUGH();
    case FDI_IN:
    case FDI_OUT:
        if (FD_OP_TYPE(instr, 0) != FD_OT_NONE)
            break;
        FALLTHROUGH();
    case FDI_PUSHA:
    case FDI_POPA:
    case FDI_PUSHF:
    case FDI_POPF:
    case FDI_RETF:
    case FDI_IRET:
        sizesuffix[0] = "bwdq"[FD_OPSIZELG(instr)];
        sizesuffixlen = 1;
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

    for (unsigned i = 0; i < 20; i++)
        buf[i] = mnem[i];
    buf += mnemlen;
    for (unsigned i = 0; i < 4; i++)
        buf[i] = sizesuffix[i];
    buf += sizesuffixlen;

    return buf;
}

static char*
fd_format_impl(char buf[DECLARE_RESTRICTED_ARRAY_SIZE(128)], const FdInstr* instr, uint64_t addr) {
    buf = fd_mnemonic(buf, instr);

    for (int i = 0; i < 4; i++)
    {
        FdOpType op_type = FD_OP_TYPE(instr, i);
        if (op_type == FD_OT_NONE)
            break;
        if (i > 0)
            *buf++ = ',';
        *buf++ = ' ';

        int size = FD_OP_SIZELG(instr, i);

        if (op_type == FD_OT_REG) {
            unsigned type = FD_OP_REG_TYPE(instr, i);
            unsigned idx = FD_OP_REG(instr, i);
            buf = fd_strpcatreg(buf, type, idx, size);
        } else if (op_type == FD_OT_MEM || op_type == FD_OT_MEMBCST) {
            unsigned idx_rt = FD_RT_GPL;
            unsigned idx_sz = FD_ADDRSIZELG(instr);
            switch (FD_TYPE(instr)) {
            case FDI_CMPXCHGD: size = FD_OPSIZELG(instr) + 1; break;
            case FDI_BOUND: size += 1; break;
            case FDI_JMPF:
            case FDI_CALLF:
            case FDI_LDS:
            case FDI_LES:
            case FDI_LFS:
            case FDI_LGS:
            case FDI_LSS:
                size += 6;
                break;
            case FDI_FLD:
            case FDI_FSTP:
            case FDI_FBLD:
            case FDI_FBSTP:
                size = size >= 0 ? size : 9;
                break;
            case FDI_VPGATHERQD:
            case FDI_VGATHERQPS:
            case FDI_EVX_PGATHERQD:
            case FDI_EVX_GATHERQPS:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZELG(instr, 0) + 1;
                break;
            case FDI_EVX_PSCATTERQD:
            case FDI_EVX_SCATTERQPS:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZELG(instr, 1) + 1;
                break;
            case FDI_VPGATHERDQ:
            case FDI_VGATHERDPD:
            case FDI_EVX_PGATHERDQ:
            case FDI_EVX_GATHERDPD:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZELG(instr, 0) - 1;
                break;
            case FDI_EVX_PSCATTERDQ:
            case FDI_EVX_SCATTERDPD:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZELG(instr, 1) - 1;
                break;
            case FDI_VPGATHERDD:
            case FDI_VPGATHERQQ:
            case FDI_VGATHERDPS:
            case FDI_VGATHERQPD:
            case FDI_EVX_PGATHERDD:
            case FDI_EVX_PGATHERQQ:
            case FDI_EVX_GATHERDPS:
            case FDI_EVX_GATHERQPD:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZELG(instr, 0);
                break;
            case FDI_EVX_PSCATTERDD:
            case FDI_EVX_PSCATTERQQ:
            case FDI_EVX_SCATTERDPS:
            case FDI_EVX_SCATTERQPD:
                idx_rt = FD_RT_VEC;
                idx_sz = FD_OP_SIZELG(instr, 1);
                break;
            default: break;
            }

            if (op_type == FD_OT_MEMBCST)
                size = FD_OP_BCSTSZLG(instr, i);

            const char* ptrsizes =
                "\00               "
                "\11byte ptr       "
                "\11word ptr       "
                "\12dword ptr      "
                "\12qword ptr      "
                "\14xmmword ptr    "
                "\14ymmword ptr    "
                "\14zmmword ptr    "
                "\12dword ptr      "  // far ptr; word + 2
                "\12fword ptr      "  // far ptr; dword + 2
                "\12tbyte ptr      "; // far ptr/FPU; qword + 2
            const char* ptrsize = ptrsizes + 16 * (size + 1);
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
                buf = fd_strpcatreg(buf, FD_RT_GPL, FD_OP_BASE(instr, i), FD_ADDRSIZELG(instr));
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
            if (FD_ADDRSIZELG(instr) == 1)
                disp &= 0xffff;
            else if (FD_ADDRSIZELG(instr) == 2)
                disp &= 0xffffffff;
            if (disp || (!has_base && !has_idx))
                buf = fd_strpcatnum(buf, disp);
            *buf++ = ']';

            if (UNLIKELY(op_type == FD_OT_MEMBCST)) {
                // {1toX}, X = FD_OP_SIZE(instr, i) / BCSTSZ (=> 2/4/8/16/32)
                unsigned bcstszidx = FD_OP_SIZELG(instr, i) - FD_OP_BCSTSZLG(instr, i) - 1;
                const char* bcstsizes = "\6{1to2} \6{1to4} \6{1to8} \7{1to16}\7{1to32}         ";
                const char* bcstsize = bcstsizes + bcstszidx * 8;
                buf = fd_strpcat(buf, (struct FdStr) { bcstsize+1, *bcstsize });
            }
        } else if (op_type == FD_OT_IMM || op_type == FD_OT_OFF) {
            uint64_t immediate = FD_OP_IMM(instr, i);
            // Some instructions have actually two immediate operands which are
            // decoded as a single operand. Split them here appropriately.
            switch (FD_TYPE(instr)) {
            default:
                goto nosplitimm;
            case FDI_SSE_EXTRQ:
            case FDI_SSE_INSERTQ:
                buf = fd_strpcatnum(buf, immediate & 0xff);
                buf = fd_strpcat(buf, fd_stre(", "));
                immediate = (immediate >> 8) & 0xff;
                break;
            case FDI_ENTER:
                buf = fd_strpcatnum(buf, immediate & 0xffff);
                buf = fd_strpcat(buf, fd_stre(", "));
                immediate = (immediate >> 16) & 0xff;
                break;
            case FDI_JMPF:
            case FDI_CALLF:
                buf = fd_strpcatnum(buf, (immediate >> (8 << size)) & 0xffff);
                *buf++ = ':';
                // immediate is masked below.
                break;
            }

        nosplitimm:
            if (op_type == FD_OT_OFF)
                immediate += addr + FD_SIZE(instr);
            if (size == 0)
                immediate &= 0xff;
            else if (size == 1)
                immediate &= 0xffff;
            else if (size == 2)
                immediate &= 0xffffffff;
            buf = fd_strpcatnum(buf, immediate);
        }

        if (i == 0 && FD_MASKREG(instr)) {
            *buf++ = '{';
            buf = fd_strpcatreg(buf, FD_RT_MASK, FD_MASKREG(instr), 0);
            *buf++ = '}';
            if (FD_MASKZERO(instr))
                buf = fd_strpcat(buf, fd_stre("{z}"));
        }
    }
    if (UNLIKELY(FD_ROUNDCONTROL(instr) != FD_RC_MXCSR)) {
        switch (FD_ROUNDCONTROL(instr)) {
        case FD_RC_RN: buf = fd_strpcat(buf, fd_stre(", {rn-sae}")); break;
        case FD_RC_RD: buf = fd_strpcat(buf, fd_stre(", {rd-sae}")); break;
        case FD_RC_RU: buf = fd_strpcat(buf, fd_stre(", {ru-sae}")); break;
        case FD_RC_RZ: buf = fd_strpcat(buf, fd_stre(", {rz-sae}")); break;
        case FD_RC_SAE: buf = fd_strpcat(buf, fd_stre(", {sae}")); break;
        default: break; // should not happen
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

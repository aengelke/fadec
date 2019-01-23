
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <fadec.h>


#define FD_DECODE_TABLE_STRTAB1
static const char* _mnemonic_str =
#include <decode-table.inc>
;
#undef FD_DECODE_TABLE_STRTAB1

#define FD_DECODE_TABLE_STRTAB2
static const uint16_t _mnemonic_offs[] = {
#include <decode-table.inc>
};
#undef FD_DECODE_TABLE_STRTAB2

#define FMT_CONCAT(buf, end, ...) do { \
            buf += snprintf(buf, end - buf, __VA_ARGS__); \
            if (buf > end) \
                buf = end; \
        } while (0)

void
fd_format(const FdInstr* instr, char* buffer, size_t len)
{
    char* buf = buffer;
    char* end = buffer + len;

    FMT_CONCAT(buf, end, "[");
    if (FD_HAS_REP(instr))
        FMT_CONCAT(buf, end, "rep:");
    if (FD_HAS_REPNZ(instr))
        FMT_CONCAT(buf, end, "repnz:");
    if (FD_SEGMENT(instr) < 6)
        FMT_CONCAT(buf, end, "%cs:", "ecsdfg"[FD_SEGMENT(instr)]);
    if (FD_IS64(instr) && FD_ADDRSIZE(instr) == 4)
        FMT_CONCAT(buf, end, "addr32:");
    if (!FD_IS64(instr) && FD_ADDRSIZE(instr) == 2)
        FMT_CONCAT(buf, end, "addr16:");
    if (FD_HAS_LOCK(instr))
        FMT_CONCAT(buf, end, "lock:");

    FMT_CONCAT(buf, end, "%s", &_mnemonic_str[_mnemonic_offs[FD_TYPE(instr)]]);
    if (FD_OPSIZE(instr))
        FMT_CONCAT(buf, end, "_%u", FD_OPSIZE(instr));

    for (int i = 0; i < 4; i++)
    {
        FdOpType op_type = FD_OP_TYPE(instr, i);
        if (op_type == FD_OP_NONE)
            break;

        const char* op_type_name = "reg\0imm\0mem" + op_type * 4 - 4;
        FMT_CONCAT(buf, end, " %s%u:", op_type_name, FD_OP_SIZE(instr, i));

        switch (op_type)
        {
        size_t immediate;
        bool has_base;
        bool has_idx;
        bool has_disp;
        case FD_OP_REG:
            if (FD_OP_REG_HIGH(instr, i))
                FMT_CONCAT(buf, end, "r%uh", FD_OP_REG(instr, i) - 4);
            else
                FMT_CONCAT(buf, end, "r%u", FD_OP_REG(instr, i));
            break;
        case FD_OP_IMM:
            immediate = FD_OP_IMM(instr, i);
            if (FD_OP_SIZE(instr, i) == 1)
                immediate &= 0xff;
            else if (FD_OP_SIZE(instr, i) == 2)
                immediate &= 0xffff;
            else if (FD_OP_SIZE(instr, i) == 4)
                immediate &= 0xffffffff;
            FMT_CONCAT(buf, end, "0x%lx", immediate);
            break;
        case FD_OP_MEM:
            has_base = FD_OP_BASE(instr, i) != FD_REG_NONE;
            has_idx = FD_OP_INDEX(instr, i) != FD_REG_NONE;
            has_disp = FD_OP_DISP(instr, i) != 0;
            if (has_base)
            {
                FMT_CONCAT(buf, end, "r%u", FD_OP_BASE(instr, i));
                if (has_idx || has_disp)
                    FMT_CONCAT(buf, end, "+");
            }
            if (has_idx)
            {
                FMT_CONCAT(buf, end, "%u*r%u", 1 << FD_OP_SCALE(instr, i),
                           FD_OP_INDEX(instr, i));
                if (has_disp)
                    FMT_CONCAT(buf, end, "+");
            }
            if (FD_OP_DISP(instr, i) < 0)
                FMT_CONCAT(buf, end, "-0x%lx", -FD_OP_DISP(instr, i));
            else if (has_disp || (!has_base && !has_idx))
                FMT_CONCAT(buf, end, "0x%lx", FD_OP_DISP(instr, i));
            break;
        case FD_OP_NONE:
        default:
            break;
        }
    }

    FMT_CONCAT(buf, end, "]");
}


#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <decode.h>


#define DECODE_TABLE_STRTAB1
static const char* _mnemonic_str =
#include <decode-table.inc>
;
#undef DECODE_TABLE_STRTAB1

#define DECODE_TABLE_STRTAB2
static const uint16_t _mnemonic_offs[] = {
#include <decode-table.inc>
};
#undef DECODE_TABLE_STRTAB2

#define FMT_CONCAT(buf, end, ...) do { \
            buf += snprintf(buf, end - buf, __VA_ARGS__); \
            if (buf > end) \
                buf = end; \
        } while (0)

void
instr_format(const Instr* instr, char buffer[128])
{
    char* buf = buffer;
    char* end = buffer + 128;

    FMT_CONCAT(buf, end, "[");
    if (INSTR_HAS_REP(instr))
        FMT_CONCAT(buf, end, "rep:");
    if (INSTR_HAS_REPNZ(instr))
        FMT_CONCAT(buf, end, "repnz:");
    if (INSTR_SEGMENT(instr) < 6)
        FMT_CONCAT(buf, end, "%cs:", "ecsdfg"[INSTR_SEGMENT(instr)]);
    if (INSTR_IS64(instr) && INSTR_ADDRSZ(instr) == 4)
        FMT_CONCAT(buf, end, "addr32:");
    if (!INSTR_IS64(instr) && INSTR_ADDRSZ(instr) == 2)
        FMT_CONCAT(buf, end, "addr16:");
    if (INSTR_HAS_LOCK(instr))
        FMT_CONCAT(buf, end, "lock:");

    FMT_CONCAT(buf, end, "%s", &_mnemonic_str[_mnemonic_offs[instr->type]]);
    if (INSTR_WIDTH(instr))
        FMT_CONCAT(buf, end, "_%u", INSTR_WIDTH(instr));

    for (int i = 0; i < 4; i++)
    {
        const struct Operand* operand = &instr->operands[i];
        if (operand->type == OT_NONE)
            break;

        const char* op_type_name = "reg\0imm\0mem" + operand->type * 4 - 4;
        FMT_CONCAT(buf, end, " %s%u:", op_type_name, operand->size);

        switch (operand->type)
        {
        size_t immediate;
        case OT_REG:
            if (operand->size == 1 && !INSTR_HAS_REX(instr) &&
                operand->reg >= 4 && operand->reg < 8)
                FMT_CONCAT(buf, end, "r%uh", operand->reg - 4);
            else
                FMT_CONCAT(buf, end, "r%u", operand->reg);
            break;
        case OT_IMM:
            immediate = instr->immediate;
            if (operand->size == 1)
                immediate &= 0xff;
            else if (operand->size == 2)
                immediate &= 0xffff;
            else if (operand->size == 4)
                immediate &= 0xffffffff;
            FMT_CONCAT(buf, end, "0x%lx", immediate);
            break;
        case OT_MEM:
            if (!reg_is_none(operand->reg))
            {
                FMT_CONCAT(buf, end, "r%u", operand->reg);
                if (instr->scale != 0 || instr->disp > 0)
                    FMT_CONCAT(buf, end, "+");
            }
            if (instr->scale != 0)
            {
                FMT_CONCAT(buf, end, "%u*r%u", 1 << (instr->scale - 1),
                           instr->sreg);
                if (instr->disp > 0)
                    FMT_CONCAT(buf, end, "+");
            }
            if (instr->disp < 0)
                FMT_CONCAT(buf, end, "-0x%lx", -instr->disp);
            else if ((reg_is_none(operand->reg) && instr->scale == 0) ||
                     instr->disp > 0)
                FMT_CONCAT(buf, end, "0x%lx", instr->disp);
            break;
        case OT_NONE:
        default:
            break;
        }
    }

    FMT_CONCAT(buf, end, "]");
}

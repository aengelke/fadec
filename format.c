
#include <stddef.h>
#include <stdint.h>

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

static
void
instr_format_decimal(char** cur, uint32_t value)
{
    char buffer[32];
    size_t buf_idx = sizeof(buffer) - 1;
    if (value == 0)
    {
        buffer[buf_idx] = '0';
    }
    else
    {
        while (value > 0)
        {
            uint32_t digit = value % 10;
            buffer[buf_idx--] = '0' + digit;
            value /= 10;
        }
        buf_idx++;
    }

    size_t length = sizeof(buffer) - buf_idx;
    __builtin_memcpy(*cur, buffer + buf_idx, length);
    *cur += length;
}

static
void
instr_format_hex(char** cur, size_t value)
{
    char buffer[32];
    size_t buf_idx = sizeof(buffer) - 1;
    if (value == 0)
    {
        buffer[buf_idx] = '0';
    }
    else
    {
        while (value > 0)
        {
            uint32_t nibble = value & 0xf;
            buffer[buf_idx--] = "0123456789abcdef"[nibble];
            value >>= 4;
        }
        buf_idx++;
    }
    buffer[--buf_idx] = 'x';
    buffer[--buf_idx] = '0';

    size_t length = sizeof(buffer) - buf_idx;
    __builtin_memcpy(*cur, buffer + buf_idx, length);
    *cur += length;
}

void
instr_format(const Instr* instr, char buffer[128])
{
    char* cur = buffer;
    *(cur++) = '[';

    const char* mnemonic = &_mnemonic_str[_mnemonic_offs[instr->type]];
    while (*mnemonic)
    {
        *(cur++) = *(mnemonic++);
    }

    if (INSTR_WIDTH(instr))
    {
        *(cur++) = '_';
        instr_format_decimal(&cur, INSTR_WIDTH(instr));
    }

    for (int i = 0; i < 4; i++)
    {
        const struct Operand* operand = &instr->operands[i];
        if (operand->type == OT_NONE)
        {
            break;
        }

        __builtin_memcpy(cur, " REG IMM MEM" + operand->type * 4 - 4, 4);
        cur += 4;
        instr_format_decimal(&cur, operand->size);
        *(cur++) = ':';

        switch (operand->type)
        {
            size_t immediate;
            case OT_REG:
                instr_format_decimal(&cur, reg_index(operand->reg));
                break;
            case OT_IMM:
                immediate = instr->immediate;
                if (operand->size == 1)
                {
                    immediate &= 0xff;
                }
                else if (operand->size == 2)
                {
                    immediate &= 0xffff;
                }
#if defined(ARCH_X86_64)
                else if (operand->size == 4)
                {
                    immediate &= 0xffffffff;
                }
#endif
                instr_format_hex(&cur, immediate);
                break;
            case OT_MEM:
                if (!reg_is_none(operand->reg))
                {
                    instr_format_decimal(&cur, reg_index(operand->reg));
                    *(cur++) = ':';
                }
                if (instr->scale != 0)
                {
                    uint8_t scale = 1 << (instr->scale - 1);
                    instr_format_decimal(&cur, scale);
                    *(cur++) = '*';
                    instr_format_decimal(&cur, reg_index(instr->sreg));
                    *(cur++) = ':';
                }
                if (instr->disp < 0)
                {
                    *(cur++) = '-';
                    instr_format_hex(&cur, -instr->disp);
                }
                else
                {
                    instr_format_hex(&cur, instr->disp);
                }
                break;
            case OT_NONE:
            default:
                break;
        }
    }

    *(cur++) = ']';
    *(cur++) = '\0';

#ifndef NDEBUG
    if (cur - buffer > 128)
    {
        __builtin_trap();
    }
#endif
}

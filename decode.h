
#ifndef ARMX86_DECODE_H
#define ARMX86_DECODE_H

#include <stddef.h>
#include <stdint.h>

#ifndef ssize_t
#define ssize_t intptr_t
#endif

#define DECODE_TABLE_MNEMONICS
#define MNEMONIC(name,value) IT_ ## name = value,
enum
{
#include <decode-table.inc>
};
#undef DECODE_TABLE_MNEMONICS
#undef MNEMONIC

enum DecodeMode {
    DECODE_64 = 0,
    DECODE_32 = 1,
};

typedef enum DecodeMode DecodeMode;

enum RegIndex {
    RI_AL = 0,
    RI_CL,
    RI_DL,
    RI_BL,
    RI_AH,
    RI_CH,
    RI_DH,
    RI_BH,

    RI_AX = 0,
    RI_CX,
    RI_DX,
    RI_BX,
    RI_SP,
    RI_BP,
    RI_SI,
    RI_DI,
    RI_R8,
    RI_R9,
    RI_R10,
    RI_R11,
    RI_R12,
    RI_R13,
    RI_R14,
    RI_R15,

    // EIP cannot be encoded in Protected/Compatibility Mode
    RI_IP = 0x10,

    RI_ES = 0,
    RI_CS,
    RI_SS,
    RI_DS,
    RI_FS,
    RI_GS,
};

typedef uint8_t Reg;

#define reg_index(reg) (reg)
#define reg_is_none(reg) ((reg) == REG_NONE)
#define REG_NONE (0x3f)

enum PrefixSet
{
    PREFIX_SEG_FS = 1 << 0,
    PREFIX_SEG_GS = 1 << 1,
    PREFIX_SEG_CS = 1 << 12,
    PREFIX_SEG_DS = 1 << 17,
    PREFIX_SEG_ES = 1 << 18,
    PREFIX_OPSZ = 1 << 2,
    PREFIX_ADDRSZ = 1 << 3,
    PREFIX_LOCK = 1 << 4,
    PREFIX_REPNZ = 1 << 5,
    PREFIX_REP = 1 << 6,
    PREFIX_REX = 1 << 7,
    PREFIX_REXB = 1 << 8,
    PREFIX_REXX = 1 << 9,
    PREFIX_REXR = 1 << 10,
    PREFIX_REXW = 1 << 11,
    PREFIX_ESC_NONE = 0 << 13,
    PREFIX_ESC_0F = 1 << 13,
    PREFIX_ESC_0F38 = 2 << 13,
    PREFIX_ESC_0F3A = 3 << 13,
    PREFIX_ESC_MASK = 3 << 13,
    PREFIX_VEX = 1 << 15,
    PREFIX_VEXL = 1 << 16,
};

typedef enum PrefixSet PrefixSet;

enum OperandType
{
    OT_NONE = 0,
    OT_REG = 1,
    OT_IMM = 2,
    OT_MEM = 3,
};

struct Operand
{
    uint8_t type : 2;
    uint8_t reg : 6;
    uint8_t size;
};

struct Instr
{
    uint16_t type;
    struct Operand operands[4];
    uint8_t segment : 3;
    uint8_t width : 5;

    /**
     * Encoded as 1 << (scale - 1)  **or**  no scaled register at all if zero.
     **/
    uint8_t scale : 3;
    uint8_t sreg : 5;

    PrefixSet prefixes;
    size_t immediate;
    intptr_t disp;

    uintptr_t address;
    uint32_t size : 4;
};

typedef struct Instr Instr;

#define INSTR_SEGMENT(instr) ((instr)->segment)
#define INSTR_WIDTH(instr) ((instr)->width)
#define INSTR_HAS_REP(instr) ((instr)->prefixes & PREFIX_REP)
#define INSTR_HAS_REPNZ(instr) ((instr)->prefixes & PREFIX_REPNZ)
#define INSTR_HAS_LOCK(instr) ((instr)->prefixes & PREFIX_LOCK)
#define INSTR_HAS_ADDRSZ(instr) ((instr)->prefixes & PREFIX_ADDRSZ)
#define INSTR_HAS_REX(instr) ((instr)->prefixes & PREFIX_REX)

int decode(const uint8_t* buffer, int len, DecodeMode mode, Instr* out_instr);
void instr_format(const Instr* instr, char buffer[128]);
void instr_print(const Instr* instr) __attribute__((deprecated));

#endif

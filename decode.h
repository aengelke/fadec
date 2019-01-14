
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

    // No register specified
    RI_NONE = 0x3f
};

typedef uint8_t Reg;

#define reg_index(reg) (reg)
#define reg_is_none(reg) ((reg) == REG_NONE)
#define REG_NONE RI_NONE

enum
{
    INSTR_FLAG_LOCK = 1 << 0,
    INSTR_FLAG_REP = 1 << 1,
    INSTR_FLAG_REPNZ = 1 << 2,
    INSTR_FLAG_REX = 1 << 3,
    INSTR_FLAG_VEXL = 1 << 4,
    INSTR_FLAG_64 = 1 << 7,
};

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
    uint8_t flags;
    uint8_t segment;
    uint8_t op_size;
    uint8_t addr_size;

    /**
     * Encoded as 1 << (scale - 1)  **or**  no scaled register at all if zero.
     **/
    uint8_t scale : 3;
    uint8_t sreg : 5;

    size_t immediate;
    intptr_t disp;

    uintptr_t address;
    uint32_t size : 4;
};

typedef struct Instr Instr;

#define INSTR_SEGMENT(instr) ((instr)->segment)
#define INSTR_WIDTH(instr) ((instr)->op_size)
#define INSTR_ADDRSZ(instr) ((instr)->addr_size)
#define INSTR_IS64(instr) ((instr)->flags & INSTR_FLAG_64)
#define INSTR_HAS_REP(instr) ((instr)->flags & INSTR_FLAG_REP)
#define INSTR_HAS_REPNZ(instr) ((instr)->flags & INSTR_FLAG_REPNZ)
#define INSTR_HAS_LOCK(instr) ((instr)->flags & INSTR_FLAG_LOCK)
#define INSTR_HAS_REX(instr) ((instr)->flags & INSTR_FLAG_REX)
#define INSTR_HAS_VEXL(instr) ((instr)->flags & INSTR_FLAG_VEXL)

int decode(const uint8_t* buffer, int len, DecodeMode mode, uintptr_t address,
           Instr* out_instr);
void instr_format(const Instr* instr, char buffer[128]);

#endif

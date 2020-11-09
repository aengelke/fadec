
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <fadec.h>


static
void
print_hex(const uint8_t* buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

static
int
test(const void* buf, size_t buf_len, unsigned mode, const char* exp_fmt)
{
    FdInstr instr;
    char fmt[128];

    int retval = fd_decode(buf, buf_len, mode, 0, &instr);

    if (retval == FD_ERR_INTERNAL) {
        return 0; // not compiled with this arch-mode (32/64 bit)
    } else if (retval == FD_ERR_PARTIAL) {
        strcpy(fmt, "PARTIAL");
    } else if (retval == FD_ERR_UD) {
        strcpy(fmt, "UD");
    } else {
        fd_format(&instr, fmt, sizeof(fmt));
    }

    if ((retval < 0 || (unsigned) retval == buf_len) && !strcmp(fmt, exp_fmt))
        return 0;

    printf("Failed case (%u-bit): ", mode);
    print_hex(buf, buf_len);
    printf("\n  Exp (%2zu): %s", buf_len, exp_fmt);
    printf("\n  Got (%2d): %s\n", retval, fmt);
    return -1;
}

#define TEST1(mode, buf, exp_fmt) test(buf, sizeof(buf)-1, mode, exp_fmt)
#define TEST32(...) failed |= TEST1(32, __VA_ARGS__)
#define TEST64(...) failed |= TEST1(64, __VA_ARGS__)
#define TEST(...) failed |= TEST1(32, __VA_ARGS__) | TEST1(64, __VA_ARGS__)

int
main(int argc, char** argv)
{
    (void) argc; (void) argv;

    int failed = 0;

    TEST("\x90", "[NOP]");
    TEST("\x90", "[NOP]");
    TEST("\x2e\x90", "[cs:NOP]");
    TEST("\x2e\x2e\x90", "[cs:NOP]");
    TEST("\x2e\x26\x90", "[es:NOP]");
    TEST("\x26\x2e\x90", "[cs:NOP]");
    TEST("\x26\x65\x90", "[gs:NOP]");
    TEST("\x65\x26\x90", "[es:NOP]");
    TEST("\x0f\x10\xc1", "[SSE_MOVUPS reg16:r0 reg16:r1]");
    TEST("\x66\x0f\x10\xc1", "[SSE_MOVUPD reg16:r0 reg16:r1]");
    TEST("\xf2\x66\x0f\x10\xc1", "[SSE_MOVSD reg16:r0 reg8:r1]");
    TEST("\xf3\x66\x0f\x10\xc1", "[SSE_MOVSS reg16:r0 reg4:r1]");
    TEST("\xf3\xf2\x66\x0f\x10\xc1", "[SSE_MOVSD reg16:r0 reg8:r1]");
    TEST("\xf2\x66\xf3\x66\x0f\x10\xc1", "[SSE_MOVSS reg16:r0 reg4:r1]");
    TEST64("\x48\x90", "[NOP]");
    TEST64("\x49\x90", "[XCHG reg8:r8 reg8:r0]");
    TEST64("\x48\x91", "[XCHG reg8:r1 reg8:r0]");
    TEST64("\x48\x26\x91", "[es:XCHG reg4:r1 reg4:r0]");
    TEST64("\x66\x90", "[NOP]");
    TEST("\x66", "PARTIAL");
    TEST("\x0f", "PARTIAL");
    TEST("\x0f\x38", "PARTIAL");
    TEST("\x0f\x3a", "PARTIAL");
    TEST("\x80", "PARTIAL");
    TEST("\x0F\x01\x22", "[SMSW mem2:r2]");
    TEST64("\x48\x0F\x01\x22", "[SMSW mem2:r2]");
    TEST("\x66\x0F\x01\x22", "[SMSW mem2:r2]");
    TEST("\x0F\x01\xE2", "[SMSW reg4:r2]");
    TEST("\x66\x0F\x01\xE2", "[SMSW reg2:r2]");
    TEST64("\x66\x48\x0F\x01\xE2", "[SMSW reg8:r2]");
    TEST64("\x66\x0f\x20\x00", "[MOV_CR reg8:r0 reg0:r0]");
    TEST64("\x0f\x20\xc8", "UD");
    TEST64("\x0f\x20\xd0", "[MOV_CR reg8:r0 reg0:r2]");
    TEST64("\x44\x0f\x20\x08", "UD");
    TEST64("\x44\x0f\x21\x00", "UD");
    TEST("\x8c\xc0", "[MOV_S2G reg2:r0 reg2:r0]");
    TEST64("\x44\x8c\xc0", "[MOV_S2G reg2:r0 reg2:r0]");
    TEST("\x8e\xc0", "[MOV_G2S reg2:r0 reg2:r0]");
    TEST("\x8e\xc8", "UD"); // No mov cs, eax
    TEST("\xd8\xc1", "[FADD reg0:r0 reg0:r1]");
    TEST64("\x41\xd8\xc1", "[FADD reg0:r0 reg0:r1]");
    TEST64("\x41\xdf\xe0", "[FSTSW reg2:r0]");

    // ModRM Test cases
    // reg
    TEST("\x01\xc0", "[ADD reg4:r0 reg4:r0]");
    TEST("\x01\xc1", "[ADD reg4:r1 reg4:r0]");
    TEST("\x01\xd0", "[ADD reg4:r0 reg4:r2]");
    TEST("\x01\xff", "[ADD reg4:r7 reg4:r7]");
    TEST64("\x41\x01\xd0", "[ADD reg4:r8 reg4:r2]");
    TEST64("\x45\x01\xd0", "[ADD reg4:r8 reg4:r10]");
    TEST64("\x45\x01\xff", "[ADD reg4:r15 reg4:r15]");
    // [reg]
    TEST("\x01\x00", "[ADD mem4:r0 reg4:r0]");
    TEST("\x01\x08", "[ADD mem4:r0 reg4:r1]");
    TEST("\x01\x01", "[ADD mem4:r1 reg4:r0]");
    TEST("\x01\x07", "[ADD mem4:r7 reg4:r0]");
    TEST("\x01\x38", "[ADD mem4:r0 reg4:r7]");
    TEST("\x01\x04\x24", "[ADD mem4:r4 reg4:r0]");
    TEST64("\x41\x01\x00", "[ADD mem4:r8 reg4:r0]");
    TEST64("\x44\x01\x08", "[ADD mem4:r0 reg4:r9]");
    TEST64("\x45\x01\x00", "[ADD mem4:r8 reg4:r8]");
    TEST64("\x41\x01\x07", "[ADD mem4:r15 reg4:r0]");
    TEST64("\x41\x01\x04\x24", "[ADD mem4:r12 reg4:r0]");
    // [disp32]
    TEST32("\x01\x05\x01\x00\x00\x00", "[ADD mem4:0x1 reg4:r0]");
    TEST32("\x01\x05\xff\xff\xff\xff", "[ADD mem4:-0x1 reg4:r0]");
    TEST("\x01\x04\x25\x01\x00\x00\x00", "[ADD mem4:0x1 reg4:r0]");
    TEST64("\x41\x01\x04\x25\x01\x00\x00\x00", "[ADD mem4:0x1 reg4:r0]");
    // [rip+disp32]
    TEST64("\x01\x05\x01\x00\x00\x00", "[ADD mem4:r16+0x1 reg4:r0]");
    TEST64("\x41\x01\x05\x01\x00\x00\x00", "[ADD mem4:r16+0x1 reg4:r0]");
    // [reg+disp32]
    TEST("\x01\x80\x01\x00\x00\x00", "[ADD mem4:r0+0x1 reg4:r0]");
    // [reg+eiz+disp32]
    TEST("\x01\x84\x25\x01\x00\x00\x00", "[ADD mem4:r5+0x1 reg4:r0]");
    // [reg+s*reg+disp32]
    TEST64("\x42\x01\x84\x25\x01\x00\x00\x00", "[ADD mem4:r5+1*r12+0x1 reg4:r0]");

    TEST("\x04\x01", "[ADD reg1:r0 imm1:0x1]");
    TEST("\x66\x68\xff\xad", "[PUSH imm2:0xadff]");
    TEST32("\x68\xff\xad\x90\xbc", "[PUSH imm4:0xbc90adff]");
    TEST64("\x68\xff\xad\x90\xbc", "[PUSH imm8:0xffffffffbc90adff]");
    TEST("\x66\x6a\xff", "[PUSH imm2:0xffff]");
    TEST32("\x6a\xff", "[PUSH imm4:0xffffffff]");
    TEST64("\x6a\xff", "[PUSH imm8:0xffffffffffffffff]");
    TEST("\xb0\xf0", "[MOVABS reg1:r0 imm1:0xf0]");
    TEST("\xb8\xf0\xf0\xab\xff", "[MOVABS reg4:r0 imm4:0xffabf0f0]");
    TEST64("\x48\xb8\xf0\xf0\xab\xff\x00\x12\x12\xcd", "[MOVABS reg8:r0 imm8:0xcd121200ffabf0f0]");
    TEST64("\xcd\x80", "[INT imm1:0x80]");

    TEST("\x66\xc8\x00\x00\x00", "[ENTER_2 imm4:0x0]");
    TEST("\x66\xc8\x00\x0f\x00", "[ENTER_2 imm4:0xf00]");
    TEST("\x66\xc8\x00\x00\x01", "[ENTER_2 imm4:0x10000]");
    TEST32("\xc8\x00\x00\x00", "[ENTER_4 imm4:0x0]");
    TEST32("\xc8\x00\x0f\x00", "[ENTER_4 imm4:0xf00]");
    TEST32("\xc8\x00\x00\x01", "[ENTER_4 imm4:0x10000]");
    TEST64("\xc8\x00\x00\x00", "[ENTER_8 imm4:0x0]");
    TEST64("\xc8\x00\x0f\x00", "[ENTER_8 imm4:0xf00]");
    TEST64("\xc8\x00\x00\x01", "[ENTER_8 imm4:0x10000]");

    TEST64("\xd3\xe0", "[SHL reg4:r0 reg1:r1]");
    TEST64("\x0f\xa5\xd0", "[SHLD reg4:r0 reg4:r2 reg1:r1]");

    TEST("\x69\xC7\x08\x01\x00\x00", "[IMUL reg4:r0 reg4:r7 imm4:0x108]");
    TEST("\x6B\xC7\x08", "[IMUL reg4:r0 reg4:r7 imm4:0x8]");

    TEST("\x0f\x38\xf0\xd1", "UD"); // MOVBE doesn't allow register moves
    TEST("\x0f\x38\xf0\x11", "[MOVBE reg4:r2 mem4:r1]");
    TEST("\x66\x0f\x38\xf0\x11", "[MOVBE reg2:r2 mem2:r1]");
    TEST64("\x48\x0f\x38\xf0\x01", "[MOVBE reg8:r0 mem8:r1]");
    TEST("\xf2\x0f\x38\xf0\xd1", "[CRC32 reg4:r2 reg1:r1]");
    TEST("\xf2\x66\x0f\x38\xf1\xd1", "[CRC32 reg4:r2 reg2:r1]");
    TEST("\xf2\x0f\x38\xf1\xd1", "[CRC32 reg4:r2 reg4:r1]");
    TEST64("\xf2\x48\x0f\x38\xf1\xd1", "[CRC32 reg4:r2 reg8:r1]");
    TEST64("\xf2\x4c\x0f\x38\xf1\xd1", "[CRC32 reg4:r10 reg8:r1]");

    TEST32("\x40", "[INC reg4:r0]");
    TEST32("\x43", "[INC reg4:r3]");
    TEST32("\x66\x47", "[INC reg2:r7]");
    TEST("\xfe\xc0", "[INC reg1:r0]");
    TEST("\xfe\xc4", "[INC reg1:r0h]");
    TEST("\xff\xc0", "[INC reg4:r0]");
    TEST("\xff\xc4", "[INC reg4:r4]");
    TEST("\xff\x00", "[INC mem4:r0]");
    TEST("\xf0\xff\x00", "[lock:INC mem4:r0]");
    TEST("\x66\xff\xc0", "[INC reg2:r0]");
    TEST("\x66\xff\xc4", "[INC reg2:r4]");
    TEST64("\x48\xff\xc0", "[INC reg8:r0]");
    TEST64("\x48\xff\xc4", "[INC reg8:r4]");
    TEST64("\x49\xff\xc7", "[INC reg8:r15]");

    TEST32("\xe9\x00\x00\x00\x00", "[JMP off4:eip+0x0]");
    TEST32("\x66\xe9\x01\x00", "[JMP off2:ip+0x1]");
    TEST64("\xe9\x00\x00\x00\x00", "[JMP off8:rip+0x0]");
    TEST64("\x66\xe9\x00\x00\x00\x00", "[JMP off8:rip+0x0]");
    TEST("\x66\xe9\x00", "PARTIAL");
    TEST("\x66\xe9", "PARTIAL");

    TEST("\x66\x0f\xbe\xc2", "[MOVSX reg2:r0 reg1:r2]");
    TEST("\x0f\xbe\xc2", "[MOVSX reg4:r0 reg1:r2]");
    TEST("\x0f\xbf\xc2", "[MOVSX reg4:r0 reg2:r2]");
    TEST64("\x48\x0f\xbf\xc2", "[MOVSX reg8:r0 reg2:r2]");
    TEST64("\x48\x63\xc2", "[MOVSX reg8:r0 reg4:r2]");

    TEST("\x66\xc3", "[RET_2]");
    TEST("\x66\xc2\x00\x00", "[RET_2 imm2:0x0]");
    TEST("\x66\xc2\x0d\x00", "[RET_2 imm2:0xd]");
    TEST("\x66\xc2\x0d\xff", "[RET_2 imm2:0xff0d]");
    TEST32("\xc3", "[RET_4]");
    TEST32("\xc2\x00\x00", "[RET_4 imm2:0x0]");
    TEST32("\xc2\x0d\x00", "[RET_4 imm2:0xd]");
    TEST32("\xc2\x0d\xff", "[RET_4 imm2:0xff0d]");
    TEST64("\xc3", "[RET_8]");
    TEST64("\xc2\x00\x00", "[RET_8 imm2:0x0]");
    TEST64("\xc2\x0d\x00", "[RET_8 imm2:0xd]");
    TEST64("\xc2\x0d\xff", "[RET_8 imm2:0xff0d]");

    // NFx/66+F2/F3 combinations
    TEST("\x0f\xc7\xf0", "[RDRAND reg4:r0]");
    TEST64("\x48\x0f\xc7\xf0", "[RDRAND reg8:r0]");
    TEST("\x66\x0f\xc7\xf0", "[RDRAND reg2:r0]");
    TEST64("\x66\x48\x0f\xc7\xf0", "[RDRAND reg8:r0]");
    TEST("\x0f\xc7\xf8", "[RDSEED reg4:r0]");
    TEST64("\x48\x0f\xc7\xf8", "[RDSEED reg8:r0]");
    TEST("\x66\x0f\xc7\xf8", "[RDSEED reg2:r0]");
    TEST64("\x66\x48\x0f\xc7\xf8", "[RDSEED reg8:r0]");
    TEST32("\xf3\x0f\xc7\xf8", "[RDPID reg4:r0]");
    TEST32("\x66\xf3\x0f\xc7\xf8", "[RDPID reg4:r0]");
    TEST32("\xf3\x66\x0f\xc7\xf8", "[RDPID reg4:r0]");
    TEST64("\xf3\x0f\xc7\xf8", "[RDPID reg8:r0]");
    TEST64("\x66\xf3\x0f\xc7\xf8", "[RDPID reg8:r0]");
    TEST64("\xf3\x66\x0f\xc7\xf8", "[RDPID reg8:r0]");
    TEST64("\xf3\x0f\xc7\x00", "UD");
    TEST64("\x0f\xc7\x30", "[VMPTRLD mem0:r0]");
    TEST64("\x66\x0f\xc7\x30", "[VMCLEAR mem0:r0]");
    TEST64("\xf3\x0f\xc7\x30", "[VMXON mem0:r0]");

    TEST64("\x0f\x09", "[WBINVD]");
    TEST64("\xf3\x0f\x09", "[WBNOINVD]");

    TEST("\xf3\x0f\x2a\xc1", "[SSE_CVTSI2SS reg4:r0 reg4:r1]");
    TEST("\xf3\x66\x0f\x2a\xc1", "[SSE_CVTSI2SS reg4:r0 reg4:r1]");
    TEST("\x66\xf3\x0f\x2a\xc1", "[SSE_CVTSI2SS reg4:r0 reg4:r1]");
    TEST64("\xf3\x48\x0f\x2a\xc1", "[SSE_CVTSI2SS reg4:r0 reg8:r1]");
    TEST64("\x66\xf3\x48\x0f\x2a\xc1", "[SSE_CVTSI2SS reg4:r0 reg8:r1]");
    TEST64("\x66\x0f\x50\xc1", "[SSE_MOVMSKPD reg8:r0 reg16:r1]");
    TEST("\x66\x0f\xc6\xc0\x01", "[SSE_SHUFPD reg16:r0 reg16:r0 imm1:0x1]");

    TEST("\xf3\x0f\x7e\x5c\x24\x08", "[SSE_MOVQ reg16:r3 mem8:r4+0x8]");
    TEST32("\xc4\xe1\x00\x58\xc1", "[VADDPS reg16:r0 reg16:r7 reg16:r1]"); // MSB in vvvv ignored
    TEST64("\xc4\xe1\x00\x58\xc1", "[VADDPS reg16:r0 reg16:r15 reg16:r1]");
    TEST32("\xc4\xc1\x78\x58\xc0", "[VADDPS reg16:r0 reg16:r0 reg16:r0]"); // VEX.B ignored in 32-bit
    TEST64("\xc4\xc1\x78\x58\xc0", "[VADDPS reg16:r0 reg16:r0 reg16:r8]");
    TEST("\xc5\xf9\x6e\xc8", "[VMOVD reg4:r1 reg4:r0]");
    TEST64("\xc4\xe1\xf9\x6e\xc8", "[VMOVQ reg8:r1 reg8:r0]");
    TEST32("\xc4\xe1\xf9\x6e\xc8", "[VMOVD reg4:r1 reg4:r0]");
    TEST("\xc5\xf2\x2a\xc0", "[VCVTSI2SS reg16:r0 reg16:r1 reg4:r0]");
    TEST32("\xc4\xe1\xf2\x2a\xc0", "[VCVTSI2SS reg16:r0 reg16:r1 reg4:r0]");
    TEST64("\xc4\xe1\xf2\x2a\xc0", "[VCVTSI2SS reg16:r0 reg16:r1 reg8:r0]");
    TEST64("\xc4\xe2\x75\x90\x04\xe7", "[VPGATHERDD reg32:r0 mem32:r7+8*r4 reg32:r1]");

    TEST("\xc4\xe3\x79\x14\xc0\x00", "[VPEXTRB reg1:r0 reg16:r0 imm1:0x0]");
    TEST("\xc4\xe3\xf9\x14\xc0\x00", "[VPEXTRB reg1:r0 reg16:r0 imm1:0x0]");
    TEST("\xc4\xe3\x79\x15\xc0\x00", "[VPEXTRW reg2:r0 reg16:r0 imm1:0x0]");
    TEST("\xc4\xe3\xf9\x15\xc0\x00", "[VPEXTRW reg2:r0 reg16:r0 imm1:0x0]");
    TEST32("\xc4\xe1\x79\xc5\xc0\x00", "[VPEXTRW reg4:r0 reg16:r0 imm1:0x0]");
    TEST64("\xc4\xe1\x79\xc5\xc0\x00", "[VPEXTRW reg8:r0 reg16:r0 imm1:0x0]");
    TEST("\xc4\xe3\x79\x16\xc0\x00", "[VPEXTRD reg4:r0 reg16:r0 imm1:0x0]");
    TEST32("\xc4\xe3\xf9\x16\xc0\x00", "[VPEXTRD reg4:r0 reg16:r0 imm1:0x0]");
    TEST64("\xc4\xe3\xf9\x16\xc0\x00", "[VPEXTRQ reg8:r0 reg16:r0 imm1:0x0]");

    TEST("\xc4\xe3\x71\x20\xc0\x00", "[VPINSRB reg16:r0 reg16:r1 reg1:r0 imm1:0x0]");
    TEST("\xc4\xe3\xf1\x20\xc0\x00", "[VPINSRB reg16:r0 reg16:r1 reg1:r0 imm1:0x0]");
    TEST("\xc4\xe1\x71\xc4\xc0\x00", "[VPINSRW reg16:r0 reg16:r1 reg2:r0 imm1:0x0]");
    TEST("\xc4\xe1\xf1\xc4\xc0\x00", "[VPINSRW reg16:r0 reg16:r1 reg2:r0 imm1:0x0]");
    TEST("\xc4\xe3\x71\x22\xc0\x00", "[VPINSRD reg16:r0 reg16:r1 reg4:r0 imm1:0x0]");
    TEST32("\xc4\xe3\xf1\x22\xc0\x00", "[VPINSRD reg16:r0 reg16:r1 reg4:r0 imm1:0x0]");
    TEST64("\xc4\xe3\xf1\x22\xc0\x00", "[VPINSRQ reg16:r0 reg16:r1 reg8:r0 imm1:0x0]");
    TEST("\xc4\xe3\x75\x20\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe1\x75\xc4\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe1\xf5\xc4\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe3\x75\x22\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe3\xf5\x22\xc0\x00", "UD"); // VEX.L != 0

    TEST("\xc4\xe2\x71\x45\xc2", "[VPSRLVD reg16:r0 reg16:r1 reg16:r2]");
    TEST("\xc4\xe2\x75\x45\xc2", "[VPSRLVD reg32:r0 reg32:r1 reg32:r2]");
    TEST("\xc4\xe2\xf1\x45\xc2", "[VPSRLVQ reg16:r0 reg16:r1 reg16:r2]");
    TEST("\xc4\xe2\xf5\x45\xc2", "[VPSRLVQ reg32:r0 reg32:r1 reg32:r2]");

    TEST("\xc4\xe2\x7d\x5a\x20", "[VBROADCASTI128 reg32:r4 mem16:r0]");
    TEST64("\xc4\x62\x7d\x5a\x20", "[VBROADCASTI128 reg32:r12 mem16:r0]");
    TEST("\xc4\xe2\x75\x5a\x20", "UD"); // VEX.vvvv != 1111
    TEST("\xc4\xe2\x7d\x5a\xc0", "UD"); // ModRM.mod != 11
    TEST("\xc4\xe2\x79\x5a\x20", "UD"); // VEX.L != 1
    TEST("\xc4\xe2\xfd\x5a\x20", "UD"); // VEX.W != 0

    puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

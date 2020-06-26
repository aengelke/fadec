
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include <fadec-enc.h>


static
void
print_hex(const uint8_t* buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

static
int
test(uint8_t* buf, const char* name, uint64_t mnem, uint64_t op0, uint64_t op1, uint64_t op2, uint64_t op3, const void* exp, size_t exp_len)
{
    memset(buf, 0, 16);

    uint8_t* inst = buf;
    int res = fe_enc64(&inst, mnem, op0, op1, op2, op3);
    if ((res != 0) != (exp_len == 0)) goto fail;
    if (inst - buf != (ptrdiff_t) exp_len) goto fail;
    if (memcmp(buf, exp, exp_len)) goto fail;

    return 0;

fail:
    printf("Failed case %s:\n", name);
    printf("  Exp (%2zu): ", exp_len);
    print_hex(exp, exp_len);
    printf("\n  Got (%2zd): ", inst - buf);
    print_hex(buf, inst - buf);
    printf("\n");
    return -1;
}

#define TEST2(str, exp, exp_len, mnem, op0, op1, op2, op3, ...) test(buf, str, mnem, op0, op1, op2, op3, exp, exp_len)
#define TEST1(str, exp, ...) TEST2(str, exp, sizeof(exp)-1, __VA_ARGS__, 0, 0, 0, 0, 0)
#define TEST(exp, ...) failed |= TEST1(#__VA_ARGS__, exp, __VA_ARGS__)

int
main(int argc, char** argv)
{
    (void) argc; (void) argv;

    int failed = 0;
    uint8_t buf[16];

    TEST("\00\xe0", FE_ADD8rr, FE_AX, FE_AH);
    TEST("", FE_ADD8rr, FE_SI, FE_AH);
    TEST("\xe9\xfb\xff\xff\xff", FE_JMP, (intptr_t) buf);
    TEST("\xe9\x00\x00\x00\x00", FE_JMP, FE_JMP_RESERVE);
    TEST("\x0f\x85\x00\x00\x00\x00", FE_JNZ, (intptr_t) buf + 6);
    TEST("\xac", FE_LODS8);
    TEST("\x67\xac", FE_LODS8|FE_ADDR32);
    TEST("\x50", FE_PUSHr, FE_AX);
    TEST("\x66\x50", FE_PUSH16r, FE_AX);
    TEST("\x54", FE_PUSHr, FE_SP);
    TEST("\x41\x57", FE_PUSHr, FE_R15);
    TEST("\x41\x50", FE_PUSHr, FE_R8);
    TEST("\xd2\xe4", FE_SHL8rr, FE_AH, FE_CX);
    TEST("", FE_SHL8rr, FE_AH, FE_DX);
    TEST("\x48\xf7\x28", FE_IMUL64m, FE_MEM(FE_AX, 0, 0, 0));
    // TEST("\x66\x90", FE_XCHG16rr, FE_AX, FE_AX);
    TEST("\xc2\x00\x00", FE_RETi, 0);
    TEST("\x05\x00\x01\x00\x00", FE_ADD32ri, FE_AX, 0x100);
    TEST("\x66\x05\x00\x01", FE_ADD16ri, FE_AX, 0x100);
    TEST("\xb8\x05\x00\x01\x00", FE_MOV32ri, FE_AX, 0x10005);
    TEST("\x48\xb8\x05\x00\x01\x00\xff\x00\x00\x00", FE_MOV64ri, FE_AX, 0xff00010005);
    TEST("\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00", FE_MOV64ri, FE_AX, 0x0);
    TEST("\xc8\x33\x22\x11", FE_ENTERi, 0x112233);

    // Test ModRM encoding
    TEST("\x01\x00", FE_ADD32mr, FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x01\x04\x24", FE_ADD32mr, FE_MEM(FE_SP, 0, 0, 0), FE_AX);
    TEST("\x01\x45\x00", FE_ADD32mr, FE_MEM(FE_BP, 0, 0, 0), FE_AX);
    TEST("\x41\x01\x45\x00", FE_ADD32mr, FE_MEM(FE_R13, 0, 0, 0), FE_AX);
    TEST("\x41\x01\x45\x80", FE_ADD32mr, FE_MEM(FE_R13, 0, 0, -0x80), FE_AX);
    TEST("\x41\x01\x85\x80\x00\x00\x00", FE_ADD32mr, FE_MEM(FE_R13, 0, 0, 0x80), FE_AX);
    TEST("\x01\x04\x25\x01\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 0, 0, 0x1), FE_AX);
    TEST("\x01\x05\x01\x00\x00\x00", FE_ADD32mr, FE_MEM(FE_IP, 0, 0, 0x1), FE_AX);
    TEST("\x01\x04\x25\x00\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 0, 0, 0), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(0, 0, FE_AX, 0), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(0, 3, FE_AX, 0), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(0, 5, FE_AX, 0), FE_AX);
    TEST("\x01\x04\x05\x00\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 1, FE_AX, 0), FE_AX);
    TEST("\x01\x04\xc5\x00\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 8, FE_AX, 0), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(0, 8, FE_SP, 0), FE_AX);
    TEST("\x42\x01\x04\x05\x00\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 1, FE_R8, 0), FE_AX);

    puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

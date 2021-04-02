
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
    TEST("\xeb\xfe", FE_JMP, (intptr_t) buf);
    TEST("\xeb\x7f", FE_JMP, (intptr_t) buf + 129);
    TEST("\xe9\xfb\xff\xff\xff", FE_JMP|FE_JMPL, (intptr_t) buf);
    TEST("\xe9\x00\x00\x00\x00", FE_JMP|FE_JMPL, (intptr_t) buf + 5);
    TEST("\x75\x00", FE_JNZ, (intptr_t) buf + 2);
    TEST("\x0f\x85\x00\x00\x00\x00", FE_JNZ|FE_JMPL, (intptr_t) buf + 6);
    TEST("\xe3\xfc", FE_JCXZ, (intptr_t) buf - 2);
    TEST("\x67\xe3\xfb", FE_JCXZ|FE_ADDR32, (intptr_t) buf - 2);
    TEST("\xe3\xfc", FE_JCXZ|FE_JMPL, (intptr_t) buf - 2);
    TEST("\xac", FE_LODS8);
    TEST("\x67\xac", FE_LODS8|FE_ADDR32);
    TEST("\x50", FE_PUSHr, FE_AX);
    TEST("\x66\x50", FE_PUSH16r, FE_AX);
    TEST("\x54", FE_PUSHr, FE_SP);
    TEST("\x41\x57", FE_PUSHr, FE_R15);
    TEST("\x41\x50", FE_PUSHr, FE_R8);
    TEST("", FE_PUSHr, FE_ES);
    TEST("", FE_PUSH16r, FE_ES);
    TEST("", FE_PUSHr, FE_CS);
    TEST("", FE_PUSH16r, FE_CS);
    TEST("", FE_PUSHr, FE_SS);
    TEST("", FE_PUSH16r, FE_SS);
    TEST("", FE_PUSHr, FE_DS);
    TEST("", FE_PUSH16r, FE_DS);
    TEST("\x0f\xa0", FE_PUSHr, FE_FS);
    TEST("\x66\x0f\xa0", FE_PUSH16r, FE_FS);
    TEST("\x0f\xa8", FE_PUSHr, FE_GS);
    TEST("\x66\x0f\xa8", FE_PUSH16r, FE_GS);
    TEST("\xff\x30", FE_PUSHm, FE_MEM(FE_AX, 0, 0, 0));
    TEST("\xff\x31", FE_PUSHm, FE_MEM(FE_CX, 0, 0, 0));
    TEST("\x9c", FE_PUSHF);
    TEST("\xd2\xe4", FE_SHL8rr, FE_AH, FE_CX);
    TEST("", FE_SHL8rr, FE_AH, FE_DX);
    TEST("\xd0\xe0", FE_SHL8ri, FE_AX, 1);
    TEST("\xc0\xe0\x02", FE_SHL8ri, FE_AX, 2);
    TEST("\xc1\xe0\x02", FE_SHL32ri, FE_AX, 2);
    TEST("\x48\xc1\xe0\x02", FE_SHL64ri, FE_AX, 2);
    TEST("\x48\xf7\x28", FE_IMUL64m, FE_MEM(FE_AX, 0, 0, 0));
    TEST("\xc2\x00\x00", FE_RETi, 0);
    TEST("\xff\xd0", FE_CALLr, FE_AX);
    TEST("\x05\x00\x01\x00\x00", FE_ADD32ri, FE_AX, 0x100);
    TEST("\x66\x05\x00\x01", FE_ADD16ri, FE_AX, 0x100);
    TEST("\xb8\x05\x00\x01\x00", FE_MOV32ri, FE_AX, 0x10005);
    TEST("\x48\xb8\x05\x00\x01\x00\xff\x00\x00\x00", FE_MOV64ri, FE_AX, 0xff00010005);
    TEST("\x48\xc7\xc0\x00\x00\x00\x00", FE_MOV64ri, FE_AX, 0x0);
    TEST("\x48\xc7\xc0\x00\x00\x00\x80", FE_MOV64ri, FE_AX, (int32_t) 0x80000000);
    TEST("\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x80", FE_MOV64ri, FE_AX, INT64_MIN);
    TEST("\x48\xb8\x00\x00\x00\x80\x00\x00\x00\x00", FE_MOV64ri, FE_AX, 0x80000000);
    TEST("\xb0\xff", FE_MOV8ri, FE_AX, (int8_t) 0xff);
    TEST("\xb4\xff", FE_MOV8ri, FE_AH, -1);
    TEST("\xb7\x64", FE_MOV8ri, FE_BH, 0x64);
    TEST("\x66\x0f\xbe\xc2", FE_MOVSXr16r8, FE_AX, FE_DX);
    TEST("\x0f\xbe\xc2", FE_MOVSXr32r8, FE_AX, FE_DX);
    TEST("\x48\x0f\xbe\xc2", FE_MOVSXr64r8, FE_AX, FE_DX);
    TEST("\x66\x0f\xbe\xc6", FE_MOVSXr16r8, FE_AX, FE_DH);
    TEST("\x0f\xbe\xc6", FE_MOVSXr32r8, FE_AX, FE_DH);
    TEST("", FE_MOVSXr64r8, FE_AX, FE_DH);
    TEST("\x66\x0f\xbf\xc2", FE_MOVSXr16r16, FE_AX, FE_DX);
    TEST("\x0f\xbf\xc2", FE_MOVSXr32r16, FE_AX, FE_DX);
    TEST("\x48\x0f\xbf\xc2", FE_MOVSXr64r16, FE_AX, FE_DX);
    TEST("\x66\x63\xc2", FE_MOVSXr16r32, FE_AX, FE_DX);
    TEST("\x63\xc2", FE_MOVSXr32r32, FE_AX, FE_DX);
    TEST("\x48\x63\xc2", FE_MOVSXr64r32, FE_AX, FE_DX);
    TEST("\xc8\x33\x22\x11", FE_ENTERi, 0x112233);
    TEST("\x0f\x05", FE_SYSCALL);
    TEST("\x0f\x90\xc4", FE_SETO8r, FE_AH);
    TEST("\x40\x0f\x90\xc4", FE_SETO8r, FE_SP);
    TEST("\x41\x0f\x90\xc4", FE_SETO8r, FE_R12);
    TEST("\xf3\x0f\xb8\xc2", FE_POPCNT32rr, FE_AX, FE_DX);
    TEST("\x66\xf3\x0f\xb8\xc2", FE_POPCNT16rr, FE_AX, FE_DX);
    TEST("\xf3\x48\x0f\xb8\xc2", FE_POPCNT64rr, FE_AX, FE_DX);
    TEST("\x0f\xbc\xc2", FE_BSF32rr, FE_AX, FE_DX);
    TEST("\x66\x0f\xbc\xc2", FE_BSF16rr, FE_AX, FE_DX);
    TEST("\xf3\x0f\xbc\xc2", FE_TZCNT32rr, FE_AX, FE_DX);
    TEST("\x66\xf3\x0f\xbc\xc2", FE_TZCNT16rr, FE_AX, FE_DX);
    TEST("\x0f\x01\xd0", FE_XGETBV);
    TEST("\x41\x90", FE_XCHG32rr, FE_R8, FE_AX);
    TEST("\x91", FE_XCHG32rr, FE_CX, FE_AX);
    TEST("\x66\x90", FE_XCHG16rr, FE_AX, FE_AX);
    TEST("\x87\xc0", FE_XCHG32rr, FE_AX, FE_AX);
    TEST("\x48\x90", FE_XCHG64rr, FE_AX, FE_AX);
    TEST("\x87\x00", FE_XCHG32mr, FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x87\x08", FE_XCHG32mr, FE_MEM(FE_AX, 0, 0, 0), FE_CX);
    TEST("\x90", FE_NOP);
    TEST("\x0f\x1f\xc0", FE_NOP32r, FE_AX);
    TEST("\x26\x01\x00", FE_ADD32mr|FE_SEG(FE_ES), FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x2e\x01\x00", FE_ADD32mr|FE_SEG(FE_CS), FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x36\x01\x00", FE_ADD32mr|FE_SEG(FE_SS), FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x3e\x01\x00", FE_ADD32mr|FE_SEG(FE_DS), FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x64\x01\x00", FE_ADD32mr|FE_SEG(FE_FS), FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x65\x01\x00", FE_ADD32mr|FE_SEG(FE_GS), FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x8e\xc0", FE_MOV_G2Srr, FE_ES, FE_AX);
    TEST("\xae", FE_SCAS8);
    TEST("\xf2\xae", FE_REPNZ_SCAS8);
    TEST("\xf3\xae", FE_REPZ_SCAS8);
    TEST("\x66\xab", FE_STOS16);
    TEST("\x66\xf3\xab", FE_REP_STOS16);
    TEST("\xab", FE_STOS32);
    TEST("\xf3\xab", FE_REP_STOS32);
    TEST("\x48\xab", FE_STOS64);
    TEST("\xf3\x48\xab", FE_REP_STOS64);
    TEST("\x66\xf2\x0f\x38\xf1\xc1", FE_CRC32_16rr, FE_AX, FE_CX);
    TEST("\x66\x0f\x3a\x14\xc1\x02", FE_SSE_PEXTRBrri, FE_CX, FE_XMM0, 2);
    TEST("", FE_SSE_PEXTRBrri, FE_CH, FE_XMM0, 2);

    // Test FD/TD encodings
    TEST("\xa0\x00\x00\x00\x00\x00\x00\x00\x00", FE_MOV8ra, FE_AX, 0);
    TEST("\x67\xa0\x00\x00\x00\x00", FE_MOV8ra|FE_ADDR32, FE_AX, 0);
    TEST("\x66\xa1\x00\x00\x00\x00\x00\x00\x00\x00", FE_MOV16ra, FE_AX, 0);
    TEST("\x67\x66\xa1\x00\x00\x00\x00", FE_MOV16ra|FE_ADDR32, FE_AX, 0);
    TEST("\x66\xa1\x10\x32\x54\x76\x98\xba\xdc\xfe", FE_MOV16ra, FE_AX, 0xfedcba9876543210);
    TEST("\x67\x66\xa1\x98\xba\xdc\xfe", FE_MOV16ra|FE_ADDR32, FE_AX, 0xfedcba98);
    TEST("\xa1\x10\x32\x54\x76\x98\xba\xdc\xfe", FE_MOV32ra, FE_AX, 0xfedcba9876543210);
    TEST("\x67\xa1\x98\xba\xdc\xfe", FE_MOV32ra|FE_ADDR32, FE_AX, 0xfedcba98);
    TEST("\x48\xa1\x10\x32\x54\x76\x98\xba\xdc\xfe", FE_MOV64ra, FE_AX, 0xfedcba9876543210);
    TEST("\x67\x48\xa1\x98\xba\xdc\xfe", FE_MOV64ra|FE_ADDR32, FE_AX, 0xfedcba98);
    TEST("\xa2\x00\x00\x00\x00\x00\x00\x00\x00", FE_MOV8ar, 0, FE_AX);
    TEST("\x67\xa2\x00\x00\x00\x00", FE_MOV8ar|FE_ADDR32, 0, FE_AX);
    TEST("\x66\xa3\x00\x00\x00\x00\x00\x00\x00\x00", FE_MOV16ar, 0, FE_AX);
    TEST("\x67\x66\xa3\x00\x00\x00\x00", FE_MOV16ar|FE_ADDR32, 0, FE_AX);
    TEST("\x66\xa3\x10\x32\x54\x76\x98\xba\xdc\xfe", FE_MOV16ar, 0xfedcba9876543210, FE_AX);
    TEST("\x67\x66\xa3\x98\xba\xdc\xfe", FE_MOV16ar|FE_ADDR32, 0xfedcba98, FE_AX);
    TEST("\xa3\x10\x32\x54\x76\x98\xba\xdc\xfe", FE_MOV32ar, 0xfedcba9876543210, FE_AX);
    TEST("\x67\xa3\x98\xba\xdc\xfe", FE_MOV32ar|FE_ADDR32, 0xfedcba98, FE_AX);
    TEST("\x48\xa3\x10\x32\x54\x76\x98\xba\xdc\xfe", FE_MOV64ar, 0xfedcba9876543210, FE_AX);
    TEST("\x67\x48\xa3\x98\xba\xdc\xfe", FE_MOV64ar|FE_ADDR32, 0xfedcba98, FE_AX);
    TEST("", FE_MOV8ra, FE_CX, 0);
    TEST("", FE_MOV8ra|FE_ADDR32, FE_CX, 0);
    TEST("", FE_MOV16ra, FE_CX, 0);
    TEST("", FE_MOV16ra|FE_ADDR32, FE_CX, 0);
    TEST("", FE_MOV16ra, FE_CX, 0xfedcba9876543210);
    TEST("", FE_MOV16ra|FE_ADDR32, FE_CX, 0xfedcba98);
    TEST("", FE_MOV32ra, FE_CX, 0xfedcba9876543210);
    TEST("", FE_MOV32ra|FE_ADDR32, FE_CX, 0xfedcba98);
    TEST("", FE_MOV64ra, FE_CX, 0xfedcba9876543210);
    TEST("", FE_MOV64ra|FE_ADDR32, FE_CX, 0xfedcba98);
    TEST("", FE_MOV8ar, 0, FE_CX);
    TEST("", FE_MOV8ar|FE_ADDR32, 0, FE_CX);
    TEST("", FE_MOV16ar, 0, FE_CX);
    TEST("", FE_MOV16ar|FE_ADDR32, 0, FE_CX);
    TEST("", FE_MOV16ar, 0xfedcba9876543210, FE_CX);
    TEST("", FE_MOV16ar|FE_ADDR32, 0xfedcba98, FE_CX);
    TEST("", FE_MOV32ar, 0xfedcba9876543210, FE_CX);
    TEST("", FE_MOV32ar|FE_ADDR32, 0xfedcba98, FE_CX);
    TEST("", FE_MOV64ar, 0xfedcba9876543210, FE_CX);
    TEST("", FE_MOV64ar|FE_ADDR32, 0xfedcba98, FE_CX);

    // Test VEX encoding
    TEST("\xc5\xfc\x77", FE_VZEROALL);
    TEST("\xc5\xf8\x77", FE_VZEROUPPER);
    TEST("\xc5\xf2\x58\xc2", FE_VADDSSrrr, FE_XMM0, FE_XMM1, FE_XMM2);
    TEST("\xc5\xf0\x58\xc2", FE_VADDPS128rrr, FE_XMM0, FE_XMM1, FE_XMM2);
    TEST("\xc5\xf4\x58\xc2", FE_VADDPS256rrr, FE_XMM0, FE_XMM1, FE_XMM2);
    TEST("\xc4\xc1\x74\x58\xc0", FE_VADDPS256rrr, FE_XMM0, FE_XMM1, FE_XMM8);
    TEST("\xc4\x62\x7d\x19\xc2", FE_VBROADCASTSD256rr, FE_XMM8, FE_XMM2);
    TEST("\xc4\x62\x7d\x1a\xc2", FE_VBROADCASTF128_256rr, FE_XMM8, FE_XMM2);
    TEST("\xc4\xe2\x71\x9d\xc2", FE_VFNMADD132SSrrr, FE_XMM0, FE_XMM1, FE_XMM2);
    TEST("\xc4\xe2\xf1\x9d\xc2", FE_VFNMADD132SDrrr, FE_XMM0, FE_XMM1, FE_XMM2);

    // Test RVMR encoding
    TEST("\xc4\xe3\x71\x4a\xc2\x30", FE_VBLENDVPS128rrrr, FE_XMM0, FE_XMM1, FE_XMM2, FE_XMM3);
    TEST("\xc4\xe3\x75\x4a\xc2\x30", FE_VBLENDVPS256rrrr, FE_XMM0, FE_XMM1, FE_XMM2, FE_XMM3);
    TEST("\xc4\xe3\x71\x4a\x05\x00\x00\x00\x00\x20", FE_VBLENDVPS128rrmr, FE_XMM0, FE_XMM1, FE_MEM(FE_IP, 0, 0, 10), FE_XMM2);
    TEST("\xc4\xe3\x75\x4a\x05\x00\x00\x00\x00\x20", FE_VBLENDVPS256rrmr, FE_XMM0, FE_XMM1, FE_MEM(FE_IP, 0, 0, 10), FE_XMM2);

    // VSIB encodings
    TEST("", FE_VGATHERDPS128rmr, FE_XMM0, FE_XMM0, FE_XMM1); // must have memory operand
    TEST("", FE_VGATHERDPS128rmr, FE_XMM0, FE_MEM(FE_DI, 8, 0, 0), FE_XMM1); // must have SIB
    TEST("", FE_VGATHERDPS128rmr, FE_XMM0, FE_MEM(FE_IP, 0, 0, 0), FE_XMM1); // must have SIB
    TEST("\xc4\xe2\x71\x92\x04\xff", FE_VGATHERDPS128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\x71\x92\x04\xe7", FE_VGATHERDPS128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\x75\x92\x04\xff", FE_VGATHERDPS256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\x75\x92\x04\xe7", FE_VGATHERDPS256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\x71\x93\x04\xff", FE_VGATHERQPS128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\x71\x93\x04\xe7", FE_VGATHERQPS128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\x75\x93\x04\xff", FE_VGATHERQPS256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\x75\x93\x04\xe7", FE_VGATHERQPS256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\xf1\x92\x04\xff", FE_VGATHERDPD128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\xf1\x92\x04\xe7", FE_VGATHERDPD128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\xf5\x92\x04\xff", FE_VGATHERDPD256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\xf5\x92\x04\xe7", FE_VGATHERDPD256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\xf1\x93\x04\xff", FE_VGATHERQPD128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\xf1\x93\x04\xe7", FE_VGATHERQPD128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\xf5\x93\x04\xff", FE_VGATHERQPD256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\xf5\x93\x04\xe7", FE_VGATHERQPD256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\x71\x90\x04\xff", FE_VPGATHERDD128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\x71\x90\x04\xe7", FE_VPGATHERDD128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\x75\x90\x04\xff", FE_VPGATHERDD256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\x75\x90\x04\xe7", FE_VPGATHERDD256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\x71\x91\x04\xff", FE_VPGATHERQD128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\x71\x91\x04\xe7", FE_VPGATHERQD128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\x75\x91\x04\xff", FE_VPGATHERQD256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\x75\x91\x04\xe7", FE_VPGATHERQD256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\xf1\x90\x04\xff", FE_VPGATHERDQ128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\xf1\x90\x04\xe7", FE_VPGATHERDQ128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\xf5\x90\x04\xff", FE_VPGATHERDQ256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\xf5\x90\x04\xe7", FE_VPGATHERDQ256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\xf1\x91\x04\xff", FE_VPGATHERQQ128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\xf1\x91\x04\xe7", FE_VPGATHERQQ128rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);
    TEST("\xc4\xe2\xf5\x91\x04\xff", FE_VPGATHERQQ256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM7, 0), FE_XMM1);
    TEST("\xc4\xe2\xf5\x91\x04\xe7", FE_VPGATHERQQ256rmr, FE_XMM0, FE_MEM(FE_DI, 8, FE_XMM4, 0), FE_XMM1);

    // Test ModRM encoding
    TEST("\x01\x00", FE_ADD32mr, FE_MEM(FE_AX, 0, 0, 0), FE_AX);
    TEST("\x01\x04\x24", FE_ADD32mr, FE_MEM(FE_SP, 0, 0, 0), FE_AX);
    TEST("\x01\x45\x00", FE_ADD32mr, FE_MEM(FE_BP, 0, 0, 0), FE_AX);
    TEST("\x41\x01\x45\x00", FE_ADD32mr, FE_MEM(FE_R13, 0, 0, 0), FE_AX);
    TEST("\x41\x01\x45\x80", FE_ADD32mr, FE_MEM(FE_R13, 0, 0, -0x80), FE_AX);
    TEST("\x41\x01\x85\x80\x00\x00\x00", FE_ADD32mr, FE_MEM(FE_R13, 0, 0, 0x80), FE_AX);
    TEST("\x01\x04\x25\x01\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 0, 0, 0x1), FE_AX);
    TEST("\x01\x04\x25\x00\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 0, 0, 0), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(0, 0, FE_AX, 0), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(0, 3, FE_AX, 0), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(0, 5, FE_AX, 0), FE_AX);
    TEST("\x01\x04\x05\x00\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 1, FE_AX, 0), FE_AX);
    TEST("\x01\x04\xc5\x00\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 8, FE_AX, 0), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(0, 8, FE_SP, 0), FE_AX);
    TEST("\x42\x01\x04\x05\x00\x00\x00\x00", FE_ADD32mr, FE_MEM(0, 1, FE_R8, 0), FE_AX);
    // RIP-relative addressing, adds instruction size to offset.
    TEST("\x01\x05\x01\x00\x00\x00", FE_ADD32mr, FE_MEM(FE_IP, 0, 0, 0x7), FE_AX);
    TEST("", FE_ADD32mr, FE_MEM(FE_IP, 1, FE_AX, 0x7), FE_AX);
    TEST("\x0f\xaf\x05\xf9\xff\xff\xff", FE_IMUL32rm, FE_AX, FE_MEM(FE_IP, 0, 0, 0));
    TEST("\x6b\x05\xf9\xff\xff\xff\x02", FE_IMUL32rmi, FE_AX, FE_MEM(FE_IP, 0, 0, 0), 2);
    TEST("\x66\x6b\x05\xf8\xff\xff\xff\x02", FE_IMUL16rmi, FE_AX, FE_MEM(FE_IP, 0, 0, 0), 2);
    TEST("\x69\x05\xf6\xff\xff\xff\x80\x00\x00\x00", FE_IMUL32rmi, FE_AX, FE_MEM(FE_IP, 0, 0, 0), 0x80);
    TEST("\x66\x69\x05\xf7\xff\xff\xff\x80\x00", FE_IMUL16rmi, FE_AX, FE_MEM(FE_IP, 0, 0, 0), 0x80);

    // Test LOCK prefix
    TEST("\xf0\x87\x08", FE_LOCK_XCHG32mr, FE_MEM(FE_AX, 0, 0, 0), FE_CX);
    TEST("\xf0\x0f\xc1\x01", FE_LOCK_XADD32mr, FE_MEM(FE_CX, 0, 0, 0), FE_AX);
    TEST("\x64\x67\xf0\x41\x81\x84\x00\x00\xff\xff\xff\x78\x56\x34\x12", FE_LOCK_ADD32mi|FE_ADDR32|FE_SEG(FE_FS), FE_MEM(FE_R8, 1, FE_AX, -0x100), 0x12345678);

    puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}


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

    TEST("\x90", "nop");
    TEST("\xac", "lodsb");
    TEST32("\x2e\xac", "cs lodsb");
    TEST64("\x2e\xac", "lodsb");
    TEST32("\x2e\x2e\xac", "cs lodsb");
    TEST64("\x2e\x2e\xac", "lodsb");
    TEST32("\x2e\x26\xac", "es lodsb");
    TEST64("\x2e\x26\xac", "lodsb");
    TEST32("\x26\x2e\xac", "cs lodsb");
    TEST64("\x26\x2e\xac", "lodsb");
    TEST32("\x26\x65\xac", "gs lodsb");
    TEST64("\x26\x65\xac", "gs lodsb");
    TEST32("\x65\x26\xac", "es lodsb");
    TEST64("\x65\x26\xac", "gs lodsb");
    TEST("\x0f\x10\xc1", "movups xmm0, xmm1");
    TEST("\x66\x0f\x10\xc1", "movupd xmm0, xmm1");
    TEST("\xf2\x66\x0f\x10\xc1", "movsd xmm0, xmm1");
    TEST("\xf3\x66\x0f\x10\xc1", "movss xmm0, xmm1");
    TEST("\xf3\xf2\x66\x0f\x10\xc1", "movsd xmm0, xmm1");
    TEST("\xf2\x66\xf3\x66\x0f\x10\xc1", "movss xmm0, xmm1");
    TEST64("\x48\x90", "nop");
    TEST64("\x49\x90", "xchg r8, rax");
    TEST64("\x48\x91", "xchg rcx, rax");
    TEST64("\x48\x26\x91", "xchg ecx, eax");
    TEST64("\x66\x90", "nop");
    TEST32("\x0f\xc7\x0f", "cmpxchg8b qword ptr [edi]");
    TEST64("\x0f\xc7\x0f", "cmpxchg8b qword ptr [rdi]");
    TEST64("\x48\x0f\xc7\x0f", "cmpxchg16b xmmword ptr [rdi]");
    TEST("\x66", "PARTIAL");
    TEST("\xf0", "PARTIAL");
    TEST("\x0f", "PARTIAL");
    TEST("\x0f\x38", "PARTIAL");
    TEST("\x0f\x3a", "PARTIAL");
    TEST("\x80", "PARTIAL");
    TEST32("\x0F\x01\x22", "smsw word ptr [edx]");
    TEST64("\x0F\x01\x22", "smsw word ptr [rdx]");
    TEST64("\x48\x0F\x01\x22", "smsw word ptr [rdx]");
    TEST32("\x66\x0F\x01\x22", "smsw word ptr [edx]");
    TEST64("\x66\x0F\x01\x22", "smsw word ptr [rdx]");
    TEST("\x0F\x01\xE2", "smsw edx");
    TEST("\x66\x0F\x01\xE2", "smsw dx");
    TEST64("\x66\x48\x0F\x01\xE2", "smsw rdx");
    TEST32("\x66\x0f\x20\x00", "mov eax, cr0"); // mod=0, 66h
    TEST64("\x66\x0f\x20\x00", "mov rax, cr0"); // mod=0, 66h
    TEST("\x0f\x20\xc8", "UD"); // cr1
    TEST32("\x0f\x20\xd0", "mov eax, cr2"); // cr2
    TEST64("\x0f\x20\xd0", "mov rax, cr2"); // cr2
    TEST64("\x48\x0f\x20\xd0", "mov rax, cr2"); // cr2 + REX.W
    TEST64("\x44\x0f\x20\x08", "UD"); // cr9
    TEST64("\x44\x0f\x21\x00", "UD"); // dr8
    TEST("\x8c\xc0", "mov ax, es");
    TEST64("\x44\x8c\xc0", "mov ax, es");
    TEST64("\x44\x8c\xf0", "UD"); // no segment register 6
    TEST64("\x44\x8c\xf8", "UD"); // no segment register 7
    TEST("\x8e\xc0", "mov es, ax");
    TEST("\x8e\xc8", "UD"); // No mov cs, eax
    TEST("\x0f\x1e\xc0", "nop eax, eax"); // reserved nop
    TEST("\x0f\x1e\x04\x25\x01\x00\x00\x00", "nop dword ptr [0x1], eax"); // reserved nop
    TEST64("\xf3\x4f\x0f\x1e\xfc", "nop r12, r15"); // reserved nop
    TEST("\xd8\xc1", "fadd st(0), st(1)");
    TEST("\xdc\xc1", "fadd st(1), st(0)");
    TEST64("\x41\xd8\xc1", "fadd st(0), st(1)"); // REX.B ignored
    TEST64("\xd9\xc9", "fxch st(1)");
    TEST64("\xd9\xd0", "fnop");
    TEST64("\x41\xdf\xe0", "fstsw ax");

    // ModRM Test cases
    // reg
    TEST("\x01\xc0", "add eax, eax");
    TEST("\x01\xc1", "add ecx, eax");
    TEST("\x01\xd0", "add eax, edx");
    TEST("\x01\xff", "add edi, edi");
    TEST64("\x41\x01\xd0", "add r8d, edx");
    TEST64("\x45\x01\xd0", "add r8d, r10d");
    TEST64("\x45\x01\xff", "add r15d, r15d");
    // [reg]
    TEST32("\x01\x00", "add dword ptr [eax], eax");
    TEST64("\x01\x00", "add dword ptr [rax], eax");
    TEST32("\x01\x08", "add dword ptr [eax], ecx");
    TEST64("\x01\x08", "add dword ptr [rax], ecx");
    TEST32("\x01\x01", "add dword ptr [ecx], eax");
    TEST64("\x01\x01", "add dword ptr [rcx], eax");
    TEST32("\x01\x07", "add dword ptr [edi], eax");
    TEST64("\x01\x07", "add dword ptr [rdi], eax");
    TEST32("\x01\x38", "add dword ptr [eax], edi");
    TEST64("\x01\x38", "add dword ptr [rax], edi");
    TEST32("\x01\x04\x24", "add dword ptr [esp], eax");
    TEST64("\x01\x04\x24", "add dword ptr [rsp], eax");
    TEST64("\x41\x01\x00", "add dword ptr [r8], eax");
    TEST64("\x44\x01\x08", "add dword ptr [rax], r9d");
    TEST64("\x45\x01\x00", "add dword ptr [r8], r8d");
    TEST64("\x41\x01\x07", "add dword ptr [r15], eax");
    TEST64("\x41\x01\x04\x24", "add dword ptr [r12], eax");
    // [disp32]
    TEST32("\x01\x05\x01\x00\x00\x00", "add dword ptr [0x1], eax");
    TEST32("\x01\x05\xff\xff\xff\xff", "add dword ptr [0xffffffff], eax");
    TEST("\x01\x04\x25\x01\x00\x00\x00", "add dword ptr [0x1], eax");
    TEST32("\x01\x04\x25\x00\x00\x00\x80", "add dword ptr [0x80000000], eax");
    TEST64("\x01\x04\x25\x00\x00\x00\x80", "add dword ptr [0xffffffff80000000], eax");
    TEST64("\x41\x01\x04\x25\x01\x00\x00\x00", "add dword ptr [0x1], eax");
    // [rip+disp32]
    TEST64("\x01\x05\x01\x00\x00\x00", "add dword ptr [rip+0x1], eax");
    TEST64("\x41\x01\x05\x01\x00\x00\x00", "add dword ptr [rip+0x1], eax");
    // [reg+disp32]
    TEST32("\x01\x80\x01\x00\x00\x00", "add dword ptr [eax+0x1], eax");
    TEST64("\x01\x80\x01\x00\x00\x00", "add dword ptr [rax+0x1], eax");
    TEST32("\x01\x80\x00\x00\x00\x80", "add dword ptr [eax-0x80000000], eax");
    TEST64("\x01\x80\x00\x00\x00\x80", "add dword ptr [rax-0x80000000], eax");
    // [reg+eiz+disp32]
    TEST32("\x01\x84\x25\x01\x00\x00\x00", "add dword ptr [ebp+0x1], eax");
    TEST64("\x01\x84\x25\x01\x00\x00\x00", "add dword ptr [rbp+0x1], eax");
    // [reg+s*reg+disp32]
    TEST64("\x42\x01\x84\x25\x01\x00\x00\x00", "add dword ptr [rbp+1*r12+0x1], eax");

    TEST("\x0f\xbc\xc0", "bsf eax, eax");
    TEST("\x66\x0f\xbc\xc0", "bsf ax, ax");
    TEST("\xf2\x0f\xbc\xc0", "bsf eax, eax");
    TEST("\x66\xf2\x0f\xbc\xc0", "bsf ax, ax");
    TEST("\xf3\x0f\xbc\xc0", "tzcnt eax, eax");
    TEST("\x66\xf3\x0f\xbc\xc0", "tzcnt ax, ax");
    TEST32("\x0f\x01\x00", "sgdt [eax]");
    TEST64("\x0f\x01\x00", "sgdt [rax]");
    TEST32("\x66\x0f\x01\x00", "sgdt [eax]");
    TEST64("\x66\x0f\x01\x00", "sgdt [rax]");
    TEST32("\xf2\x0f\x01\x00", "sgdt [eax]");
    TEST64("\xf2\x0f\x01\x00", "sgdt [rax]");
    TEST32("\xf3\x0f\x01\x00", "sgdt [eax]");
    TEST64("\xf3\x0f\x01\x00", "sgdt [rax]");
    TEST("\x04\x01", "add al, 0x1");
    TEST("\x66\x68\xff\xad", "pushw 0xadff");
    TEST32("\x68\xff\xad\x90\xbc", "push 0xbc90adff");
    TEST64("\x68\xff\xad\x90\xbc", "push 0xffffffffbc90adff");
    TEST("\x66\x6a\xff", "pushw 0xffff");
    TEST32("\x6a\xff", "push 0xffffffff");
    TEST64("\x6a\xff", "push 0xffffffffffffffff");
    TEST("\xb0\xf0", "mov al, 0xf0");
    TEST("\x66\xb8\xf0\xf0", "mov ax, 0xf0f0");
    TEST("\xb8\xf0\xf0\xab\xff", "mov eax, 0xffabf0f0");
    TEST64("\x48\xb8\xf0\xf0\xab\xff\x00\x12\x12\xcd", "mov rax, 0xcd121200ffabf0f0");
    TEST64("\xcd\x80", "int 0x80");

    TEST("\x66\xc8\x00\x00\x00", "enterw 0x0, 0x0");
    TEST("\x66\xc8\x00\x0f\x00", "enterw 0xf00, 0x0");
    TEST("\x66\xc8\x00\x00\x01", "enterw 0x0, 0x1");
    TEST32("\xc8\x00\x00\x00", "enter 0x0, 0x0");
    TEST32("\xc8\x00\x0f\x00", "enter 0xf00, 0x0");
    TEST32("\xc8\x00\x00\x01", "enter 0x0, 0x1");
    TEST64("\xc8\x00\x00\x00", "enter 0x0, 0x0");
    TEST64("\xc8\x00\x0f\x00", "enter 0xf00, 0x0");
    TEST64("\xc8\x00\x00\x01", "enter 0x0, 0x1");

    TEST64("\xd3\xe0", "shl eax, cl");
    TEST64("\xd0\x3e", "sar byte ptr [rsi], 0x1");
    TEST64("\x0f\xa5\xd0", "shld eax, edx, cl");

    TEST("\x69\xC7\x08\x01\x00\x00", "imul eax, edi, 0x108");
    TEST("\x6B\xC7\x08", "imul eax, edi, 0x8");

    TEST("\x0f\x38\xf0\xd1", "UD"); // MOVBE doesn't allow register moves
    TEST32("\x0f\x38\xf0\x11", "movbe edx, dword ptr [ecx]");
    TEST64("\x0f\x38\xf0\x11", "movbe edx, dword ptr [rcx]");
    TEST32("\x66\x0f\x38\xf0\x11", "movbe dx, word ptr [ecx]");
    TEST64("\x66\x0f\x38\xf0\x11", "movbe dx, word ptr [rcx]");
    TEST64("\x48\x0f\x38\xf0\x01", "movbe rax, qword ptr [rcx]");
    TEST("\xf2\x0f\x38\xf0\xd1", "crc32 edx, cl");
    TEST("\xf2\x66\x0f\x38\xf1\xd1", "crc32 edx, cx");
    TEST("\xf2\x0f\x38\xf1\xd1", "crc32 edx, ecx");
    TEST64("\xf2\x48\x0f\x38\xf1\xd1", "crc32 edx, rcx");
    TEST64("\xf2\x4c\x0f\x38\xf1\xd1", "crc32 r10d, rcx");

    TEST32("\x8d\x00", "lea eax, [eax]");
    TEST64("\x8d\x00", "lea eax, [rax]");
    TEST("\x8d\xc0", "UD");

    TEST32("\x40", "inc eax");
    TEST32("\x43", "inc ebx");
    TEST32("\x66\x47", "inc di");
    TEST("\xfe\xc0", "inc al");
    TEST("\xfe\xc4", "inc ah");
    TEST("\xff\xc0", "inc eax");
    TEST("\xff\xc4", "inc esp");
    TEST32("\xff\x00", "inc dword ptr [eax]");
    TEST64("\xff\x00", "inc dword ptr [rax]");
    TEST32("\xf0\xff\x00", "lock inc dword ptr [eax]");
    TEST64("\xf0\xff\x00", "lock inc dword ptr [rax]");
    TEST("\x66\xff\xc0", "inc ax");
    TEST("\x66\xff\xc4", "inc sp");
    TEST64("\x48\xff\xc0", "inc rax");
    TEST64("\x48\xff\xc4", "inc rsp");
    TEST64("\x49\xff\xc7", "inc r15");

    TEST32("\xe9\x00\x00\x00\x00", "jmp 0x5");
    TEST32("\x66\xe9\x01\x00", "jmpw 0x5");
    TEST64("\xe9\x00\x00\x00\x00", "jmp 0x5");
    TEST64("\x66\xe9\x00\x00\x00\x00", "jmp 0x6");
    TEST64("\x66\xeb\x00", "jmp 0x3");
    TEST64("\x66\xeb\xff", "jmp 0x2");
    TEST("\x66\xe9\x00", "PARTIAL");
    TEST("\x66\xe9", "PARTIAL");
    TEST32("\xc7\xf8\xd3\x9c\xff\xff", "xbegin 0xffff9cd9");
    TEST32("\x66\xc7\xf8\xd3\x9c", "xbegin 0xffff9cd8");
    TEST64("\xc7\xf8\xd3\x9c\xff\xff", "xbegin 0xffffffffffff9cd9");
    TEST64("\x66\xc7\xf8\xd3\x9c", "xbegin 0xffffffffffff9cd8");


    TEST("\xa5", "movsd");
    TEST("\x66\xa5", "movsw");
    TEST("\xf3\xa5", "rep movsd");
    TEST("\xf3\x66\xa5", "rep movsw");

    TEST("\x66\x0f\xbe\xc2", "movsx ax, dl");
    TEST("\x0f\xbe\xc2", "movsx eax, dl");
    TEST("\x0f\xbf\xc2", "movsx eax, dx");
    TEST64("\x48\x0f\xbf\xc2", "movsx rax, dx");
    TEST64("\x48\x63\xc2", "movsx rax, edx");

    TEST32("\x66\xc3", "retw");
    TEST32("\x66\xc2\x00\x00", "retw 0x0");
    TEST32("\x66\xc2\x0d\x00", "retw 0xd");
    TEST32("\x66\xc2\x0d\xff", "retw 0xff0d");
    TEST64("\x66\xc3", "ret");
    TEST64("\x66\xc2\x00\x00", "ret 0x0");
    TEST64("\x66\xc2\x0d\x00", "ret 0xd");
    TEST64("\x66\xc2\x0d\xff", "ret 0xff0d");
    TEST32("\xc3", "ret");
    TEST32("\xc2\x00\x00", "ret 0x0");
    TEST32("\xc2\x0d\x00", "ret 0xd");
    TEST32("\xc2\x0d\xff", "ret 0xff0d");
    TEST64("\xc3", "ret");
    TEST64("\xc2\x00\x00", "ret 0x0");
    TEST64("\xc2\x0d\x00", "ret 0xd");
    TEST64("\xc2\x0d\xff", "ret 0xff0d");

    // NFx/66+F2/F3 combinations
    TEST("\x0f\xc7\xf0", "rdrand eax");
    TEST64("\x48\x0f\xc7\xf0", "rdrand rax");
    TEST("\x66\x0f\xc7\xf0", "rdrand ax");
    TEST64("\x66\x48\x0f\xc7\xf0", "rdrand rax");
    TEST("\x0f\xc7\xf8", "rdseed eax");
    TEST64("\x48\x0f\xc7\xf8", "rdseed rax");
    TEST("\x66\x0f\xc7\xf8", "rdseed ax");
    TEST64("\x66\x48\x0f\xc7\xf8", "rdseed rax");
    TEST32("\xf3\x0f\xc7\xf8", "rdpid eax");
    TEST32("\x66\xf3\x0f\xc7\xf8", "rdpid eax");
    TEST32("\xf3\x66\x0f\xc7\xf8", "rdpid eax");
    TEST64("\xf3\x0f\xc7\xf8", "rdpid rax");
    TEST64("\x66\xf3\x0f\xc7\xf8", "rdpid rax");
    TEST64("\xf3\x66\x0f\xc7\xf8", "rdpid rax");
    TEST64("\xf3\x0f\xc7\x00", "UD");
    TEST64("\x0f\xc7\x30", "vmptrld qword ptr [rax]");
    TEST64("\x66\x0f\xc7\x30", "vmclear qword ptr [rax]");
    TEST64("\xf3\x0f\xc7\x30", "vmxon qword ptr [rax]");

    TEST64("\x0f\x09", "wbinvd");
    TEST64("\xf3\x0f\x09", "wbnoinvd");
    TEST32("\x66\x0f\x38\x82\x01", "invpcid eax, xmmword ptr [ecx]");
    TEST64("\x66\x0f\x38\x82\x01", "invpcid rax, xmmword ptr [rcx]");
    TEST32("\x66\x0f\x38\xf8\x01", "movdir64b eax, zmmword ptr [ecx]");
    TEST64("\x66\x0f\x38\xf8\x01", "movdir64b rax, zmmword ptr [rcx]");
    // TODO: MOVDIR64B first operand has address size.
    // TEST32("\x67\x66\x0f\x38\xf8\x01", "movdir64b ax, zmmword ptr [cx]");
    // TEST64("\x67\x66\x0f\x38\xf8\x01", "movdir64b eax, zmmword ptr [ecx]");

    TEST("\x0f\xae\xe8", "lfence");
    TEST("\x0f\xae\xe9", "lfence");
    TEST("\x0f\xae\xef", "lfence");
    TEST("\x0f\xae\xf0", "mfence");
    TEST("\x0f\xae\xf7", "mfence");
    TEST("\x0f\xae\xf8", "sfence");
    TEST("\x0f\xae\xf9", "sfence");
    TEST("\x0f\xae\xff", "sfence");

    TEST("\x0f\x70\xc0\x85", "pshufw mm0, mm0, 0x85");

    TEST("\xf3\x0f\x2a\xc1", "cvtsi2ss xmm0, ecx");
    TEST("\xf3\x66\x0f\x2a\xc1", "cvtsi2ss xmm0, ecx");
    TEST("\x66\xf3\x0f\x2a\xc1", "cvtsi2ss xmm0, ecx");
    TEST64("\xf3\x48\x0f\x2a\xc1", "cvtsi2ss xmm0, rcx");
    TEST64("\x66\xf3\x48\x0f\x2a\xc1", "cvtsi2ss xmm0, rcx");
    TEST64("\x66\x0f\x50\xc1", "movmskpd rax, xmm1");
    TEST("\x66\x0f\xc6\xc0\x01", "shufpd xmm0, xmm0, 0x1");
    TEST("\x66\x0f\x71\xd0\x01", "psrlw xmm0, 0x1");
    TEST("\x66\x0f\x3a\x20\xc4\x01", "pinsrb xmm0, spl, 0x1");
    TEST("\x66\x0f\x71\x10\x01", "UD");
    TEST("\x66\x0f\x78\xc0\xab\xcd", "extrq xmm0, 0xab, 0xcd");
    TEST("\xf2\x0f\x78\xc1\xab\xcd", "insertq xmm0, xmm1, 0xab, 0xcd");

    TEST32("\xc4\x00", "les eax, fword ptr [eax]");
    TEST32("\xc5\x00", "lds eax, fword ptr [eax]");
    TEST32("\x0f\xb2\x00", "lss eax, fword ptr [eax]");
    TEST64("\x0f\xb2\x00", "lss eax, fword ptr [rax]");
    TEST64("\x48\x0f\xb2\x00", "lss rax, tbyte ptr [rax]");
    TEST("\xc5\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, eax");
    TEST("\xf3\xc5\xf2\x2a\xc0", "UD"); // VEX+REP
    TEST("\xf2\xc5\xf2\x2a\xc0", "UD"); // VEX+REPNZ
    TEST("\xf2\xf3\xc5\xf2\x2a\xc0", "UD"); // VEX+REP+REPNZ
    TEST("\x66\xc5\xf2\x2a\xc0", "UD"); // VEX+66
    TEST("\xf0\xc5\xf2\x2a\xc0", "UD"); // VEX+LOCK
    TEST64("\x40\xc5\xf2\x2a\xc0", "UD"); // VEX+REX
    TEST64("\x40\x26\xc5\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, eax"); // VEX+REX, but REX doesn't precede VEX

    TEST32("\xd9\x00", "fld dword ptr [eax]");
    TEST64("\xd9\x00", "fld dword ptr [rax]");
    TEST32("\xdd\x00", "fld qword ptr [eax]");
    TEST64("\xdd\x00", "fld qword ptr [rax]");
    TEST32("\xdb\x28", "fld tbyte ptr [eax]");
    TEST64("\xdb\x28", "fld tbyte ptr [rax]");
    TEST("\xd9\xc1", "fld st(1)");
    TEST("\xdf\xe9", "fucomip st(0), st(1)");
    TEST64("\x45\xdf\xe9", "fucomip st(0), st(1)"); // REX.RB are ignored.

    TEST32("\xf3\x0f\x7e\x5c\x24\x08", "movq xmm3, qword ptr [esp+0x8]");
    TEST64("\xf3\x0f\x7e\x5c\x24\x08", "movq xmm3, qword ptr [rsp+0x8]");
    TEST32("\xc4\xe1\x00\x58\xc1", "vaddps xmm0, xmm7, xmm1"); // MSB in vvvv ignored
    TEST64("\xc4\xe1\x00\x58\xc1", "vaddps xmm0, xmm15, xmm1");
    TEST32("\xc4\xc1\x78\x58\xc0", "vaddps xmm0, xmm0, xmm0"); // VEX.B ignored in 32-bit
    TEST64("\xc4\xc1\x78\x58\xc0", "vaddps xmm0, xmm0, xmm8");
    TEST("\xc5\xf9\x6e\xc8", "vmovd xmm1, eax");
    TEST64("\xc4\xe1\xf9\x6e\xc8", "vmovq xmm1, rax");
    TEST32("\xc4\xe1\xf9\x6e\xc8", "vmovd xmm1, eax");
    TEST("\xc5\xf2\x10\xc2", "vmovss xmm0, xmm1, xmm2");
    TEST("\xc5\xf6\x10\xc2", "vmovss xmm0, xmm1, xmm2"); // VEX.L=1
    TEST("\xc5\xfa\x11\x04\x25\x34\x12\x00\x00", "vmovss dword ptr [0x1234], xmm0");
    TEST("\xc5\xf2\x11\x04\x25\x34\x12\x00\x00", "UD"); // VEX.vvvv != 0
    TEST("\xc5\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, eax");
    TEST32("\xc4\xe1\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, eax");
    TEST64("\xc4\xe1\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, rax");

    TEST("\xc4\xe3\x79\x14\xc0\x00", "vpextrb eax, xmm0, 0x0");
    TEST("\xc4\xe3\xf9\x14\xc0\x00", "vpextrb eax, xmm0, 0x0");
    TEST("\xc4\xe3\x79\x15\xc0\x00", "vpextrw eax, xmm0, 0x0");
    TEST("\xc4\xe3\xf9\x15\xc0\x00", "vpextrw eax, xmm0, 0x0");
    TEST32("\xc4\xe1\x79\xc5\xc0\x00", "vpextrw eax, xmm0, 0x0");
    TEST64("\xc4\xe1\x79\xc5\xc0\x00", "vpextrw rax, xmm0, 0x0");
    TEST("\xc4\xe3\x79\x16\xc0\x00", "vpextrd eax, xmm0, 0x0");
    TEST32("\xc4\xe3\xf9\x16\xc0\x00", "vpextrd eax, xmm0, 0x0");
    TEST64("\xc4\xe3\xf9\x16\xc0\x00", "vpextrq rax, xmm0, 0x0");

    TEST("\xc4\xe3\x71\x20\xc0\x00", "vpinsrb xmm0, xmm1, al, 0x0");
    TEST("\xc4\xe3\xf1\x20\xc0\x00", "vpinsrb xmm0, xmm1, al, 0x0");
    TEST("\xc4\xe1\x71\xc4\xc0\x00", "vpinsrw xmm0, xmm1, ax, 0x0");
    TEST("\xc4\xe1\xf1\xc4\xc0\x00", "vpinsrw xmm0, xmm1, ax, 0x0");
    TEST("\xc4\xe3\x71\x22\xc0\x00", "vpinsrd xmm0, xmm1, eax, 0x0");
    TEST32("\xc4\xe3\xf1\x22\xc0\x00", "vpinsrd xmm0, xmm1, eax, 0x0");
    TEST64("\xc4\xe3\xf1\x22\xc0\x00", "vpinsrq xmm0, xmm1, rax, 0x0");
    TEST("\xc4\xe3\x75\x20\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe1\x75\xc4\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe1\xf5\xc4\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe3\x75\x22\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe3\xf5\x22\xc0\x00", "UD"); // VEX.L != 0

    TEST("\xc4\xe2\x71\x45\xc2", "vpsrlvd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\x45\xc2", "vpsrlvd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf1\x45\xc2", "vpsrlvq xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf5\x45\xc2", "vpsrlvq ymm0, ymm1, ymm2");

    TEST("\xc4\xe2\x71\x92\xc0", "UD"); // Must have memory operand
    TEST("\xc4\xe2\x71\x92\x00", "UD"); // Must have SIB byte
    TEST("\xc4\xe2\x71\x92\x05\x00\x00\x00\x00", "UD"); // Must have SIB byte
    TEST32("\xc4\xe2\x71\x92\x04\xe7", "vgatherdps xmm0, dword ptr [edi+8*xmm4], xmm1");
    TEST64("\xc4\xe2\x71\x92\x04\xe7", "vgatherdps xmm0, dword ptr [rdi+8*xmm4], xmm1");
    TEST32("\xc4\xe2\x75\x92\x04\xe7", "vgatherdps ymm0, dword ptr [edi+8*ymm4], ymm1");
    TEST64("\xc4\xe2\x75\x92\x04\xe7", "vgatherdps ymm0, dword ptr [rdi+8*ymm4], ymm1");
    TEST32("\xc4\xe2\x71\x93\x04\xe7", "vgatherqps xmm0, dword ptr [edi+8*xmm4], xmm1");
    TEST64("\xc4\xe2\x71\x93\x04\xe7", "vgatherqps xmm0, dword ptr [rdi+8*xmm4], xmm1");
    TEST32("\xc4\xe2\x75\x93\x04\xe7", "vgatherqps xmm0, dword ptr [edi+8*ymm4], xmm1");
    TEST64("\xc4\xe2\x75\x93\x04\xe7", "vgatherqps xmm0, dword ptr [rdi+8*ymm4], xmm1");
    TEST32("\xc4\xe2\xf1\x92\x04\xe7", "vgatherdpd xmm0, qword ptr [edi+8*xmm4], xmm1");
    TEST64("\xc4\xe2\xf1\x92\x04\xe7", "vgatherdpd xmm0, qword ptr [rdi+8*xmm4], xmm1");
    TEST32("\xc4\xe2\xf5\x92\x04\xe7", "vgatherdpd ymm0, qword ptr [edi+8*xmm4], ymm1");
    TEST64("\xc4\xe2\xf5\x92\x04\xe7", "vgatherdpd ymm0, qword ptr [rdi+8*xmm4], ymm1");
    TEST32("\xc4\xe2\xf1\x93\x04\xe7", "vgatherqpd xmm0, qword ptr [edi+8*xmm4], xmm1");
    TEST64("\xc4\xe2\xf1\x93\x04\xe7", "vgatherqpd xmm0, qword ptr [rdi+8*xmm4], xmm1");
    TEST32("\xc4\xe2\xf5\x93\x04\xe7", "vgatherqpd ymm0, qword ptr [edi+8*ymm4], ymm1");
    TEST64("\xc4\xe2\xf5\x93\x04\xe7", "vgatherqpd ymm0, qword ptr [rdi+8*ymm4], ymm1");
    TEST32("\xc4\xe2\x71\x90\x04\xe7", "vpgatherdd xmm0, dword ptr [edi+8*xmm4], xmm1");
    TEST64("\xc4\xe2\x71\x90\x04\xe7", "vpgatherdd xmm0, dword ptr [rdi+8*xmm4], xmm1");
    TEST32("\xc4\xe2\x75\x90\x04\xe7", "vpgatherdd ymm0, dword ptr [edi+8*ymm4], ymm1");
    TEST64("\xc4\xe2\x75\x90\x04\xe7", "vpgatherdd ymm0, dword ptr [rdi+8*ymm4], ymm1");
    TEST32("\xc4\xe2\x71\x91\x04\xe7", "vpgatherqd xmm0, dword ptr [edi+8*xmm4], xmm1");
    TEST64("\xc4\xe2\x71\x91\x04\xe7", "vpgatherqd xmm0, dword ptr [rdi+8*xmm4], xmm1");
    TEST32("\xc4\xe2\x75\x91\x04\xe7", "vpgatherqd xmm0, dword ptr [edi+8*ymm4], xmm1");
    TEST64("\xc4\xe2\x75\x91\x04\xe7", "vpgatherqd xmm0, dword ptr [rdi+8*ymm4], xmm1");
    TEST32("\xc4\xe2\xf1\x90\x04\xe7", "vpgatherdq xmm0, qword ptr [edi+8*xmm4], xmm1");
    TEST64("\xc4\xe2\xf1\x90\x04\xe7", "vpgatherdq xmm0, qword ptr [rdi+8*xmm4], xmm1");
    TEST32("\xc4\xe2\xf5\x90\x04\xe7", "vpgatherdq ymm0, qword ptr [edi+8*xmm4], ymm1");
    TEST64("\xc4\xe2\xf5\x90\x04\xe7", "vpgatherdq ymm0, qword ptr [rdi+8*xmm4], ymm1");
    TEST32("\xc4\xe2\xf1\x91\x04\xe7", "vpgatherqq xmm0, qword ptr [edi+8*xmm4], xmm1");
    TEST64("\xc4\xe2\xf1\x91\x04\xe7", "vpgatherqq xmm0, qword ptr [rdi+8*xmm4], xmm1");
    TEST32("\xc4\xe2\xf5\x91\x04\xe7", "vpgatherqq ymm0, qword ptr [edi+8*ymm4], ymm1");
    TEST64("\xc4\xe2\xf5\x91\x04\xe7", "vpgatherqq ymm0, qword ptr [rdi+8*ymm4], ymm1");

    TEST32("\xc4\xe2\x7d\x5a\x20", "vbroadcasti128 ymm4, xmmword ptr [eax]");
    TEST64("\xc4\xe2\x7d\x5a\x20", "vbroadcasti128 ymm4, xmmword ptr [rax]");
    TEST64("\xc4\x62\x7d\x5a\x20", "vbroadcasti128 ymm12, xmmword ptr [rax]");
    TEST("\xc4\xe2\x75\x5a\x20", "UD"); // VEX.vvvv != 1111
    TEST("\xc4\xe2\x7d\x5a\xc0", "UD"); // ModRM.mod != 11
    TEST("\xc4\xe2\x79\x5a\x20", "UD"); // VEX.L != 1
    TEST("\xc4\xe2\xfd\x5a\x20", "UD"); // VEX.W != 0

    // Intel-Syntax special cases
    TEST("\x66\x98", "cbw");
    TEST("\x98", "cwde");
    TEST64("\x48\x98", "cdqe");
    TEST("\x66\x99", "cwd");
    TEST("\x99", "cdq");
    TEST64("\x48\x99", "cqo");

    TEST32("\x0f\xae\x00", "fxsave [eax]");
    TEST64("\x0f\xae\x00", "fxsave [rax]");
    TEST64("\x48\x0f\xae\x00", "fxsave64 [rax]");
    TEST32("\x66\xff\xe0", "jmp ax");
    TEST64("\x66\xff\xe0", "jmp rax");
    TEST32("\x66\x70\x00", "jow 0x3");
    TEST64("\x66\x70\x00", "jo 0x3");
    TEST32("\xe3\xfe", "jecxz 0x0");
    TEST64("\xe3\xfe", "jrcxz 0x0");
    TEST32("\x67\xe3\xfd", "jcxz 0x0");
    TEST64("\x67\xe3\xfd", "jecxz 0x0");
    TEST32("\x66\x9a\x23\x01\x23\x00", "call far 0x23:0x123");
    TEST32("\x9a\x67\x45\x23\x01\x23\x00", "call far 0x23:0x1234567");
    TEST32("\x9a\xff\xff\xff\xff\xff\xff", "call far 0xffff:0xffffffff");
    TEST32("\x66\xff\x1f", "call far dword ptr [edi]");
    TEST64("\x66\xff\x1f", "call far dword ptr [rdi]");
    TEST32("\xff\x1f", "call far fword ptr [edi]");
    TEST64("\xff\x1f", "call far fword ptr [rdi]");
    TEST64("\x48\xff\x1f", "call far tbyte ptr [rdi]");
    TEST32("\x66\x0f\xb4\x07", "lfs ax, dword ptr [edi]");
    TEST64("\x66\x0f\xb4\x07", "lfs ax, dword ptr [rdi]");
    TEST32("\x0f\xb4\x07", "lfs eax, fword ptr [edi]");
    TEST64("\x0f\xb4\x07", "lfs eax, fword ptr [rdi]");
    TEST64("\x48\x0f\xb4\x07", "lfs rax, tbyte ptr [rdi]");
    TEST("\xa5", "movsd");
    TEST("\x64\xa5", "fs movsd");
    TEST32("\x2e\xa5", "cs movsd");
    TEST64("\x2e\xa5", "movsd");
    TEST32("\x67\xa5", "addr16 movsd");
    TEST64("\x67\xa5", "addr32 movsd");
    TEST("\xaf", "scasd");
    TEST("\x64\xaf", "scasd"); // SCAS doesn't use segment overrides
    TEST("\xec", "inb");
    TEST32("\x66\x61", "popaw");
    TEST32("\x61", "popad");
    TEST("\x66\x9d", "popfw");
    TEST32("\x9d", "popfd");
    TEST64("\x9d", "popfq");
    TEST("\x66\xcf", "iretw");
    TEST("\xcf", "iretd");
    TEST64("\x48\xcf", "iretq");
    TEST32("\x06", "push es");
    TEST32("\x66\x06", "pushw es");
    TEST32("\x07", "pop es");
    TEST32("\x66\x07", "popw es");
    TEST32("\x0e", "push cs");
    TEST32("\x66\x0e", "pushw cs");
    TEST32("\x16", "push ss");
    TEST32("\x66\x16", "pushw ss");
    TEST32("\x17", "pop ss");
    TEST32("\x66\x17", "popw ss");
    TEST("\x0f\xa8", "push gs");
    TEST("\x66\x0f\xa8", "pushw gs");
    TEST("\x0f\xa9", "pop gs");
    TEST("\x66\x0f\xa9", "popw gs");
    TEST32("\x0f\x21\xd0", "mov eax, dr2");
    TEST64("\x0f\x21\xd0", "mov rax, dr2");
    TEST32("\x62\x00", "bound eax, qword ptr [eax]");
    TEST32("\x66\x62\x00", "bound ax, dword ptr [eax]");
    TEST32("\x0f\xae\x38", "clflush byte ptr [eax]");
    TEST64("\x0f\xae\x38", "clflush byte ptr [rax]");
    TEST32("\xdd\x00", "fld qword ptr [eax]");
    TEST64("\xdd\x00", "fld qword ptr [rax]");
    TEST32("\xdb\x28", "fld tbyte ptr [eax]");
    TEST64("\xdb\x28", "fld tbyte ptr [rax]");
    TEST32("\xd9\x20", "fldenv [eax]");
    TEST64("\xd9\x20", "fldenv [rax]");

    // 3DNow!
    TEST("\x0f\x0f\xc0\x00", "UD");
    TEST("\x0f\x0f\xc0\x0c", "3dnow mm0, mm0, 0xc"); // PI2FW
    TEST("\x0f\x0f\xc0\x0d", "3dnow mm0, mm0, 0xd"); // PI2FD
    TEST("\x0f\x0f\xc0\x0e", "UD");
    TEST("\x0f\x0f\xc0\x1c", "3dnow mm0, mm0, 0x1c"); // PF2IW
    TEST("\x0f\x0f\xc0\x1d", "3dnow mm0, mm0, 0x1d"); // PF2ID
    TEST("\x0f\x0f\xc0\x42", "UD");
    TEST("\x0f\x0f\xc0\x80", "UD");
    TEST("\x0f\x0f\xc0\x8a", "3dnow mm0, mm0, 0x8a"); // PFNACC
    TEST("\x0f\x0f\xc0\xa0", "3dnow mm0, mm0, 0xa0"); // PFCMPGT
    TEST("\x0f\x0f\xc0\xb6", "3dnow mm0, mm0, 0xb6"); // PFRCPIT2
    TEST("\x0f\x0f\xc0\xbf", "3dnow mm0, mm0, 0xbf"); // PAVGUSB

    puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

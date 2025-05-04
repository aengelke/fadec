
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

    memset(fmt, 0, sizeof(fmt));
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

    if ((retval < 0 || (unsigned) retval == buf_len)) {
        if (!strcmp(fmt, exp_fmt))
            return 0;
        // Consider 32/64 bit differences, e.g. for addressing mode.
        const char* it = exp_fmt;
        while ((it = (const char*) strchr(it, '@'))) {
            if (fmt[it - exp_fmt] == (mode != 64 ? 'e' : 'r'))
                fmt[it - exp_fmt] = '@';
            it++;
        }
        if (!strcmp(fmt, exp_fmt))
            return 0;
    }

    printf("Failed case (%u-bit): ", mode);
    print_hex(buf, buf_len);
    printf("\n  Exp (%2zu): %s", buf_len, exp_fmt);
    printf("\n  Got (%2d): %s\n", retval, fmt);
    return -1;
}

#define TEST1(mode, buf, exp_fmt) test(buf, sizeof(buf)-1, mode, exp_fmt)
#define TEST32(...) failed |= TEST1(32, __VA_ARGS__)
#define TEST64(...) failed |= TEST1(64, __VA_ARGS__)
#define TEST3264(buf, exp_fmt32, exp_fmt64) \
            failed |= TEST1(32, buf, exp_fmt32) | TEST1(64, buf, exp_fmt64)
#define TEST(...) failed |= TEST1(32, __VA_ARGS__) | TEST1(64, __VA_ARGS__)

int
main(int argc, char** argv)
{
    (void) argc; (void) argv;

    int failed = 0;

    TEST("\x90", "nop");
    TEST("\xac", "lodsb");
    TEST3264("\x26\xac", "es lodsb", "lodsb");
    TEST3264("\x2e\xac", "cs lodsb", "lodsb");
    TEST3264("\x36\xac", "ss lodsb", "lodsb");
    TEST3264("\x3e\xac", "ds lodsb", "lodsb");
    TEST("\x64\xac", "fs lodsb");
    TEST("\x65\xac", "gs lodsb");
    TEST3264("\x2e\x2e\xac", "cs lodsb", "lodsb");
    TEST3264("\x2e\x26\xac", "es lodsb", "lodsb");
    TEST3264("\x26\x2e\xac", "cs lodsb", "lodsb");
    TEST3264("\x26\x65\xac", "gs lodsb", "gs lodsb");
    TEST3264("\x65\x26\xac", "es lodsb", "gs lodsb");
    TEST("\x01\x00", "add dword ptr [@ax], eax");
    TEST3264("\x26\x01\x00", "add dword ptr es:[eax], eax", "add dword ptr [rax], eax");
    TEST3264("\x2e\x01\x00", "add dword ptr cs:[eax], eax", "add dword ptr [rax], eax");
    TEST3264("\x36\x01\x00", "add dword ptr ss:[eax], eax", "add dword ptr [rax], eax");
    TEST3264("\x3e\x01\x00", "add dword ptr ds:[eax], eax", "add dword ptr [rax], eax");
    TEST("\x64\x01\x00", "add dword ptr fs:[@ax], eax");
    TEST("\x65\x01\x00", "add dword ptr gs:[@ax], eax");
    TEST("\x0f\x10\xc1", "movups xmm0, xmm1");
    TEST("\x66\x0f\x10\xc1", "movupd xmm0, xmm1");
    TEST("\xf2\x66\x0f\x10\xc1", "movsd xmm0, xmm1");
    TEST("\xf3\x66\x0f\x10\xc1", "movss xmm0, xmm1");
    TEST("\xf3\xf2\x66\x0f\x10\xc1", "movsd xmm0, xmm1");
    TEST("\xf2\x66\xf3\x66\x0f\x10\xc1", "movss xmm0, xmm1");

    TEST64("\x48\x91", "xchg rcx, rax");
    TEST64("\x48\x26\x91", "xchg ecx, eax");
    TEST("\x90", "nop");
    TEST("\xf2\x90", "nop");
    TEST("\x66\x90", "nop"); // NB: could be xchg ax, ax
    TEST("\x66\xf2\x90", "nop"); // NB: could be xchg ax, ax
    TEST64("\x41\x90", "xchg r8d, eax");
    TEST64("\xf2\x41\x90", "xchg r8d, eax");
    TEST64("\x66\x41\x90", "xchg r8w, ax");
    TEST64("\x66\xf2\x41\x90", "xchg r8w, ax");
    TEST64("\x48\x90", "nop"); // NB: could be xchg rax, rax
    TEST64("\xf2\x48\x90", "nop"); // NB: could be xchg rax, rax
    TEST64("\x66\x48\x90", "nop"); // NB: could be xchg rax, rax
    TEST64("\x66\xf2\x48\x90", "nop"); // NB: could be xchg rax, rax
    TEST64("\x49\x90", "xchg r8, rax");
    TEST64("\xf2\x49\x90", "xchg r8, rax");
    TEST64("\x66\x49\x90", "xchg r8, rax");
    TEST64("\x66\xf2\x49\x90", "xchg r8, rax");
    TEST("\xf3\x90", "pause");
    TEST("\x66\xf3\x90", "pause");
    TEST64("\xf3\x41\x90", "pause"); // NB: xchg for AMD
    TEST64("\x66\xf3\x41\x90", "pause"); // NB: xchg for AMD
    TEST64("\xf3\x48\x90", "pause");
    TEST64("\x66\xf3\x48\x90", "pause");
    TEST64("\xf3\x49\x90", "pause"); // NB: xchg for AMD
    TEST64("\x66\xf3\x49\x90", "pause"); // NB: xchg for AMD
    TEST("\xf3\x91", "xchg ecx, eax");

    TEST("\x0f\xc7\x0f", "cmpxchg8b qword ptr [@di]");
    TEST("\x66\x0f\xc7\x0f", "cmpxchg8b qword ptr [@di]"); // 66h is ignored
    TEST64("\x48\x0f\xc7\x0f", "cmpxchg16b xmmword ptr [rdi]");
    TEST("\xf2\x0f\xc7\x0f", "cmpxchg8b qword ptr [@di]");
    TEST("\xf3\x0f\xc7\x0f", "cmpxchg8b qword ptr [@di]");
    TEST("\xf2\xf0\x0f\xc7\x0f", "xacquire lock cmpxchg8b qword ptr [@di]");
    TEST("\xf3\xf0\x0f\xc7\x0f", "xrelease lock cmpxchg8b qword ptr [@di]");
    TEST("\x87\x0f", "xchg dword ptr [@di], ecx");
    TEST("\xf2\x87\x0f", "xacquire xchg dword ptr [@di], ecx");
    TEST("\xf3\x87\x0f", "xrelease xchg dword ptr [@di], ecx");
    TEST("\xf2\xf0\x87\x0f", "xacquire lock xchg dword ptr [@di], ecx");
    TEST("\xf3\xf0\x87\x0f", "xrelease lock xchg dword ptr [@di], ecx");
    TEST("\xc6\x07\x12", "mov byte ptr [@di], 0x12");
    TEST("\xf2\xc6\x07\x12", "mov byte ptr [@di], 0x12"); // no xacquire
    TEST("\xf3\xc6\x07\x12", "xrelease mov byte ptr [@di], 0x12");
    TEST("\x66\xc7\x07\x34\x12", "mov word ptr [@di], 0x1234");
    TEST("\x66\xf2\xc7\x07\x34\x12", "mov word ptr [@di], 0x1234"); // no xacquire
    TEST("\x66\xf3\xc7\x07\x34\x12", "xrelease mov word ptr [@di], 0x1234");
    TEST64("\xf0\xff\xc0", "UD"); // lock with register operand is UD
    TEST64("\xf0\xd0\x00", "UD"); // lock with rol is UD
    TEST("\x66", "PARTIAL");
    TEST("\xf0", "PARTIAL");
    TEST("\x0f", "PARTIAL");
    TEST("\x0f\x38", "PARTIAL");
    TEST("\x0f\x3a", "PARTIAL");
    TEST("\x80", "PARTIAL");
    TEST("\x80\x04", "PARTIAL");
    TEST("\x80\x40", "PARTIAL");
    TEST("\x80\x80\x00\x00\x00", "PARTIAL");
    TEST("\xb0", "PARTIAL");
    TEST("\xb8", "PARTIAL");
    TEST("\xb8\x00", "PARTIAL");
    TEST("\xb8\x00\x00", "PARTIAL");
    TEST("\xb8\x00\x00\x00", "PARTIAL");
    TEST("\x0F\x01\x22", "smsw word ptr [@dx]");
    TEST64("\x48\x0F\x01\x22", "smsw word ptr [rdx]");
    TEST("\x66\x0F\x01\x22", "smsw word ptr [@dx]");
    TEST("\x0F\x01\xE2", "smsw edx");
    TEST("\x66\x0F\x01\xE2", "smsw dx");
    TEST64("\x66\x48\x0F\x01\xE2", "smsw rdx");
    TEST64("\xf2\x66\x0f\x01\x23", "smsw word ptr [rbx]");
    TEST("\x66\x0f\x20\x00", "mov @ax, cr0"); // mod=0, 66h
    TEST("\xf3\x0f\x20\x00", "mov @ax, cr0"); // REP
    TEST("\x0f\x20\xc8", "UD"); // cr1
    TEST("\x0f\x20\xd0", "mov @ax, cr2"); // cr2
    TEST64("\x48\x0f\x20\xd0", "mov rax, cr2"); // cr2 + REX.W
    TEST("\x0f\x20\xd8", "mov @ax, cr3"); // cr3
    TEST("\x0f\x20\xe0", "mov @ax, cr4"); // cr4
    TEST3264("\x0f\x20\xe8", "UD", "UD"); // cr5
    TEST64("\x44\x0f\x20\x00", "mov rax, cr8"); // cr8
    TEST64("\x45\x0f\x20\x00", "mov r8, cr8"); // cr8
    TEST64("\x44\x0f\x20\x08", "UD"); // cr9
    TEST64("\x44\x0f\x21\x00", "UD"); // dr8
    TEST32("\xf0\x0f\x20\x00", "UD"); // LOCK
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
    TEST("\xdf\xe0", "fstsw ax");
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
    TEST("\x01\x00", "add dword ptr [@ax], eax");
    TEST("\x01\x08", "add dword ptr [@ax], ecx");
    TEST("\x01\x01", "add dword ptr [@cx], eax");
    TEST("\x01\x07", "add dword ptr [@di], eax");
    TEST("\x01\x38", "add dword ptr [@ax], edi");
    TEST("\x01\x04\x24", "add dword ptr [@sp], eax");
    TEST64("\x41\x01\x00", "add dword ptr [r8], eax");
    TEST64("\x44\x01\x08", "add dword ptr [rax], r9d");
    TEST64("\x45\x01\x00", "add dword ptr [r8], r8d");
    TEST64("\x41\x01\x07", "add dword ptr [r15], eax");
    TEST64("\x41\x01\x04\x24", "add dword ptr [r12], eax");
    // [disp32]
    TEST32("\x01\x05\x01\x00\x00\x00", "add dword ptr [0x1], eax");
    TEST32("\x01\x05\xff\xff\xff\xff", "add dword ptr [0xffffffff], eax");
    TEST("\x01\x04\x25\x01\x00\x00\x00", "add dword ptr [0x1], eax");
    TEST3264("\x01\x04\x25\x00\x00\x00\x80", "add dword ptr [0x80000000], eax", "add dword ptr [0xffffffff80000000], eax");
    TEST64("\x41\x01\x04\x25\x01\x00\x00\x00", "add dword ptr [0x1], eax");
    TEST("\x01\x04\x25\x00\x00\x00\x00", "add dword ptr [0x0], eax");
    // [rip+disp32]
    TEST64("\x01\x05\x01\x00\x00\x00", "add dword ptr [rip+0x1], eax");
    TEST64("\x41\x01\x05\x01\x00\x00\x00", "add dword ptr [rip+0x1], eax");
    TEST64("\x67\x01\x05\x01\x00\x00\x00", "add dword ptr [eip+0x1], eax");
    TEST64("\x67\x41\x01\x05\x01\x00\x00\x00", "add dword ptr [eip+0x1], eax");
    // [reg+disp32]
    TEST("\x01\x80\x01\x00\x00\x00", "add dword ptr [@ax+0x1], eax");
    TEST("\x01\x80\x00\x00\x00\x80", "add dword ptr [@ax-0x80000000], eax");
    // [reg+eiz+disp32]
    TEST("\x01\x84\x25\x01\x00\x00\x00", "add dword ptr [@bp+0x1], eax");
    // [reg+s*reg+disp32]
    TEST64("\x42\x01\x84\x25\x01\x00\x00\x00", "add dword ptr [rbp+1*r12+0x1], eax");
    // [s*reg]
    TEST("\x01\x04\x8d\x00\x00\x00\x00", "add dword ptr [4*@cx], eax");

    // 32-bit+67 ModRM cases. reg=0
    TEST32("\x67\x01\x00", "add dword ptr [bx+1*si], eax");
    TEST32("\x67\x01\x01", "add dword ptr [bx+1*di], eax");
    TEST32("\x67\x01\x02", "add dword ptr [bp+1*si], eax");
    TEST32("\x67\x01\x03", "add dword ptr [bp+1*di], eax");
    TEST32("\x67\x01\x04", "add dword ptr [1*si], eax");
    TEST32("\x67\x01\x05", "add dword ptr [1*di], eax");
    TEST32("\x67\x01\x06\x11\x22", "add dword ptr [0x2211], eax");
    TEST32("\x67\x01\x06\xf0\xff", "add dword ptr [0xfff0], eax");
    TEST32("\x67\x01\x07", "add dword ptr [bx], eax");
    TEST32("\x67\x01\x40\x12", "add dword ptr [bx+1*si+0x12], eax");
    TEST32("\x67\x01\x40\x99", "add dword ptr [bx+1*si-0x67], eax");
    TEST32("\x67\x01\x41\x12", "add dword ptr [bx+1*di+0x12], eax");
    TEST32("\x67\x01\x41\x99", "add dword ptr [bx+1*di-0x67], eax");
    TEST32("\x67\x01\x42\x12", "add dword ptr [bp+1*si+0x12], eax");
    TEST32("\x67\x01\x42\x99", "add dword ptr [bp+1*si-0x67], eax");
    TEST32("\x67\x01\x43\x12", "add dword ptr [bp+1*di+0x12], eax");
    TEST32("\x67\x01\x43\x99", "add dword ptr [bp+1*di-0x67], eax");
    TEST32("\x67\x01\x44\x12", "add dword ptr [1*si+0x12], eax");
    TEST32("\x67\x01\x44\x99", "add dword ptr [1*si-0x67], eax");
    TEST32("\x67\x01\x45\x12", "add dword ptr [1*di+0x12], eax");
    TEST32("\x67\x01\x45\x99", "add dword ptr [1*di-0x67], eax");
    TEST32("\x67\x01\x46\x12", "add dword ptr [bp+0x12], eax");
    TEST32("\x67\x01\x46\x99", "add dword ptr [bp-0x67], eax");
    TEST32("\x67\x01\x47\x12", "add dword ptr [bx+0x12], eax");
    TEST32("\x67\x01\x47\x99", "add dword ptr [bx-0x67], eax");
    TEST32("\x67\x01\x80\x11\x22", "add dword ptr [bx+1*si+0x2211], eax");
    TEST32("\x67\x01\x80\xf0\xff", "add dword ptr [bx+1*si-0x10], eax");
    TEST32("\x67\x01\x81\x11\x22", "add dword ptr [bx+1*di+0x2211], eax");
    TEST32("\x67\x01\x81\xf0\xff", "add dword ptr [bx+1*di-0x10], eax");
    TEST32("\x67\x01\x82\x11\x22", "add dword ptr [bp+1*si+0x2211], eax");
    TEST32("\x67\x01\x82\xf0\xff", "add dword ptr [bp+1*si-0x10], eax");
    TEST32("\x67\x01\x83\x11\x22", "add dword ptr [bp+1*di+0x2211], eax");
    TEST32("\x67\x01\x83\xf0\xff", "add dword ptr [bp+1*di-0x10], eax");
    TEST32("\x67\x01\x84\x11\x22", "add dword ptr [1*si+0x2211], eax");
    TEST32("\x67\x01\x84\xf0\xff", "add dword ptr [1*si-0x10], eax");
    TEST32("\x67\x01\x85\x11\x22", "add dword ptr [1*di+0x2211], eax");
    TEST32("\x67\x01\x85\xf0\xff", "add dword ptr [1*di-0x10], eax");
    TEST32("\x67\x01\x86\x11\x22", "add dword ptr [bp+0x2211], eax");
    TEST32("\x67\x01\x86\xf0\xff", "add dword ptr [bp-0x10], eax");
    TEST32("\x67\x01\x87\x11\x22", "add dword ptr [bx+0x2211], eax");
    TEST32("\x67\x01\x87\xf0\xff", "add dword ptr [bx-0x10], eax");
    TEST32("\x67\x01", "PARTIAL");
    TEST32("\x67\x01\x47", "PARTIAL");
    TEST32("\x67\x01\x80", "PARTIAL");
    TEST32("\x67\x01\x80\x11", "PARTIAL");

    // 32-bit, 64-bit and 64-bit+67 ModRM+SIB cases. scale=2, reg=0
    TEST("\x01\x00", "add dword ptr [@ax], eax");
    TEST64("\x67\x01\x00", "add dword ptr [eax], eax");
    TEST("\x01\x01", "add dword ptr [@cx], eax");
    TEST64("\x67\x01\x01", "add dword ptr [ecx], eax");
    TEST("\x01\x02", "add dword ptr [@dx], eax");
    TEST64("\x67\x01\x02", "add dword ptr [edx], eax");
    TEST("\x01\x03", "add dword ptr [@bx], eax");
    TEST64("\x67\x01\x03", "add dword ptr [ebx], eax");
    TEST("\x01\x04\x80", "add dword ptr [@ax+4*@ax], eax");
    TEST64("\x67\x01\x04\x80", "add dword ptr [eax+4*eax], eax");
    TEST("\x01\x04\x81", "add dword ptr [@cx+4*@ax], eax");
    TEST64("\x67\x01\x04\x81", "add dword ptr [ecx+4*eax], eax");
    TEST("\x01\x04\x82", "add dword ptr [@dx+4*@ax], eax");
    TEST64("\x67\x01\x04\x82", "add dword ptr [edx+4*eax], eax");
    TEST("\x01\x04\x83", "add dword ptr [@bx+4*@ax], eax");
    TEST64("\x67\x01\x04\x83", "add dword ptr [ebx+4*eax], eax");
    TEST("\x01\x04\x84", "add dword ptr [@sp+4*@ax], eax");
    TEST64("\x67\x01\x04\x84", "add dword ptr [esp+4*eax], eax");
    TEST("\x01\x04\x85\x11\x22\x33\x44", "add dword ptr [4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x04\x85\x11\x22\x33\x44", "add dword ptr [4*eax+0x44332211], eax");
    TEST("\x01\x04\x86", "add dword ptr [@si+4*@ax], eax");
    TEST64("\x67\x01\x04\x86", "add dword ptr [esi+4*eax], eax");
    TEST("\x01\x04\x87", "add dword ptr [@di+4*@ax], eax");
    TEST64("\x67\x01\x04\x87", "add dword ptr [edi+4*eax], eax");
    TEST("\x01\x04\x88", "add dword ptr [@ax+4*@cx], eax");
    TEST64("\x67\x01\x04\x88", "add dword ptr [eax+4*ecx], eax");
    TEST("\x01\x04\x89", "add dword ptr [@cx+4*@cx], eax");
    TEST64("\x67\x01\x04\x89", "add dword ptr [ecx+4*ecx], eax");
    TEST("\x01\x04\x8a", "add dword ptr [@dx+4*@cx], eax");
    TEST64("\x67\x01\x04\x8a", "add dword ptr [edx+4*ecx], eax");
    TEST("\x01\x04\x8b", "add dword ptr [@bx+4*@cx], eax");
    TEST64("\x67\x01\x04\x8b", "add dword ptr [ebx+4*ecx], eax");
    TEST("\x01\x04\x8c", "add dword ptr [@sp+4*@cx], eax");
    TEST64("\x67\x01\x04\x8c", "add dword ptr [esp+4*ecx], eax");
    TEST("\x01\x04\x8d\x11\x22\x33\x44", "add dword ptr [4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x04\x8d\x11\x22\x33\x44", "add dword ptr [4*ecx+0x44332211], eax");
    TEST("\x01\x04\x8e", "add dword ptr [@si+4*@cx], eax");
    TEST64("\x67\x01\x04\x8e", "add dword ptr [esi+4*ecx], eax");
    TEST("\x01\x04\x8f", "add dword ptr [@di+4*@cx], eax");
    TEST64("\x67\x01\x04\x8f", "add dword ptr [edi+4*ecx], eax");
    TEST("\x01\x04\x90", "add dword ptr [@ax+4*@dx], eax");
    TEST64("\x67\x01\x04\x90", "add dword ptr [eax+4*edx], eax");
    TEST("\x01\x04\x91", "add dword ptr [@cx+4*@dx], eax");
    TEST64("\x67\x01\x04\x91", "add dword ptr [ecx+4*edx], eax");
    TEST("\x01\x04\x92", "add dword ptr [@dx+4*@dx], eax");
    TEST64("\x67\x01\x04\x92", "add dword ptr [edx+4*edx], eax");
    TEST("\x01\x04\x93", "add dword ptr [@bx+4*@dx], eax");
    TEST64("\x67\x01\x04\x93", "add dword ptr [ebx+4*edx], eax");
    TEST("\x01\x04\x94", "add dword ptr [@sp+4*@dx], eax");
    TEST64("\x67\x01\x04\x94", "add dword ptr [esp+4*edx], eax");
    TEST("\x01\x04\x95\x11\x22\x33\x44", "add dword ptr [4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x04\x95\x11\x22\x33\x44", "add dword ptr [4*edx+0x44332211], eax");
    TEST("\x01\x04\x96", "add dword ptr [@si+4*@dx], eax");
    TEST64("\x67\x01\x04\x96", "add dword ptr [esi+4*edx], eax");
    TEST("\x01\x04\x97", "add dword ptr [@di+4*@dx], eax");
    TEST64("\x67\x01\x04\x97", "add dword ptr [edi+4*edx], eax");
    TEST("\x01\x04\x98", "add dword ptr [@ax+4*@bx], eax");
    TEST64("\x67\x01\x04\x98", "add dword ptr [eax+4*ebx], eax");
    TEST("\x01\x04\x99", "add dword ptr [@cx+4*@bx], eax");
    TEST64("\x67\x01\x04\x99", "add dword ptr [ecx+4*ebx], eax");
    TEST("\x01\x04\x9a", "add dword ptr [@dx+4*@bx], eax");
    TEST64("\x67\x01\x04\x9a", "add dword ptr [edx+4*ebx], eax");
    TEST("\x01\x04\x9b", "add dword ptr [@bx+4*@bx], eax");
    TEST64("\x67\x01\x04\x9b", "add dword ptr [ebx+4*ebx], eax");
    TEST("\x01\x04\x9c", "add dword ptr [@sp+4*@bx], eax");
    TEST64("\x67\x01\x04\x9c", "add dword ptr [esp+4*ebx], eax");
    TEST("\x01\x04\x9d\x11\x22\x33\x44", "add dword ptr [4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x04\x9d\x11\x22\x33\x44", "add dword ptr [4*ebx+0x44332211], eax");
    TEST("\x01\x04\x9e", "add dword ptr [@si+4*@bx], eax");
    TEST64("\x67\x01\x04\x9e", "add dword ptr [esi+4*ebx], eax");
    TEST("\x01\x04\x9f", "add dword ptr [@di+4*@bx], eax");
    TEST64("\x67\x01\x04\x9f", "add dword ptr [edi+4*ebx], eax");
    TEST("\x01\x04\xa0", "add dword ptr [@ax], eax");
    TEST64("\x67\x01\x04\xa0", "add dword ptr [eax], eax");
    TEST("\x01\x04\xa1", "add dword ptr [@cx], eax");
    TEST64("\x67\x01\x04\xa1", "add dword ptr [ecx], eax");
    TEST("\x01\x04\xa2", "add dword ptr [@dx], eax");
    TEST64("\x67\x01\x04\xa2", "add dword ptr [edx], eax");
    TEST("\x01\x04\xa3", "add dword ptr [@bx], eax");
    TEST64("\x67\x01\x04\xa3", "add dword ptr [ebx], eax");
    TEST("\x01\x04\xa4", "add dword ptr [@sp], eax");
    TEST64("\x67\x01\x04\xa4", "add dword ptr [esp], eax");
    TEST3264("\x01\x04\xa5\x11\x22\x33\x44", "add dword ptr [0x44332211], eax", "add dword ptr [0x44332211], eax");
    TEST64("\x67\x01\x04\xa5\x11\x22\x33\x44", "add dword ptr [0x44332211], eax");
    TEST("\x01\x04\xa6", "add dword ptr [@si], eax");
    TEST64("\x67\x01\x04\xa6", "add dword ptr [esi], eax");
    TEST("\x01\x04\xa7", "add dword ptr [@di], eax");
    TEST64("\x67\x01\x04\xa7", "add dword ptr [edi], eax");
    TEST("\x01\x04\xa8", "add dword ptr [@ax+4*@bp], eax");
    TEST64("\x67\x01\x04\xa8", "add dword ptr [eax+4*ebp], eax");
    TEST("\x01\x04\xa9", "add dword ptr [@cx+4*@bp], eax");
    TEST64("\x67\x01\x04\xa9", "add dword ptr [ecx+4*ebp], eax");
    TEST("\x01\x04\xaa", "add dword ptr [@dx+4*@bp], eax");
    TEST64("\x67\x01\x04\xaa", "add dword ptr [edx+4*ebp], eax");
    TEST("\x01\x04\xab", "add dword ptr [@bx+4*@bp], eax");
    TEST64("\x67\x01\x04\xab", "add dword ptr [ebx+4*ebp], eax");
    TEST("\x01\x04\xac", "add dword ptr [@sp+4*@bp], eax");
    TEST64("\x67\x01\x04\xac", "add dword ptr [esp+4*ebp], eax");
    TEST("\x01\x04\xad\x11\x22\x33\x44", "add dword ptr [4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x04\xad\x11\x22\x33\x44", "add dword ptr [4*ebp+0x44332211], eax");
    TEST("\x01\x04\xae", "add dword ptr [@si+4*@bp], eax");
    TEST64("\x67\x01\x04\xae", "add dword ptr [esi+4*ebp], eax");
    TEST("\x01\x04\xaf", "add dword ptr [@di+4*@bp], eax");
    TEST64("\x67\x01\x04\xaf", "add dword ptr [edi+4*ebp], eax");
    TEST("\x01\x04\xb0", "add dword ptr [@ax+4*@si], eax");
    TEST64("\x67\x01\x04\xb0", "add dword ptr [eax+4*esi], eax");
    TEST("\x01\x04\xb1", "add dword ptr [@cx+4*@si], eax");
    TEST64("\x67\x01\x04\xb1", "add dword ptr [ecx+4*esi], eax");
    TEST("\x01\x04\xb2", "add dword ptr [@dx+4*@si], eax");
    TEST64("\x67\x01\x04\xb2", "add dword ptr [edx+4*esi], eax");
    TEST("\x01\x04\xb3", "add dword ptr [@bx+4*@si], eax");
    TEST64("\x67\x01\x04\xb3", "add dword ptr [ebx+4*esi], eax");
    TEST("\x01\x04\xb4", "add dword ptr [@sp+4*@si], eax");
    TEST64("\x67\x01\x04\xb4", "add dword ptr [esp+4*esi], eax");
    TEST("\x01\x04\xb5\x11\x22\x33\x44", "add dword ptr [4*@si+0x44332211], eax");
    TEST64("\x67\x01\x04\xb5\x11\x22\x33\x44", "add dword ptr [4*esi+0x44332211], eax");
    TEST("\x01\x04\xb6", "add dword ptr [@si+4*@si], eax");
    TEST64("\x67\x01\x04\xb6", "add dword ptr [esi+4*esi], eax");
    TEST("\x01\x04\xb7", "add dword ptr [@di+4*@si], eax");
    TEST64("\x67\x01\x04\xb7", "add dword ptr [edi+4*esi], eax");
    TEST("\x01\x04\xb8", "add dword ptr [@ax+4*@di], eax");
    TEST64("\x67\x01\x04\xb8", "add dword ptr [eax+4*edi], eax");
    TEST("\x01\x04\xb9", "add dword ptr [@cx+4*@di], eax");
    TEST64("\x67\x01\x04\xb9", "add dword ptr [ecx+4*edi], eax");
    TEST("\x01\x04\xba", "add dword ptr [@dx+4*@di], eax");
    TEST64("\x67\x01\x04\xba", "add dword ptr [edx+4*edi], eax");
    TEST("\x01\x04\xbb", "add dword ptr [@bx+4*@di], eax");
    TEST64("\x67\x01\x04\xbb", "add dword ptr [ebx+4*edi], eax");
    TEST("\x01\x04\xbc", "add dword ptr [@sp+4*@di], eax");
    TEST64("\x67\x01\x04\xbc", "add dword ptr [esp+4*edi], eax");
    TEST("\x01\x04\xbd\x11\x22\x33\x44", "add dword ptr [4*@di+0x44332211], eax");
    TEST64("\x67\x01\x04\xbd\x11\x22\x33\x44", "add dword ptr [4*edi+0x44332211], eax");
    TEST("\x01\x04\xbe", "add dword ptr [@si+4*@di], eax");
    TEST64("\x67\x01\x04\xbe", "add dword ptr [esi+4*edi], eax");
    TEST("\x01\x04\xbf", "add dword ptr [@di+4*@di], eax");
    TEST64("\x67\x01\x04\xbf", "add dword ptr [edi+4*edi], eax");
    TEST3264("\x01\x05\x11\x22\x33\x44", "add dword ptr [0x44332211], eax", "add dword ptr [rip+0x44332211], eax");
    TEST64("\x67\x01\x05\x11\x22\x33\x44", "add dword ptr [eip+0x44332211], eax");
    TEST("\x01\x06", "add dword ptr [@si], eax");
    TEST64("\x67\x01\x06", "add dword ptr [esi], eax");
    TEST("\x01\x07", "add dword ptr [@di], eax");
    TEST64("\x67\x01\x07", "add dword ptr [edi], eax");
    TEST("\x01\x40\x99", "add dword ptr [@ax-0x67], eax");
    TEST64("\x67\x01\x40\x99", "add dword ptr [eax-0x67], eax");
    TEST("\x01\x41\x99", "add dword ptr [@cx-0x67], eax");
    TEST64("\x67\x01\x41\x99", "add dword ptr [ecx-0x67], eax");
    TEST("\x01\x42\x99", "add dword ptr [@dx-0x67], eax");
    TEST64("\x67\x01\x42\x99", "add dword ptr [edx-0x67], eax");
    TEST("\x01\x43\x99", "add dword ptr [@bx-0x67], eax");
    TEST64("\x67\x01\x43\x99", "add dword ptr [ebx-0x67], eax");
    TEST("\x01\x44\x80\x99", "add dword ptr [@ax+4*@ax-0x67], eax");
    TEST64("\x67\x01\x44\x80\x99", "add dword ptr [eax+4*eax-0x67], eax");
    TEST("\x01\x44\x81\x99", "add dword ptr [@cx+4*@ax-0x67], eax");
    TEST64("\x67\x01\x44\x81\x99", "add dword ptr [ecx+4*eax-0x67], eax");
    TEST("\x01\x44\x82\x99", "add dword ptr [@dx+4*@ax-0x67], eax");
    TEST64("\x67\x01\x44\x82\x99", "add dword ptr [edx+4*eax-0x67], eax");
    TEST("\x01\x44\x83\x99", "add dword ptr [@bx+4*@ax-0x67], eax");
    TEST64("\x67\x01\x44\x83\x99", "add dword ptr [ebx+4*eax-0x67], eax");
    TEST("\x01\x44\x84\x99", "add dword ptr [@sp+4*@ax-0x67], eax");
    TEST64("\x67\x01\x44\x84\x99", "add dword ptr [esp+4*eax-0x67], eax");
    TEST("\x01\x44\x85\x99", "add dword ptr [@bp+4*@ax-0x67], eax");
    TEST64("\x67\x01\x44\x85\x99", "add dword ptr [ebp+4*eax-0x67], eax");
    TEST("\x01\x44\x86\x99", "add dword ptr [@si+4*@ax-0x67], eax");
    TEST64("\x67\x01\x44\x86\x99", "add dword ptr [esi+4*eax-0x67], eax");
    TEST("\x01\x44\x87\x99", "add dword ptr [@di+4*@ax-0x67], eax");
    TEST64("\x67\x01\x44\x87\x99", "add dword ptr [edi+4*eax-0x67], eax");
    TEST("\x01\x44\x88\x99", "add dword ptr [@ax+4*@cx-0x67], eax");
    TEST64("\x67\x01\x44\x88\x99", "add dword ptr [eax+4*ecx-0x67], eax");
    TEST("\x01\x44\x89\x99", "add dword ptr [@cx+4*@cx-0x67], eax");
    TEST64("\x67\x01\x44\x89\x99", "add dword ptr [ecx+4*ecx-0x67], eax");
    TEST("\x01\x44\x8a\x99", "add dword ptr [@dx+4*@cx-0x67], eax");
    TEST64("\x67\x01\x44\x8a\x99", "add dword ptr [edx+4*ecx-0x67], eax");
    TEST("\x01\x44\x8b\x99", "add dword ptr [@bx+4*@cx-0x67], eax");
    TEST64("\x67\x01\x44\x8b\x99", "add dword ptr [ebx+4*ecx-0x67], eax");
    TEST("\x01\x44\x8c\x99", "add dword ptr [@sp+4*@cx-0x67], eax");
    TEST64("\x67\x01\x44\x8c\x99", "add dword ptr [esp+4*ecx-0x67], eax");
    TEST("\x01\x44\x8d\x99", "add dword ptr [@bp+4*@cx-0x67], eax");
    TEST64("\x67\x01\x44\x8d\x99", "add dword ptr [ebp+4*ecx-0x67], eax");
    TEST("\x01\x44\x8e\x99", "add dword ptr [@si+4*@cx-0x67], eax");
    TEST64("\x67\x01\x44\x8e\x99", "add dword ptr [esi+4*ecx-0x67], eax");
    TEST("\x01\x44\x8f\x99", "add dword ptr [@di+4*@cx-0x67], eax");
    TEST64("\x67\x01\x44\x8f\x99", "add dword ptr [edi+4*ecx-0x67], eax");
    TEST("\x01\x44\x90\x99", "add dword ptr [@ax+4*@dx-0x67], eax");
    TEST64("\x67\x01\x44\x90\x99", "add dword ptr [eax+4*edx-0x67], eax");
    TEST("\x01\x44\x91\x99", "add dword ptr [@cx+4*@dx-0x67], eax");
    TEST64("\x67\x01\x44\x91\x99", "add dword ptr [ecx+4*edx-0x67], eax");
    TEST("\x01\x44\x92\x99", "add dword ptr [@dx+4*@dx-0x67], eax");
    TEST64("\x67\x01\x44\x92\x99", "add dword ptr [edx+4*edx-0x67], eax");
    TEST("\x01\x44\x93\x99", "add dword ptr [@bx+4*@dx-0x67], eax");
    TEST64("\x67\x01\x44\x93\x99", "add dword ptr [ebx+4*edx-0x67], eax");
    TEST("\x01\x44\x94\x99", "add dword ptr [@sp+4*@dx-0x67], eax");
    TEST64("\x67\x01\x44\x94\x99", "add dword ptr [esp+4*edx-0x67], eax");
    TEST("\x01\x44\x95\x99", "add dword ptr [@bp+4*@dx-0x67], eax");
    TEST64("\x67\x01\x44\x95\x99", "add dword ptr [ebp+4*edx-0x67], eax");
    TEST("\x01\x44\x96\x99", "add dword ptr [@si+4*@dx-0x67], eax");
    TEST64("\x67\x01\x44\x96\x99", "add dword ptr [esi+4*edx-0x67], eax");
    TEST("\x01\x44\x97\x99", "add dword ptr [@di+4*@dx-0x67], eax");
    TEST64("\x67\x01\x44\x97\x99", "add dword ptr [edi+4*edx-0x67], eax");
    TEST("\x01\x44\x98\x99", "add dword ptr [@ax+4*@bx-0x67], eax");
    TEST64("\x67\x01\x44\x98\x99", "add dword ptr [eax+4*ebx-0x67], eax");
    TEST("\x01\x44\x99\x99", "add dword ptr [@cx+4*@bx-0x67], eax");
    TEST64("\x67\x01\x44\x99\x99", "add dword ptr [ecx+4*ebx-0x67], eax");
    TEST("\x01\x44\x9a\x99", "add dword ptr [@dx+4*@bx-0x67], eax");
    TEST64("\x67\x01\x44\x9a\x99", "add dword ptr [edx+4*ebx-0x67], eax");
    TEST("\x01\x44\x9b\x99", "add dword ptr [@bx+4*@bx-0x67], eax");
    TEST64("\x67\x01\x44\x9b\x99", "add dword ptr [ebx+4*ebx-0x67], eax");
    TEST("\x01\x44\x9c\x99", "add dword ptr [@sp+4*@bx-0x67], eax");
    TEST64("\x67\x01\x44\x9c\x99", "add dword ptr [esp+4*ebx-0x67], eax");
    TEST("\x01\x44\x9d\x99", "add dword ptr [@bp+4*@bx-0x67], eax");
    TEST64("\x67\x01\x44\x9d\x99", "add dword ptr [ebp+4*ebx-0x67], eax");
    TEST("\x01\x44\x9e\x99", "add dword ptr [@si+4*@bx-0x67], eax");
    TEST64("\x67\x01\x44\x9e\x99", "add dword ptr [esi+4*ebx-0x67], eax");
    TEST("\x01\x44\x9f\x99", "add dword ptr [@di+4*@bx-0x67], eax");
    TEST64("\x67\x01\x44\x9f\x99", "add dword ptr [edi+4*ebx-0x67], eax");
    TEST("\x01\x44\xa0\x99", "add dword ptr [@ax-0x67], eax");
    TEST64("\x67\x01\x44\xa0\x99", "add dword ptr [eax-0x67], eax");
    TEST("\x01\x44\xa1\x99", "add dword ptr [@cx-0x67], eax");
    TEST64("\x67\x01\x44\xa1\x99", "add dword ptr [ecx-0x67], eax");
    TEST("\x01\x44\xa2\x99", "add dword ptr [@dx-0x67], eax");
    TEST64("\x67\x01\x44\xa2\x99", "add dword ptr [edx-0x67], eax");
    TEST("\x01\x44\xa3\x99", "add dword ptr [@bx-0x67], eax");
    TEST64("\x67\x01\x44\xa3\x99", "add dword ptr [ebx-0x67], eax");
    TEST("\x01\x44\xa4\x99", "add dword ptr [@sp-0x67], eax");
    TEST64("\x67\x01\x44\xa4\x99", "add dword ptr [esp-0x67], eax");
    TEST("\x01\x44\xa5\x99", "add dword ptr [@bp-0x67], eax");
    TEST64("\x67\x01\x44\xa5\x99", "add dword ptr [ebp-0x67], eax");
    TEST("\x01\x44\xa6\x99", "add dword ptr [@si-0x67], eax");
    TEST64("\x67\x01\x44\xa6\x99", "add dword ptr [esi-0x67], eax");
    TEST("\x01\x44\xa7\x99", "add dword ptr [@di-0x67], eax");
    TEST64("\x67\x01\x44\xa7\x99", "add dword ptr [edi-0x67], eax");
    TEST("\x01\x44\xa8\x99", "add dword ptr [@ax+4*@bp-0x67], eax");
    TEST64("\x67\x01\x44\xa8\x99", "add dword ptr [eax+4*ebp-0x67], eax");
    TEST("\x01\x44\xa9\x99", "add dword ptr [@cx+4*@bp-0x67], eax");
    TEST64("\x67\x01\x44\xa9\x99", "add dword ptr [ecx+4*ebp-0x67], eax");
    TEST("\x01\x44\xaa\x99", "add dword ptr [@dx+4*@bp-0x67], eax");
    TEST64("\x67\x01\x44\xaa\x99", "add dword ptr [edx+4*ebp-0x67], eax");
    TEST("\x01\x44\xab\x99", "add dword ptr [@bx+4*@bp-0x67], eax");
    TEST64("\x67\x01\x44\xab\x99", "add dword ptr [ebx+4*ebp-0x67], eax");
    TEST("\x01\x44\xac\x99", "add dword ptr [@sp+4*@bp-0x67], eax");
    TEST64("\x67\x01\x44\xac\x99", "add dword ptr [esp+4*ebp-0x67], eax");
    TEST("\x01\x44\xad\x99", "add dword ptr [@bp+4*@bp-0x67], eax");
    TEST64("\x67\x01\x44\xad\x99", "add dword ptr [ebp+4*ebp-0x67], eax");
    TEST("\x01\x44\xae\x99", "add dword ptr [@si+4*@bp-0x67], eax");
    TEST64("\x67\x01\x44\xae\x99", "add dword ptr [esi+4*ebp-0x67], eax");
    TEST("\x01\x44\xaf\x99", "add dword ptr [@di+4*@bp-0x67], eax");
    TEST64("\x67\x01\x44\xaf\x99", "add dword ptr [edi+4*ebp-0x67], eax");
    TEST("\x01\x44\xb0\x99", "add dword ptr [@ax+4*@si-0x67], eax");
    TEST64("\x67\x01\x44\xb0\x99", "add dword ptr [eax+4*esi-0x67], eax");
    TEST("\x01\x44\xb1\x99", "add dword ptr [@cx+4*@si-0x67], eax");
    TEST64("\x67\x01\x44\xb1\x99", "add dword ptr [ecx+4*esi-0x67], eax");
    TEST("\x01\x44\xb2\x99", "add dword ptr [@dx+4*@si-0x67], eax");
    TEST64("\x67\x01\x44\xb2\x99", "add dword ptr [edx+4*esi-0x67], eax");
    TEST("\x01\x44\xb3\x99", "add dword ptr [@bx+4*@si-0x67], eax");
    TEST64("\x67\x01\x44\xb3\x99", "add dword ptr [ebx+4*esi-0x67], eax");
    TEST("\x01\x44\xb4\x99", "add dword ptr [@sp+4*@si-0x67], eax");
    TEST64("\x67\x01\x44\xb4\x99", "add dword ptr [esp+4*esi-0x67], eax");
    TEST("\x01\x44\xb5\x99", "add dword ptr [@bp+4*@si-0x67], eax");
    TEST64("\x67\x01\x44\xb5\x99", "add dword ptr [ebp+4*esi-0x67], eax");
    TEST("\x01\x44\xb6\x99", "add dword ptr [@si+4*@si-0x67], eax");
    TEST64("\x67\x01\x44\xb6\x99", "add dword ptr [esi+4*esi-0x67], eax");
    TEST("\x01\x44\xb7\x99", "add dword ptr [@di+4*@si-0x67], eax");
    TEST64("\x67\x01\x44\xb7\x99", "add dword ptr [edi+4*esi-0x67], eax");
    TEST("\x01\x44\xb8\x99", "add dword ptr [@ax+4*@di-0x67], eax");
    TEST64("\x67\x01\x44\xb8\x99", "add dword ptr [eax+4*edi-0x67], eax");
    TEST("\x01\x44\xb9\x99", "add dword ptr [@cx+4*@di-0x67], eax");
    TEST64("\x67\x01\x44\xb9\x99", "add dword ptr [ecx+4*edi-0x67], eax");
    TEST("\x01\x44\xba\x99", "add dword ptr [@dx+4*@di-0x67], eax");
    TEST64("\x67\x01\x44\xba\x99", "add dword ptr [edx+4*edi-0x67], eax");
    TEST("\x01\x44\xbb\x99", "add dword ptr [@bx+4*@di-0x67], eax");
    TEST64("\x67\x01\x44\xbb\x99", "add dword ptr [ebx+4*edi-0x67], eax");
    TEST("\x01\x44\xbc\x99", "add dword ptr [@sp+4*@di-0x67], eax");
    TEST64("\x67\x01\x44\xbc\x99", "add dword ptr [esp+4*edi-0x67], eax");
    TEST("\x01\x44\xbd\x99", "add dword ptr [@bp+4*@di-0x67], eax");
    TEST64("\x67\x01\x44\xbd\x99", "add dword ptr [ebp+4*edi-0x67], eax");
    TEST("\x01\x44\xbe\x99", "add dword ptr [@si+4*@di-0x67], eax");
    TEST64("\x67\x01\x44\xbe\x99", "add dword ptr [esi+4*edi-0x67], eax");
    TEST("\x01\x44\xbf\x99", "add dword ptr [@di+4*@di-0x67], eax");
    TEST64("\x67\x01\x44\xbf\x99", "add dword ptr [edi+4*edi-0x67], eax");
    TEST("\x01\x45\x99", "add dword ptr [@bp-0x67], eax");
    TEST64("\x67\x01\x45\x99", "add dword ptr [ebp-0x67], eax");
    TEST("\x01\x46\x99", "add dword ptr [@si-0x67], eax");
    TEST64("\x67\x01\x46\x99", "add dword ptr [esi-0x67], eax");
    TEST("\x01\x47\x99", "add dword ptr [@di-0x67], eax");
    TEST64("\x67\x01\x47\x99", "add dword ptr [edi-0x67], eax");
    TEST("\x01\x80\x11\x22\x33\x44", "add dword ptr [@ax+0x44332211], eax");
    TEST64("\x67\x01\x80\x11\x22\x33\x44", "add dword ptr [eax+0x44332211], eax");
    TEST("\x01\x81\x11\x22\x33\x44", "add dword ptr [@cx+0x44332211], eax");
    TEST64("\x67\x01\x81\x11\x22\x33\x44", "add dword ptr [ecx+0x44332211], eax");
    TEST("\x01\x82\x11\x22\x33\x44", "add dword ptr [@dx+0x44332211], eax");
    TEST64("\x67\x01\x82\x11\x22\x33\x44", "add dword ptr [edx+0x44332211], eax");
    TEST("\x01\x83\x11\x22\x33\x44", "add dword ptr [@bx+0x44332211], eax");
    TEST64("\x67\x01\x83\x11\x22\x33\x44", "add dword ptr [ebx+0x44332211], eax");
    TEST("\x01\x84\x80\x11\x22\x33\x44", "add dword ptr [@ax+4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\x80\x11\x22\x33\x44", "add dword ptr [eax+4*eax+0x44332211], eax");
    TEST("\x01\x84\x81\x11\x22\x33\x44", "add dword ptr [@cx+4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\x81\x11\x22\x33\x44", "add dword ptr [ecx+4*eax+0x44332211], eax");
    TEST("\x01\x84\x82\x11\x22\x33\x44", "add dword ptr [@dx+4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\x82\x11\x22\x33\x44", "add dword ptr [edx+4*eax+0x44332211], eax");
    TEST("\x01\x84\x83\x11\x22\x33\x44", "add dword ptr [@bx+4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\x83\x11\x22\x33\x44", "add dword ptr [ebx+4*eax+0x44332211], eax");
    TEST("\x01\x84\x84\x11\x22\x33\x44", "add dword ptr [@sp+4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\x84\x11\x22\x33\x44", "add dword ptr [esp+4*eax+0x44332211], eax");
    TEST("\x01\x84\x85\x11\x22\x33\x44", "add dword ptr [@bp+4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\x85\x11\x22\x33\x44", "add dword ptr [ebp+4*eax+0x44332211], eax");
    TEST("\x01\x84\x86\x11\x22\x33\x44", "add dword ptr [@si+4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\x86\x11\x22\x33\x44", "add dword ptr [esi+4*eax+0x44332211], eax");
    TEST("\x01\x84\x87\x11\x22\x33\x44", "add dword ptr [@di+4*@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\x87\x11\x22\x33\x44", "add dword ptr [edi+4*eax+0x44332211], eax");
    TEST("\x01\x84\x88\x11\x22\x33\x44", "add dword ptr [@ax+4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\x88\x11\x22\x33\x44", "add dword ptr [eax+4*ecx+0x44332211], eax");
    TEST("\x01\x84\x89\x11\x22\x33\x44", "add dword ptr [@cx+4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\x89\x11\x22\x33\x44", "add dword ptr [ecx+4*ecx+0x44332211], eax");
    TEST("\x01\x84\x8a\x11\x22\x33\x44", "add dword ptr [@dx+4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\x8a\x11\x22\x33\x44", "add dword ptr [edx+4*ecx+0x44332211], eax");
    TEST("\x01\x84\x8b\x11\x22\x33\x44", "add dword ptr [@bx+4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\x8b\x11\x22\x33\x44", "add dword ptr [ebx+4*ecx+0x44332211], eax");
    TEST("\x01\x84\x8c\x11\x22\x33\x44", "add dword ptr [@sp+4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\x8c\x11\x22\x33\x44", "add dword ptr [esp+4*ecx+0x44332211], eax");
    TEST("\x01\x84\x8d\x11\x22\x33\x44", "add dword ptr [@bp+4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\x8d\x11\x22\x33\x44", "add dword ptr [ebp+4*ecx+0x44332211], eax");
    TEST("\x01\x84\x8e\x11\x22\x33\x44", "add dword ptr [@si+4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\x8e\x11\x22\x33\x44", "add dword ptr [esi+4*ecx+0x44332211], eax");
    TEST("\x01\x84\x8f\x11\x22\x33\x44", "add dword ptr [@di+4*@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\x8f\x11\x22\x33\x44", "add dword ptr [edi+4*ecx+0x44332211], eax");
    TEST("\x01\x84\x90\x11\x22\x33\x44", "add dword ptr [@ax+4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\x90\x11\x22\x33\x44", "add dword ptr [eax+4*edx+0x44332211], eax");
    TEST("\x01\x84\x91\x11\x22\x33\x44", "add dword ptr [@cx+4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\x91\x11\x22\x33\x44", "add dword ptr [ecx+4*edx+0x44332211], eax");
    TEST("\x01\x84\x92\x11\x22\x33\x44", "add dword ptr [@dx+4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\x92\x11\x22\x33\x44", "add dword ptr [edx+4*edx+0x44332211], eax");
    TEST("\x01\x84\x93\x11\x22\x33\x44", "add dword ptr [@bx+4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\x93\x11\x22\x33\x44", "add dword ptr [ebx+4*edx+0x44332211], eax");
    TEST("\x01\x84\x94\x11\x22\x33\x44", "add dword ptr [@sp+4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\x94\x11\x22\x33\x44", "add dword ptr [esp+4*edx+0x44332211], eax");
    TEST("\x01\x84\x95\x11\x22\x33\x44", "add dword ptr [@bp+4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\x95\x11\x22\x33\x44", "add dword ptr [ebp+4*edx+0x44332211], eax");
    TEST("\x01\x84\x96\x11\x22\x33\x44", "add dword ptr [@si+4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\x96\x11\x22\x33\x44", "add dword ptr [esi+4*edx+0x44332211], eax");
    TEST("\x01\x84\x97\x11\x22\x33\x44", "add dword ptr [@di+4*@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\x97\x11\x22\x33\x44", "add dword ptr [edi+4*edx+0x44332211], eax");
    TEST("\x01\x84\x98\x11\x22\x33\x44", "add dword ptr [@ax+4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\x98\x11\x22\x33\x44", "add dword ptr [eax+4*ebx+0x44332211], eax");
    TEST("\x01\x84\x99\x11\x22\x33\x44", "add dword ptr [@cx+4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\x99\x11\x22\x33\x44", "add dword ptr [ecx+4*ebx+0x44332211], eax");
    TEST("\x01\x84\x9a\x11\x22\x33\x44", "add dword ptr [@dx+4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\x9a\x11\x22\x33\x44", "add dword ptr [edx+4*ebx+0x44332211], eax");
    TEST("\x01\x84\x9b\x11\x22\x33\x44", "add dword ptr [@bx+4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\x9b\x11\x22\x33\x44", "add dword ptr [ebx+4*ebx+0x44332211], eax");
    TEST("\x01\x84\x9c\x11\x22\x33\x44", "add dword ptr [@sp+4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\x9c\x11\x22\x33\x44", "add dword ptr [esp+4*ebx+0x44332211], eax");
    TEST("\x01\x84\x9d\x11\x22\x33\x44", "add dword ptr [@bp+4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\x9d\x11\x22\x33\x44", "add dword ptr [ebp+4*ebx+0x44332211], eax");
    TEST("\x01\x84\x9e\x11\x22\x33\x44", "add dword ptr [@si+4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\x9e\x11\x22\x33\x44", "add dword ptr [esi+4*ebx+0x44332211], eax");
    TEST("\x01\x84\x9f\x11\x22\x33\x44", "add dword ptr [@di+4*@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\x9f\x11\x22\x33\x44", "add dword ptr [edi+4*ebx+0x44332211], eax");
    TEST("\x01\x84\xa0\x11\x22\x33\x44", "add dword ptr [@ax+0x44332211], eax");
    TEST64("\x67\x01\x84\xa0\x11\x22\x33\x44", "add dword ptr [eax+0x44332211], eax");
    TEST("\x01\x84\xa1\x11\x22\x33\x44", "add dword ptr [@cx+0x44332211], eax");
    TEST64("\x67\x01\x84\xa1\x11\x22\x33\x44", "add dword ptr [ecx+0x44332211], eax");
    TEST("\x01\x84\xa2\x11\x22\x33\x44", "add dword ptr [@dx+0x44332211], eax");
    TEST64("\x67\x01\x84\xa2\x11\x22\x33\x44", "add dword ptr [edx+0x44332211], eax");
    TEST("\x01\x84\xa3\x11\x22\x33\x44", "add dword ptr [@bx+0x44332211], eax");
    TEST64("\x67\x01\x84\xa3\x11\x22\x33\x44", "add dword ptr [ebx+0x44332211], eax");
    TEST("\x01\x84\xa4\x11\x22\x33\x44", "add dword ptr [@sp+0x44332211], eax");
    TEST64("\x67\x01\x84\xa4\x11\x22\x33\x44", "add dword ptr [esp+0x44332211], eax");
    TEST("\x01\x84\xa5\x11\x22\x33\x44", "add dword ptr [@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xa5\x11\x22\x33\x44", "add dword ptr [ebp+0x44332211], eax");
    TEST("\x01\x84\xa6\x11\x22\x33\x44", "add dword ptr [@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xa6\x11\x22\x33\x44", "add dword ptr [esi+0x44332211], eax");
    TEST("\x01\x84\xa7\x11\x22\x33\x44", "add dword ptr [@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xa7\x11\x22\x33\x44", "add dword ptr [edi+0x44332211], eax");
    TEST("\x01\x84\xa8\x11\x22\x33\x44", "add dword ptr [@ax+4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xa8\x11\x22\x33\x44", "add dword ptr [eax+4*ebp+0x44332211], eax");
    TEST("\x01\x84\xa9\x11\x22\x33\x44", "add dword ptr [@cx+4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xa9\x11\x22\x33\x44", "add dword ptr [ecx+4*ebp+0x44332211], eax");
    TEST("\x01\x84\xaa\x11\x22\x33\x44", "add dword ptr [@dx+4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xaa\x11\x22\x33\x44", "add dword ptr [edx+4*ebp+0x44332211], eax");
    TEST("\x01\x84\xab\x11\x22\x33\x44", "add dword ptr [@bx+4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xab\x11\x22\x33\x44", "add dword ptr [ebx+4*ebp+0x44332211], eax");
    TEST("\x01\x84\xac\x11\x22\x33\x44", "add dword ptr [@sp+4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xac\x11\x22\x33\x44", "add dword ptr [esp+4*ebp+0x44332211], eax");
    TEST("\x01\x84\xad\x11\x22\x33\x44", "add dword ptr [@bp+4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xad\x11\x22\x33\x44", "add dword ptr [ebp+4*ebp+0x44332211], eax");
    TEST("\x01\x84\xae\x11\x22\x33\x44", "add dword ptr [@si+4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xae\x11\x22\x33\x44", "add dword ptr [esi+4*ebp+0x44332211], eax");
    TEST("\x01\x84\xaf\x11\x22\x33\x44", "add dword ptr [@di+4*@bp+0x44332211], eax");
    TEST64("\x67\x01\x84\xaf\x11\x22\x33\x44", "add dword ptr [edi+4*ebp+0x44332211], eax");
    TEST("\x01\x84\xb0\x11\x22\x33\x44", "add dword ptr [@ax+4*@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xb0\x11\x22\x33\x44", "add dword ptr [eax+4*esi+0x44332211], eax");
    TEST("\x01\x84\xb1\x11\x22\x33\x44", "add dword ptr [@cx+4*@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xb1\x11\x22\x33\x44", "add dword ptr [ecx+4*esi+0x44332211], eax");
    TEST("\x01\x84\xb2\x11\x22\x33\x44", "add dword ptr [@dx+4*@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xb2\x11\x22\x33\x44", "add dword ptr [edx+4*esi+0x44332211], eax");
    TEST("\x01\x84\xb3\x11\x22\x33\x44", "add dword ptr [@bx+4*@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xb3\x11\x22\x33\x44", "add dword ptr [ebx+4*esi+0x44332211], eax");
    TEST("\x01\x84\xb4\x11\x22\x33\x44", "add dword ptr [@sp+4*@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xb4\x11\x22\x33\x44", "add dword ptr [esp+4*esi+0x44332211], eax");
    TEST("\x01\x84\xb5\x11\x22\x33\x44", "add dword ptr [@bp+4*@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xb5\x11\x22\x33\x44", "add dword ptr [ebp+4*esi+0x44332211], eax");
    TEST("\x01\x84\xb6\x11\x22\x33\x44", "add dword ptr [@si+4*@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xb6\x11\x22\x33\x44", "add dword ptr [esi+4*esi+0x44332211], eax");
    TEST("\x01\x84\xb7\x11\x22\x33\x44", "add dword ptr [@di+4*@si+0x44332211], eax");
    TEST64("\x67\x01\x84\xb7\x11\x22\x33\x44", "add dword ptr [edi+4*esi+0x44332211], eax");
    TEST("\x01\x84\xb8\x11\x22\x33\x44", "add dword ptr [@ax+4*@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xb8\x11\x22\x33\x44", "add dword ptr [eax+4*edi+0x44332211], eax");
    TEST("\x01\x84\xb9\x11\x22\x33\x44", "add dword ptr [@cx+4*@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xb9\x11\x22\x33\x44", "add dword ptr [ecx+4*edi+0x44332211], eax");
    TEST("\x01\x84\xba\x11\x22\x33\x44", "add dword ptr [@dx+4*@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xba\x11\x22\x33\x44", "add dword ptr [edx+4*edi+0x44332211], eax");
    TEST("\x01\x84\xbb\x11\x22\x33\x44", "add dword ptr [@bx+4*@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xbb\x11\x22\x33\x44", "add dword ptr [ebx+4*edi+0x44332211], eax");
    TEST("\x01\x84\xbc\x11\x22\x33\x44", "add dword ptr [@sp+4*@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xbc\x11\x22\x33\x44", "add dword ptr [esp+4*edi+0x44332211], eax");
    TEST("\x01\x84\xbd\x11\x22\x33\x44", "add dword ptr [@bp+4*@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xbd\x11\x22\x33\x44", "add dword ptr [ebp+4*edi+0x44332211], eax");
    TEST("\x01\x84\xbe\x11\x22\x33\x44", "add dword ptr [@si+4*@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xbe\x11\x22\x33\x44", "add dword ptr [esi+4*edi+0x44332211], eax");
    TEST("\x01\x84\xbf\x11\x22\x33\x44", "add dword ptr [@di+4*@di+0x44332211], eax");
    TEST64("\x67\x01\x84\xbf\x11\x22\x33\x44", "add dword ptr [edi+4*edi+0x44332211], eax");
    TEST("\x01\x85\x11\x22\x33\x44", "add dword ptr [@bp+0x44332211], eax");
    TEST64("\x67\x01\x85\x11\x22\x33\x44", "add dword ptr [ebp+0x44332211], eax");
    TEST("\x01\x86\x11\x22\x33\x44", "add dword ptr [@si+0x44332211], eax");
    TEST64("\x67\x01\x86\x11\x22\x33\x44", "add dword ptr [esi+0x44332211], eax");
    TEST("\x01\x87\x11\x22\x33\x44", "add dword ptr [@di+0x44332211], eax");
    TEST64("\x67\x01\x87\x11\x22\x33\x44", "add dword ptr [edi+0x44332211], eax");
    TEST("\x01\xc0", "add eax, eax");
    TEST("\x01\xc1", "add ecx, eax");
    TEST("\x01\xc2", "add edx, eax");
    TEST("\x01\xc3", "add ebx, eax");
    TEST("\x01\xc4", "add esp, eax");
    TEST("\x01\xc5", "add ebp, eax");
    TEST("\x01\xc6", "add esi, eax");
    TEST("\x01\xc7", "add edi, eax");

    TEST("\x0f\xbc\xc0", "bsf eax, eax");
    TEST("\x66\x0f\xbc\xc0", "bsf ax, ax");
    TEST("\xf2\x0f\xbc\xc0", "bsf eax, eax");
    TEST("\x66\xf2\x0f\xbc\xc0", "bsf ax, ax");
    TEST("\x0f\x01\x00", "sgdt [@ax]");
    TEST("\x66\x0f\x01\x00", "sgdt [@ax]");
    TEST("\xf2\x0f\x01\x00", "sgdt [@ax]");
    TEST("\xf3\x0f\x01\x00", "sgdt [@ax]");
    TEST("\x04\x01", "add al, 0x1");
    TEST("\x66\x50", "push ax");
    TEST("\x50", "push @ax");
    TEST("\x66\x68\xff\xad", "pushw 0xadff");
    TEST3264("\x68\xff\xad\x90\xbc", "push 0xbc90adff", "push 0xffffffffbc90adff");
    TEST("\x66\x6a\xff", "pushw 0xffff");
    TEST3264("\x6a\xff", "push 0xffffffff", "push 0xffffffffffffffff");
    TEST32("\x60", "pushad");
    TEST32("\x66\x60", "pushaw");
    TEST("\xb0\xf0", "mov al, 0xf0");
    TEST("\xb1\xda", "mov cl, 0xda");
    TEST("\xb2\xff", "mov dl, 0xff");
    TEST("\xb3\x8d", "mov bl, 0x8d");
    TEST("\xb4\x5e", "mov ah, 0x5e");
    TEST64("\x40\xb4\x00", "mov spl, 0x0");
    TEST("\xb5\x74", "mov ch, 0x74");
    TEST64("\x40\xb5\xd0", "mov bpl, 0xd0");
    TEST("\xb6\xe5", "mov dh, 0xe5");
    TEST64("\x40\xb6\xf1", "mov sil, 0xf1");
    TEST("\xb7\xe8", "mov bh, 0xe8");
    TEST64("\x40\xb7\x31", "mov dil, 0x31");
    TEST("\x66\xb8\xf0\xf0", "mov ax, 0xf0f0");
    TEST("\xb8\xf0\xf0\xab\xff", "mov eax, 0xffabf0f0");
    TEST64("\x48\xb8\xf0\xf0\xab\xff\x00\x12\x12\xcd", "mov rax, 0xcd121200ffabf0f0");
    TEST64("\xcd\x80", "int 0x80");

    // Test FD/TD encoding
    TEST32("\xa0\x44\x33\x22\x11", "mov al, byte ptr [0x11223344]");
    TEST64("\xa0\x88\x77\x66\x55\x44\x33\x22\x11", "mov al, byte ptr [0x1122334455667788]");
    TEST32("\x67\xa0\x22\x11", "mov al, byte ptr [0x1122]");
    TEST64("\x67\xa0\x44\x33\x22\x11", "mov al, byte ptr [0x11223344]");
    TEST32("\xa1\x44\x33\x22\x11", "mov eax, dword ptr [0x11223344]");
    TEST64("\xa1\x88\x77\x66\x55\x44\x33\x22\x11", "mov eax, dword ptr [0x1122334455667788]");
    TEST32("\x67\xa1\x22\x11", "mov eax, dword ptr [0x1122]");
    TEST64("\x67\xa1\x44\x33\x22\x11", "mov eax, dword ptr [0x11223344]");
    TEST32("\x66\xa1\x44\x33\x22\x11", "mov ax, word ptr [0x11223344]");
    TEST64("\x66\xa1\x88\x77\x66\x55\x44\x33\x22\x11", "mov ax, word ptr [0x1122334455667788]");
    TEST32("\x66\x67\xa1\x22\x11", "mov ax, word ptr [0x1122]");
    TEST64("\x66\x67\xa1\x44\x33\x22\x11", "mov ax, word ptr [0x11223344]");
    TEST64("\x48\xa1\x88\x77\x66\x55\x44\x33\x22\x11", "mov rax, qword ptr [0x1122334455667788]");
    TEST64("\x67\x48\xa1\x44\x33\x22\x11", "mov rax, qword ptr [0x11223344]");
    TEST32("\xa2\x44\x33\x22\x11", "mov byte ptr [0x11223344], al");
    TEST64("\xa2\x88\x77\x66\x55\x44\x33\x22\x11", "mov byte ptr [0x1122334455667788], al");
    TEST32("\x67\xa2\x22\x11", "mov byte ptr [0x1122], al");
    TEST64("\x67\xa2\x44\x33\x22\x11", "mov byte ptr [0x11223344], al");
    TEST32("\xa3\x44\x33\x22\x11", "mov dword ptr [0x11223344], eax");
    TEST64("\xa3\x88\x77\x66\x55\x44\x33\x22\x11", "mov dword ptr [0x1122334455667788], eax");
    TEST32("\x67\xa3\x22\x11", "mov dword ptr [0x1122], eax");
    TEST64("\x67\xa3\x44\x33\x22\x11", "mov dword ptr [0x11223344], eax");
    TEST32("\x66\xa3\x44\x33\x22\x11", "mov word ptr [0x11223344], ax");
    TEST64("\x66\xa3\x88\x77\x66\x55\x44\x33\x22\x11", "mov word ptr [0x1122334455667788], ax");
    TEST32("\x66\x67\xa3\x22\x11", "mov word ptr [0x1122], ax");
    TEST64("\x66\x67\xa3\x44\x33\x22\x11", "mov word ptr [0x11223344], ax");
    TEST64("\x48\xa3\x88\x77\x66\x55\x44\x33\x22\x11", "mov qword ptr [0x1122334455667788], rax");
    TEST64("\x67\x48\xa3\x44\x33\x22\x11", "mov qword ptr [0x11223344], rax");
    TEST32("\xa0\x44\x33\x22", "PARTIAL");
    TEST64("\xa0\x88\x77\x66\x55\x44\x33\x22", "PARTIAL");
    TEST32("\x67\xa0\x22", "PARTIAL");
    TEST64("\x67\xa0\x44\x33\x22", "PARTIAL");

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
    TEST("\x6B\xC7\xff", "imul eax, edi, 0xffffffff");

    TEST("\x0f\x38\xf0\xd1", "UD"); // MOVBE doesn't allow register moves
    TEST("\x0f\x38\xf0\x11", "movbe edx, dword ptr [@cx]");
    TEST("\x66\x0f\x38\xf0\x11", "movbe dx, word ptr [@cx]");
    TEST64("\x48\x0f\x38\xf0\x01", "movbe rax, qword ptr [rcx]");
    TEST("\xf2\x0f\x38\xf0\xd1", "crc32 edx, cl");
    TEST("\xf2\x66\x0f\x38\xf1\xd1", "crc32 edx, cx");
    TEST("\xf2\x0f\x38\xf1\xd1", "crc32 edx, ecx");
    TEST64("\xf2\x48\x0f\x38\xf1\xd1", "crc32 edx, rcx");
    TEST64("\xf2\x4c\x0f\x38\xf1\xd1", "crc32 r10d, rcx");

    TEST("\x8d\x00", "lea eax, [@ax]");
    TEST("\x8d\xc0", "UD");

    TEST("\x00\xc0", "add al, al");
    TEST("\x00\xc1", "add cl, al");
    TEST("\x00\xd0", "add al, dl");
    TEST("\x00\xff", "add bh, bh");
    TEST("\x01\xc0", "add eax, eax");
    TEST("\x01\xc1", "add ecx, eax");
    TEST("\x01\xd0", "add eax, edx");
    TEST("\x01\xff", "add edi, edi");
    TEST("\x02\xc0", "add al, al");
    TEST("\x02\xc1", "add al, cl");
    TEST("\x02\xd0", "add dl, al");
    TEST("\x02\xff", "add bh, bh");
    TEST("\x03\xc0", "add eax, eax");
    TEST("\x03\xc1", "add eax, ecx");
    TEST("\x03\xd0", "add edx, eax");
    TEST("\x03\xff", "add edi, edi");
    TEST("\x05\x01\x00\x00\x80", "add eax, 0x80000001");
    TEST64("\x48\x05\x01\x00\x00\x80", "add rax, 0xffffffff80000001");

    TEST32("\x40", "inc eax");
    TEST32("\x43", "inc ebx");
    TEST32("\x66\x47", "inc di");
    TEST("\xfe\xc0", "inc al");
    TEST("\xfe\xc4", "inc ah");
    TEST("\xff\xc0", "inc eax");
    TEST("\xff\xc4", "inc esp");
    TEST("\xff\x00", "inc dword ptr [@ax]");
    TEST("\xf0\xff\x00", "lock inc dword ptr [@ax]");
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
    TEST("\xf3\xae", "rep scasb");
    TEST("\xf2\xae", "repnz scasb");
    TEST("\xf3\x66\xae", "rep scasb");
    TEST("\xf2\x66\xae", "repnz scasb");
    TEST("\xf3\xaf", "rep scasd");
    TEST("\xf2\xaf", "repnz scasd");
    TEST("\xf3\x66\xaf", "rep scasw");
    TEST("\xf2\x66\xaf", "repnz scasw");
    TEST64("\xf3\x48\xaf", "rep scasq");
    TEST64("\xf2\x48\xaf", "repnz scasq");
    TEST64("\xf3\x66\x48\xaf", "rep scasq");
    TEST64("\xf2\x66\x48\xaf", "repnz scasq");

    TEST("\x66\x0f\xbe\xc2", "movsx ax, dl");
    TEST("\x0f\xbe\xc2", "movsx eax, dl");
    TEST("\x0f\xbe\xc4", "movsx eax, ah");
    TEST64("\x40\x0f\xbe\xc4", "movsx eax, spl");
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
    TEST("\xca\x00\x00", "retfd 0x0");
    TEST("\xca\x0d\x00", "retfd 0xd");
    TEST("\xca\x0d\xff", "retfd 0xff0d");
    TEST("\xcb", "retfd");
    TEST("\x66\xca\x00\x00", "retfw 0x0");
    TEST("\x66\xca\x0d\x00", "retfw 0xd");
    TEST("\x66\xca\x0d\xff", "retfw 0xff0d");
    TEST("\x66\xcb", "retfw");
    TEST64("\x48\xca\x00\x00", "retfq 0x0");
    TEST64("\x48\xca\x0d\x00", "retfq 0xd");
    TEST64("\x48\xca\x0d\xff", "retfq 0xff0d");
    TEST64("\x48\xcb", "retfq");

    // BMI1
    TEST("\xf3\x0f\xbc\xc0", "tzcnt eax, eax");
    TEST("\x66\xf3\x0f\xbc\xc0", "tzcnt ax, ax");
    TEST64("\xf3\x48\x0f\xbc\xc0", "tzcnt rax, rax");
    TEST("\xf3\x0f\xbd\xc0", "lzcnt eax, eax");
    TEST("\x66\xf3\x0f\xbd\xc0", "lzcnt ax, ax");
    TEST64("\xf3\x48\x0f\xbd\xc0", "lzcnt rax, rax");
    TEST3264("\xc4\xc2\x18\xf2\xc7", "andn eax, esp, edi", "andn eax, r12d, r15d");
    TEST3264("\xc4\xc2\x98\xf2\xc7", "andn eax, esp, edi", "andn rax, r12, r15");
    TEST64("\xc4\x42\x18\xf2\xc7", "andn r8d, r12d, r15d");
    TEST64("\xc4\x42\x98\xf2\xc7", "andn r8, r12, r15");
    TEST("\xc4\xe2\x78\xf3\xca", "blsr eax, edx");
    TEST("\xc4\xe2\x78\xf3\x08", "blsr eax, dword ptr [@ax]");
    TEST("\xc4\xe2\xf8\xf3\xca", "blsr @ax, @dx");
    TEST3264("\xc4\xe2\xf8\xf3\x08", "blsr eax, dword ptr [eax]", "blsr rax, qword ptr [rax]");
    TEST3264("\xc4\xc2\x38\xf3\xc9", "blsr eax, ecx", "blsr r8d, r9d");
    TEST3264("\xc4\xc2\xb8\xf3\xc9", "blsr eax, ecx", "blsr r8, r9");
    TEST3264("\xc4\xe2\x38\xf3\xc9", "blsr eax, ecx", "blsr r8d, ecx");
    TEST3264("\xc4\xe2\xb8\xf3\xc9", "blsr eax, ecx", "blsr r8, rcx");
    TEST3264("\xc4\xc2\x78\xf3\xc9", "blsr eax, ecx", "blsr eax, r9d");
    TEST3264("\xc4\xc2\xf8\xf3\xc9", "blsr eax, ecx", "blsr rax, r9");
    TEST("\xc4\xe2\x78\xf3\xd2", "blsmsk eax, edx");
    TEST("\xc4\xe2\x78\xf3\x10", "blsmsk eax, dword ptr [@ax]");
    TEST("\xc4\xe2\xf8\xf3\xd2", "blsmsk @ax, @dx");
    TEST3264("\xc4\xe2\xf8\xf3\x10", "blsmsk eax, dword ptr [eax]", "blsmsk rax, qword ptr [rax]");
    TEST("\xc4\xe2\x78\xf3\xda", "blsi eax, edx");
    TEST("\xc4\xe2\x78\xf3\x18", "blsi eax, dword ptr [@ax]");
    TEST("\xc4\xe2\xf8\xf3\xda", "blsi @ax, @dx");
    TEST3264("\xc4\xe2\xf8\xf3\x18", "blsi eax, dword ptr [eax]", "blsi rax, qword ptr [rax]");
    TEST3264("\xc4\xc2\x18\xf7\xc7", "bextr eax, edi, esp", "bextr eax, r15d, r12d");
    TEST3264("\xc4\xc2\x98\xf7\xc7", "bextr eax, edi, esp", "bextr rax, r15, r12");
    TEST64("\xc4\x42\x18\xf7\xc7", "bextr r8d, r15d, r12d");
    TEST64("\xc4\x42\x98\xf7\xc7", "bextr r8, r15, r12");

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
    TEST("\x0f\x78\xc1", "vmread @cx, @ax");
    TEST("\x0f\x79\xc1", "vmwrite @ax, @cx");

    TEST64("\x0f\x09", "wbinvd");
    TEST64("\xf3\x0f\x09", "wbnoinvd");
    TEST("\x66\x0f\x38\x82\x01", "invpcid @ax, xmmword ptr [@cx]");
    TEST("\x66\x0f\x38\x80\x02", "invept @ax, xmmword ptr [@dx]");
    TEST("\x66\x0f\x38\x81\x02", "invvpid @ax, xmmword ptr [@dx]");
    TEST("\x66\x0f\x38\xf8\x01", "movdir64b @ax, zmmword ptr [@cx]");
    // TODO: MOVDIR64B first operand has address size.
    // TEST32("\x67\x66\x0f\x38\xf8\x01", "movdir64b ax, zmmword ptr [cx]");
    // TEST64("\x67\x66\x0f\x38\xf8\x01", "movdir64b eax, zmmword ptr [ecx]");
    TEST("\x0f\x30", "wrmsr");
    TEST("\x0f\x32", "rdmsr");
    TEST("\x0f\x01\xc6", "wrmsrns");
    TEST3264("\xf2\x0f\x01\xc6", "UD", "rdmsrlist");
    TEST3264("\xf3\x0f\x01\xc6", "UD", "wrmsrlist");
    TEST3264("\xc4\xe7\x7b\xf6\xc1\x10\x20\x30\x40", "UD", "rdmsr rcx, 0x40302010");
    TEST3264("\xc4\xe7\x7a\xf6\xc1\x10\x20\x30\x40", "UD", "wrmsrns 0x40302010, rcx");
    TEST3264("\xf2\x0f\x38\xf8\xc1", "UD", "urdmsr rcx, rax");
    TEST3264("\xf3\x0f\x38\xf8\xc1", "UD", "uwrmsr rcx, rax");
    TEST3264("\xc4\xe7\x7b\xf8\xc1\x10\x20\x30\x40", "UD", "urdmsr rcx, 0x40302010");
    TEST3264("\xc4\xe7\x7a\xf8\xc1\x10\x20\x30\x40", "UD", "uwrmsr 0x40302010, rcx");

    TEST("\x0f\x38\xfc\xc1", "UD"); // Must be memory operand
    TEST("\x0f\x38\xfc\x01", "aadd dword ptr [@cx], eax");
    TEST64("\x48\x0f\x38\xfc\x01", "aadd qword ptr [rcx], rax");
    TEST("\x66\x0f\x38\xfc\xc1", "UD"); // Must be memory operand
    TEST("\x66\x0f\x38\xfc\x01", "aand dword ptr [@cx], eax");
    TEST64("\x66\x48\x0f\x38\xfc\x01", "aand qword ptr [rcx], rax");
    TEST("\xf3\x0f\x38\xfc\xc1", "UD"); // Must be memory operand
    TEST("\xf3\x0f\x38\xfc\x01", "axor dword ptr [@cx], eax");
    TEST64("\xf3\x48\x0f\x38\xfc\x01", "axor qword ptr [rcx], rax");
    TEST("\xf2\x0f\x38\xfc\xc1", "UD"); // Must be memory operand
    TEST("\xf2\x0f\x38\xfc\x01", "aor dword ptr [@cx], eax");
    TEST64("\xf2\x48\x0f\x38\xfc\x01", "aor qword ptr [rcx], rax");

    TEST64("\xc4\xe2\x61\xe0\x08", "cmpoxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe0\x08", "cmpoxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe1\x08", "cmpnoxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe1\x08", "cmpnoxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe2\x08", "cmpbxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe2\x08", "cmpbxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe3\x08", "cmpnbxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe3\x08", "cmpnbxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe4\x08", "cmpzxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe4\x08", "cmpzxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe5\x08", "cmpnzxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe5\x08", "cmpnzxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe6\x08", "cmpbexadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe6\x08", "cmpbexadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe7\x08", "cmpnbexadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe7\x08", "cmpnbexadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe8\x08", "cmpsxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe8\x08", "cmpsxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xe9\x08", "cmpnsxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xe9\x08", "cmpnsxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xea\x08", "cmppxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xea\x08", "cmppxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xeb\x08", "cmpnpxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xeb\x08", "cmpnpxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xec\x08", "cmplxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xec\x08", "cmplxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xed\x08", "cmpnlxadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xed\x08", "cmpnlxadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xee\x08", "cmplexadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xee\x08", "cmplexadd qword ptr [rax], rcx, rbx");
    TEST64("\xc4\xe2\x61\xef\x08", "cmpnlexadd dword ptr [rax], ecx, ebx");
    TEST64("\xc4\xe2\xe1\xef\x08", "cmpnlexadd qword ptr [rax], rcx, rbx");

    TEST("\x0f\xae\xe8", "lfence");
    TEST("\x0f\xae\xe9", "lfence");
    TEST("\x0f\xae\xef", "lfence");
    TEST("\x0f\xae\xf0", "mfence");
    TEST("\x0f\xae\xf7", "mfence");
    TEST("\x0f\xae\xf8", "sfence");
    TEST("\x0f\xae\xf9", "sfence");
    TEST("\x0f\xae\xff", "sfence");

    TEST("\x0f\x6e\xc0", "movd mm0, eax");
    TEST64("\x48\x0f\x6e\xc0", "movq mm0, rax");
    TEST("\x0f\x70\xc0\x85", "pshufw mm0, mm0, 0x85");

    TEST("\x0f\x58\xc1", "addps xmm0, xmm1");
    TEST64("\x40\x0f\x58\xc1", "addps xmm0, xmm1");
    TEST64("\x41\x0f\x58\xc1", "addps xmm0, xmm9");
    TEST64("\x42\x0f\x58\xc1", "addps xmm0, xmm1"); // REX.X ignored
    TEST64("\x43\x0f\x58\xc1", "addps xmm0, xmm9"); // REX.X ignored
    TEST64("\x44\x0f\x58\xc1", "addps xmm8, xmm1");
    TEST64("\x45\x0f\x58\xc1", "addps xmm8, xmm9");
    TEST64("\x46\x0f\x58\xc1", "addps xmm8, xmm1"); // REX.X ignored
    TEST64("\x47\x0f\x58\xc1", "addps xmm8, xmm9"); // REX.X ignored
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
    TEST("\x66\x0f\x38\x20\xc1", "pmovsxbw xmm0, xmm1");
    TEST("\x66\x0f\x38\x20\x00", "pmovsxbw xmm0, qword ptr [@ax]");
    TEST("\x66\x0f\x38\x21\xc1", "pmovsxbd xmm0, xmm1");
    TEST("\x66\x0f\x38\x21\x00", "pmovsxbd xmm0, dword ptr [@ax]");
    TEST("\x66\x0f\x38\x22\xc1", "pmovsxbq xmm0, xmm1");
    TEST("\x66\x0f\x38\x22\x00", "pmovsxbq xmm0, word ptr [@ax]");
    TEST("\x66\x0f\x38\x23\xc1", "pmovsxwd xmm0, xmm1");
    TEST("\x66\x0f\x38\x23\x00", "pmovsxwd xmm0, qword ptr [@ax]");
    TEST("\x66\x0f\x38\x24\xc1", "pmovsxwq xmm0, xmm1");
    TEST("\x66\x0f\x38\x24\x00", "pmovsxwq xmm0, dword ptr [@ax]");
    TEST("\x66\x0f\x38\x25\xc1", "pmovsxdq xmm0, xmm1");
    TEST("\x66\x0f\x38\x25\x00", "pmovsxdq xmm0, qword ptr [@ax]");
    TEST("\x66\x0f\x38\x30\xc1", "pmovzxbw xmm0, xmm1");
    TEST("\x66\x0f\x38\x30\x00", "pmovzxbw xmm0, qword ptr [@ax]");
    TEST("\x66\x0f\x38\x31\xc1", "pmovzxbd xmm0, xmm1");
    TEST("\x66\x0f\x38\x31\x00", "pmovzxbd xmm0, dword ptr [@ax]");
    TEST("\x66\x0f\x38\x32\xc1", "pmovzxbq xmm0, xmm1");
    TEST("\x66\x0f\x38\x32\x00", "pmovzxbq xmm0, word ptr [@ax]");
    TEST("\x66\x0f\x38\x33\xc1", "pmovzxwd xmm0, xmm1");
    TEST("\x66\x0f\x38\x33\x00", "pmovzxwd xmm0, qword ptr [@ax]");
    TEST("\x66\x0f\x38\x34\xc1", "pmovzxwq xmm0, xmm1");
    TEST("\x66\x0f\x38\x34\x00", "pmovzxwq xmm0, dword ptr [@ax]");
    TEST("\x66\x0f\x38\x35\xc1", "pmovzxdq xmm0, xmm1");
    TEST("\x66\x0f\x38\x35\x00", "pmovzxdq xmm0, qword ptr [@ax]");

    TEST("\xc4", "PARTIAL");
    TEST("\xc5", "PARTIAL");
    TEST32("\xc4\xc0", "PARTIAL");
    TEST64("\xc4\x00", "PARTIAL");
    TEST32("\xc5\xc0", "PARTIAL");
    TEST64("\xc5\x00", "PARTIAL");
    TEST("\xc4\xe0\x78\x10\xc0", "UD"); // VEX map 0
    TEST("\xc4\xe1\x78\x10\xc0", "vmovups xmm0, xmm0"); // VEX map 1
    TEST("\xc4\xe2\x78\x10\xc0", "UD"); // VEX map 2
    TEST("\xc4\xe3\x78\x10\xc0\x00", "UD"); // VEX map 3
    TEST("\xc4\xe4\x78\x10\xc0", "UD"); // VEX map 4
    TEST("\xc4\xe5\x78\x10\xc0", "UD"); // VEX map 5
    TEST("\xc4\xe6\x78\x10\xc0", "UD"); // VEX map 6
    TEST("\xc4\xe7\x78\x10\xc0", "UD"); // VEX map 7
    TEST("\xc4\xe8\x78\x10\xc0", "UD"); // VEX map 8
    TEST("\xc4\xe9\x78\x10\xc0", "UD"); // VEX map 9
    TEST("\xc4\xea\x78\x10\xc0", "UD"); // VEX map 10
    TEST("\xc4\xeb\x78\x10\xc0", "UD"); // VEX map 11
    TEST("\xc4\xec\x78\x10\xc0", "UD"); // VEX map 12
    TEST("\xc4\xed\x78\x10\xc0", "UD"); // VEX map 13
    TEST("\xc4\xee\x78\x10\xc0", "UD"); // VEX map 14
    TEST("\xc4\xef\x78\x10\xc0", "UD"); // VEX map 15
    TEST("\xc4\xf0\x78\x10\xc0", "UD"); // VEX map 16
    TEST("\xc4\xf1\x78\x10\xc0", "UD"); // VEX map 17
    TEST("\xc4\xf2\x78\x10\xc0", "UD"); // VEX map 18
    TEST("\xc4\xf3\x78\x10\xc0", "UD"); // VEX map 19
    TEST("\xc4\xf4\x78\x10\xc0", "UD"); // VEX map 20
    TEST("\xc4\xf5\x78\x10\xc0", "UD"); // VEX map 21
    TEST("\xc4\xf6\x78\x10\xc0", "UD"); // VEX map 22
    TEST("\xc4\xf7\x78\x10\xc0", "UD"); // VEX map 23
    TEST("\xc4\xf8\x78\x10\xc0", "UD"); // VEX map 24
    TEST("\xc4\xf9\x78\x10\xc0", "UD"); // VEX map 25
    TEST("\xc4\xfa\x78\x10\xc0", "UD"); // VEX map 26
    TEST("\xc4\xfb\x78\x10\xc0", "UD"); // VEX map 27
    TEST("\xc4\xfc\x78\x10\xc0", "UD"); // VEX map 28
    TEST("\xc4\xfd\x78\x10\xc0", "UD"); // VEX map 29
    TEST("\xc4\xfe\x78\x10\xc0", "UD"); // VEX map 30
    TEST("\xc4\xff\x78\x10\xc0", "UD"); // VEX map 31
    TEST32("\xc4\x00", "les eax, fword ptr [eax]");
    TEST32("\xc5\x00", "lds eax, fword ptr [eax]");
    TEST("\x0f\xb2\x00", "lss eax, fword ptr [@ax]");
    TEST64("\x48\x0f\xb2\x00", "lss rax, tbyte ptr [rax]");
    TEST("\x0f\xb4\x00", "lfs eax, fword ptr [@ax]");
    TEST64("\x48\x0f\xb4\x00", "lfs rax, tbyte ptr [rax]");
    TEST("\x0f\xb5\x00", "lgs eax, fword ptr [@ax]");
    TEST64("\x48\x0f\xb5\x00", "lgs rax, tbyte ptr [rax]");
    TEST("\xc5\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, eax");
    TEST("\xc4\xe1\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, @ax"); // VEX.W ignored
    TEST("\xf3\xc5\xf2\x2a\xc0", "UD"); // VEX+REP
    TEST("\xf2\xc5\xf2\x2a\xc0", "UD"); // VEX+REPNZ
    TEST("\xf2\xf3\xc5\xf2\x2a\xc0", "UD"); // VEX+REP+REPNZ
    TEST("\x66\xc5\xf2\x2a\xc0", "UD"); // VEX+66
    TEST("\xf0\xc5\xf2\x2a\xc0", "UD"); // VEX+LOCK
    TEST64("\x40\xc5\xf2\x2a\xc0", "UD"); // VEX+REX
    TEST64("\x40\x26\xc5\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, eax"); // VEX+REX, but REX doesn't precede VEX

    TEST("\xd9\x00", "fld dword ptr [@ax]");
    TEST("\xdd\x00", "fld qword ptr [@ax]");
    TEST("\xdb\x28", "fld tbyte ptr [@ax]");
    TEST("\xd9\xc1", "fld st(1)");
    TEST("\xdf\xe9", "fucomip st(0), st(1)");
    TEST64("\x45\xdf\xe9", "fucomip st(0), st(1)"); // REX.RB are ignored.

    TEST("\xf3\x0f\x7e\x5c\x24\x08", "movq xmm3, qword ptr [@sp+0x8]");
    TEST3264("\xc4\xe1\x00\x58\xc1", "vaddps xmm0, xmm7, xmm1", "vaddps xmm0, xmm15, xmm1"); // MSB in vvvv ignored
    TEST3264("\xc4\xc1\x78\x58\xc0", "vaddps xmm0, xmm0, xmm0", "vaddps xmm0, xmm0, xmm8"); // VEX.B ignored in 32-bit
    TEST("\xc5\xf9\x6e\xc8", "vmovd xmm1, eax");
    TEST64("\xc4\xe1\xf9\x6e\xc8", "vmovq xmm1, rax");
    TEST32("\xc4\xe1\xf9\x6e\xc8", "vmovd xmm1, eax");
    TEST("\xc5\xf9\x7e\xc8", "vmovd eax, xmm1");
    TEST64("\xc4\xe1\xf9\x7e\xc8", "vmovq rax, xmm1");
    TEST32("\xc4\xe1\xf9\x7e\xc8", "vmovd eax, xmm1");
    TEST("\xc5\xf2\x10\xc2", "vmovss xmm0, xmm1, xmm2");
    TEST("\xc5\xf6\x10\xc2", "vmovss xmm0, xmm1, xmm2"); // VEX.L=1
    TEST("\xc5\xfa\x10\x04\x25\x34\x12\x00\x00", "vmovss xmm0, dword ptr [0x1234]");
    TEST("\xc5\xf2\x10\x04\x25\x34\x12\x00\x00", "UD"); // VEX.vvvv != 0
    TEST("\xc5\xfa\x11\x04\x25\x34\x12\x00\x00", "vmovss dword ptr [0x1234], xmm0");
    TEST("\xc5\xf2\x11\x04\x25\x34\x12\x00\x00", "UD"); // VEX.vvvv != 0
    TEST("\xc5\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, eax");
    TEST("\xc4\xe1\xf2\x2a\xc0", "vcvtsi2ss xmm0, xmm1, @ax");
    TEST("\xc5\xf8\x53\xc0", "vrcpps xmm0, xmm0");
    TEST("\xc5\xf9\xf7\xc1", "vmaskmovdqu xmm0, xmm1");
    TEST("\xc5\xf9\xf7\x00", "UD"); // must have memory operand
    TEST("\xc5\xfd\xf7\xc1", "UD"); // VEX.L != 0
    TEST64("\xc5\x07\xd0\x02", "vaddsubps ymm8, ymm15, ymmword ptr [rdx]");
    TEST("\xc4\xc3\x6d\x09\xd9\x85", "UD"); // VEX.vvvv != 0
    TEST3264("\xc4\xc3\x7d\x09\xd9\x85", "vroundpd ymm3, ymm1, 0x85", "vroundpd ymm3, ymm9, 0x85");
    TEST("\xc5\xff\xf0\xd1", "UD"); // must have memory operand
    TEST("\xc5\xff\xf0\x11", "vlddqu ymm2, ymmword ptr [@cx]");

    // VMOVDDUP with L0 has smaller second operand size.
    TEST("\xf2\x0f\x12\x08", "movddup xmm1, qword ptr [@ax]");
    TEST("\xf2\x0f\x12\xc8", "movddup xmm1, xmm0");
    TEST("\xc5\xfb\x12\x08", "vmovddup xmm1, qword ptr [@ax]");
    TEST("\xc5\xfb\x12\xc8", "vmovddup xmm1, xmm0");
    TEST("\xc5\xff\x12\x08", "vmovddup ymm1, ymmword ptr [@ax]");
    TEST("\xc5\xff\x12\xc8", "vmovddup ymm1, ymm0");

    TEST("\xc5\xf1\xe1\xc2", "vpsraw xmm0, xmm1, xmm2");
    TEST("\xc5\xf1\xe1\x00", "vpsraw xmm0, xmm1, xmmword ptr [@ax]");
    TEST("\xc5\xf5\xe1\xc2", "vpsraw ymm0, ymm1, xmm2");
    TEST("\xc5\xf5\xe1\x00", "vpsraw ymm0, ymm1, xmmword ptr [@ax]");
    TEST("\xc5\xf1\xe2\xc2", "vpsrad xmm0, xmm1, xmm2");
    TEST("\xc5\xf1\xe2\x00", "vpsrad xmm0, xmm1, xmmword ptr [@ax]");
    TEST("\xc5\xf5\xe2\xc2", "vpsrad ymm0, ymm1, xmm2");
    TEST("\xc5\xf5\xe2\x00", "vpsrad ymm0, ymm1, xmmword ptr [@ax]");
    TEST("\xc5\xf1\xd1\xc2", "vpsrlw xmm0, xmm1, xmm2");
    TEST("\xc5\xf1\xd1\x00", "vpsrlw xmm0, xmm1, xmmword ptr [@ax]");
    TEST("\xc5\xf5\xd1\xc2", "vpsrlw ymm0, ymm1, xmm2");
    TEST("\xc5\xf5\xd1\x00", "vpsrlw ymm0, ymm1, xmmword ptr [@ax]");
    TEST("\xc5\xf1\xd2\xc2", "vpsrld xmm0, xmm1, xmm2");
    TEST("\xc5\xf1\xd2\x00", "vpsrld xmm0, xmm1, xmmword ptr [@ax]");
    TEST("\xc5\xf5\xd2\xc2", "vpsrld ymm0, ymm1, xmm2");
    TEST("\xc5\xf5\xd2\x00", "vpsrld ymm0, ymm1, xmmword ptr [@ax]");
    TEST("\xc5\xf1\xd3\xc2", "vpsrlq xmm0, xmm1, xmm2");
    TEST("\xc5\xf1\xd3\x00", "vpsrlq xmm0, xmm1, xmmword ptr [@ax]");
    TEST("\xc5\xf5\xd3\xc2", "vpsrlq ymm0, ymm1, xmm2");
    TEST("\xc5\xf5\xd3\x00", "vpsrlq ymm0, ymm1, xmmword ptr [@ax]");
    TEST("\xc5\xf1\xf1\xc2", "vpsllw xmm0, xmm1, xmm2");
    TEST("\xc5\xf1\xf1\x00", "vpsllw xmm0, xmm1, xmmword ptr [@ax]");
    TEST("\xc5\xf5\xf1\xc2", "vpsllw ymm0, ymm1, xmm2");
    TEST("\xc5\xf5\xf1\x00", "vpsllw ymm0, ymm1, xmmword ptr [@ax]");
    TEST("\xc5\xf1\xf2\xc2", "vpslld xmm0, xmm1, xmm2");
    TEST("\xc5\xf1\xf2\x00", "vpslld xmm0, xmm1, xmmword ptr [@ax]");
    TEST("\xc5\xf5\xf2\xc2", "vpslld ymm0, ymm1, xmm2");
    TEST("\xc5\xf5\xf2\x00", "vpslld ymm0, ymm1, xmmword ptr [@ax]");
    TEST("\xc5\xf1\xf3\xc2", "vpsllq xmm0, xmm1, xmm2");
    TEST("\xc5\xf1\xf3\x00", "vpsllq xmm0, xmm1, xmmword ptr [@ax]");
    TEST("\xc5\xf5\xf3\xc2", "vpsllq ymm0, ymm1, xmm2");
    TEST("\xc5\xf5\xf3\x00", "vpsllq ymm0, ymm1, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x71\x47\xc2", "vpsllvd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x47\xc2", "vpsllvq xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x45\xc2", "vpsrlvd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x45\xc2", "vpsrlvq xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x46\xc2", "vpsravd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x46\xc2", "UD"); // VEX-encoded VPSRAVQ doesn't exist

    TEST("\xc4\xe3\x79\x14\xc0\x00", "vpextrb eax, xmm0, 0x0");
    TEST("\xc4\xe3\xf9\x14\xc0\x00", "vpextrb eax, xmm0, 0x0");
    TEST("\xc4\xe3\x79\x15\xc0\x00", "vpextrw eax, xmm0, 0x0");
    TEST("\xc4\xe3\xf9\x15\xc0\x00", "vpextrw eax, xmm0, 0x0");
    TEST("\xc4\xe1\x79\xc5\xc0\x00", "vpextrw eax, xmm0, 0x0");
    TEST("\xc4\xe3\x79\x16\xc0\x00", "vpextrd eax, xmm0, 0x0");
    TEST3264("\xc4\xe3\xf9\x16\xc0\x00", "vpextrd eax, xmm0, 0x0", "vpextrq rax, xmm0, 0x0");

    TEST("\xc4\xe3\x71\x20\xc0\x00", "vpinsrb xmm0, xmm1, al, 0x0");
    TEST("\xc4\xe3\xf1\x20\xc0\x00", "vpinsrb xmm0, xmm1, al, 0x0");
    TEST("\xc4\xe3\x71\x20\xc6\x00", "vpinsrb xmm0, xmm1, sil, 0x0");
    TEST("\xc4\xe1\x71\xc4\xc0\x00", "vpinsrw xmm0, xmm1, ax, 0x0");
    TEST("\xc4\xe1\xf1\xc4\xc0\x00", "vpinsrw xmm0, xmm1, ax, 0x0");
    TEST("\xc4\xe3\x71\x22\xc0\x00", "vpinsrd xmm0, xmm1, eax, 0x0");
    TEST3264("\xc4\xe3\xf1\x22\xc0\x00", "vpinsrd xmm0, xmm1, eax, 0x0", "vpinsrq xmm0, xmm1, rax, 0x0");
    TEST("\xc4\xe3\x75\x20\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe1\x75\xc4\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe1\xf5\xc4\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe3\x75\x22\xc0\x00", "UD"); // VEX.L != 0
    TEST("\xc4\xe3\xf5\x22\xc0\x00", "UD"); // VEX.L != 0

    TEST("\xc5\xf1\x71\xd7\x02", "vpsrlw xmm1, xmm7, 0x2");
    TEST("\xc5\xf5\x71\xd7\x02", "vpsrlw ymm1, ymm7, 0x2");
    TEST("\xc5\xf5\x71\x00\x02", "UD"); // Must have register operand
    TEST("\xc4\xe2\x71\x45\xc2", "vpsrlvd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\x45\xc2", "vpsrlvd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf1\x45\xc2", "vpsrlvq xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf5\x45\xc2", "vpsrlvq ymm0, ymm1, ymm2");

    TEST("\xc4\xe2\x79\x20\xc1", "vpmovsxbw xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x20\xc1", "vpmovsxbw ymm0, xmm1");
    TEST("\xc4\xe2\x79\x20\x00", "vpmovsxbw xmm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x20\x00", "vpmovsxbw ymm0, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x79\x21\xc1", "vpmovsxbd xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x21\xc1", "vpmovsxbd ymm0, xmm1");
    TEST("\xc4\xe2\x79\x21\x00", "vpmovsxbd xmm0, dword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x21\x00", "vpmovsxbd ymm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x79\x22\xc1", "vpmovsxbq xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x22\xc1", "vpmovsxbq ymm0, xmm1");
    TEST("\xc4\xe2\x79\x22\x00", "vpmovsxbq xmm0, word ptr [@ax]");
    TEST("\xc4\xe2\x7d\x22\x00", "vpmovsxbq ymm0, dword ptr [@ax]");
    TEST("\xc4\xe2\x79\x23\xc1", "vpmovsxwd xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x23\xc1", "vpmovsxwd ymm0, xmm1");
    TEST("\xc4\xe2\x79\x23\x00", "vpmovsxwd xmm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x23\x00", "vpmovsxwd ymm0, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x79\x24\xc1", "vpmovsxwq xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x24\xc1", "vpmovsxwq ymm0, xmm1");
    TEST("\xc4\xe2\x79\x24\x00", "vpmovsxwq xmm0, dword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x24\x00", "vpmovsxwq ymm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x79\x25\xc1", "vpmovsxdq xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x25\xc1", "vpmovsxdq ymm0, xmm1");
    TEST("\xc4\xe2\x79\x25\x00", "vpmovsxdq xmm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x25\x00", "vpmovsxdq ymm0, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x79\x30\xc1", "vpmovzxbw xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x30\xc1", "vpmovzxbw ymm0, xmm1");
    TEST("\xc4\xe2\x79\x30\x00", "vpmovzxbw xmm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x30\x00", "vpmovzxbw ymm0, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x79\x31\xc1", "vpmovzxbd xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x31\xc1", "vpmovzxbd ymm0, xmm1");
    TEST("\xc4\xe2\x79\x31\x00", "vpmovzxbd xmm0, dword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x31\x00", "vpmovzxbd ymm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x79\x32\xc1", "vpmovzxbq xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x32\xc1", "vpmovzxbq ymm0, xmm1");
    TEST("\xc4\xe2\x79\x32\x00", "vpmovzxbq xmm0, word ptr [@ax]");
    TEST("\xc4\xe2\x7d\x32\x00", "vpmovzxbq ymm0, dword ptr [@ax]");
    TEST("\xc4\xe2\x79\x33\xc1", "vpmovzxwd xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x33\xc1", "vpmovzxwd ymm0, xmm1");
    TEST("\xc4\xe2\x79\x33\x00", "vpmovzxwd xmm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x33\x00", "vpmovzxwd ymm0, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x79\x34\xc1", "vpmovzxwq xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x34\xc1", "vpmovzxwq ymm0, xmm1");
    TEST("\xc4\xe2\x79\x34\x00", "vpmovzxwq xmm0, dword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x34\x00", "vpmovzxwq ymm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x79\x35\xc1", "vpmovzxdq xmm0, xmm1");
    TEST("\xc4\xe2\x7d\x35\xc1", "vpmovzxdq ymm0, xmm1");
    TEST("\xc4\xe2\x79\x35\x00", "vpmovzxdq xmm0, qword ptr [@ax]");
    TEST("\xc4\xe2\x7d\x35\x00", "vpmovzxdq ymm0, xmmword ptr [@ax]");

    TEST("\xc4\xe3\x71\x4a\xc2", "PARTIAL");
    TEST("\xc4\xe3\x71\x4a\xc2\x30", "vblendvps xmm0, xmm1, xmm2, xmm3");
    TEST3264("\xc4\xe3\x75\x4a\xc2\xf0", "vblendvps ymm0, ymm1, ymm2, ymm7", "vblendvps ymm0, ymm1, ymm2, ymm15"); // Bit 7 is ignored
    TEST("\xc4\xe3\x71\x4b\xc2\x70", "vblendvpd xmm0, xmm1, xmm2, xmm7");
    TEST3264("\xc4\xe3\x75\x4b\xc2\x80", "vblendvpd ymm0, ymm1, ymm2, ymm0", "vblendvpd ymm0, ymm1, ymm2, ymm8"); // Bit 7 is ignored
    TEST3264("\xc4\xc3\xfd\x00\xc9\x12", "vpermq ymm1, ymm1, 0x12", "vpermq ymm1, ymm9, 0x12"); // VEX.B ignored
    TEST("\xc4\xc3\x7d\x00\xc9\x12", "UD"); // VEX.W = 0 is UD
    TEST("\xc4\xe3\xfd\x01\xcf\x12", "vpermpd ymm1, ymm7, 0x12");

    TEST("\xc4\xe2\x71\x96\xc2", "vfmaddsub132ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x96\x06", "vfmaddsub132ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\x96\xc2", "vfmaddsub132ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\x96\x06", "vfmaddsub132ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\x96\xc2", "vfmaddsub132pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x96\x06", "vfmaddsub132pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\x96\xc2", "vfmaddsub132pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\x96\x06", "vfmaddsub132pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\x97\xc2", "vfmsubadd132ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x97\x06", "vfmsubadd132ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\x97\xc2", "vfmsubadd132ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\x97\x06", "vfmsubadd132ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\x97\xc2", "vfmsubadd132pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x97\x06", "vfmsubadd132pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\x97\xc2", "vfmsubadd132pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\x97\x06", "vfmsubadd132pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\x98\xc2", "vfmadd132ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x98\x06", "vfmadd132ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\x98\xc2", "vfmadd132ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\x98\x06", "vfmadd132ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\x98\xc2", "vfmadd132pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x98\x06", "vfmadd132pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\x98\xc2", "vfmadd132pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\x98\x06", "vfmadd132pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\x99\xc2", "vfmadd132ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x99\x06", "vfmadd132ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\x99\xc2", "vfmadd132sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x99\x06", "vfmadd132sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\x9a\xc2", "vfmsub132ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x9a\x06", "vfmsub132ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\x9a\xc2", "vfmsub132ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\x9a\x06", "vfmsub132ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\x9a\xc2", "vfmsub132pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x9a\x06", "vfmsub132pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\x9a\xc2", "vfmsub132pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\x9a\x06", "vfmsub132pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\x9b\xc2", "vfmsub132ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x9b\x06", "vfmsub132ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\x9b\xc2", "vfmsub132sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x9b\x06", "vfmsub132sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\x9c\xc2", "vfnmadd132ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x9c\x06", "vfnmadd132ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\x9c\xc2", "vfnmadd132ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\x9c\x06", "vfnmadd132ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\x9c\xc2", "vfnmadd132pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x9c\x06", "vfnmadd132pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\x9c\xc2", "vfnmadd132pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\x9c\x06", "vfnmadd132pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\x9d\xc2", "vfnmadd132ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x9d\x06", "vfnmadd132ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\x9d\xc2", "vfnmadd132sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x9d\x06", "vfnmadd132sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\x9e\xc2", "vfnmsub132ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x9e\x06", "vfnmsub132ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\x9e\xc2", "vfnmsub132ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\x9e\x06", "vfnmsub132ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\x9e\xc2", "vfnmsub132pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x9e\x06", "vfnmsub132pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\x9e\xc2", "vfnmsub132pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\x9e\x06", "vfnmsub132pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\x9f\xc2", "vfnmsub132ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\x9f\x06", "vfnmsub132ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\x9f\xc2", "vfnmsub132sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\x9f\x06", "vfnmsub132sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\xa6\xc2", "vfmaddsub213ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xa6\x06", "vfmaddsub213ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xa6\xc2", "vfmaddsub213ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xa6\x06", "vfmaddsub213ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xa6\xc2", "vfmaddsub213pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xa6\x06", "vfmaddsub213pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xa6\xc2", "vfmaddsub213pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xa6\x06", "vfmaddsub213pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xa7\xc2", "vfmsubadd213ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xa7\x06", "vfmsubadd213ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xa7\xc2", "vfmsubadd213ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xa7\x06", "vfmsubadd213ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xa7\xc2", "vfmsubadd213pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xa7\x06", "vfmsubadd213pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xa7\xc2", "vfmsubadd213pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xa7\x06", "vfmsubadd213pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xa8\xc2", "vfmadd213ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xa8\x06", "vfmadd213ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xa8\xc2", "vfmadd213ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xa8\x06", "vfmadd213ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xa8\xc2", "vfmadd213pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xa8\x06", "vfmadd213pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xa8\xc2", "vfmadd213pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xa8\x06", "vfmadd213pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xa9\xc2", "vfmadd213ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xa9\x06", "vfmadd213ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\xa9\xc2", "vfmadd213sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xa9\x06", "vfmadd213sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\xaa\xc2", "vfmsub213ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xaa\x06", "vfmsub213ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xaa\xc2", "vfmsub213ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xaa\x06", "vfmsub213ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xaa\xc2", "vfmsub213pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xaa\x06", "vfmsub213pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xaa\xc2", "vfmsub213pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xaa\x06", "vfmsub213pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xab\xc2", "vfmsub213ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xab\x06", "vfmsub213ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\xab\xc2", "vfmsub213sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xab\x06", "vfmsub213sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\xac\xc2", "vfnmadd213ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xac\x06", "vfnmadd213ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xac\xc2", "vfnmadd213ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xac\x06", "vfnmadd213ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xac\xc2", "vfnmadd213pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xac\x06", "vfnmadd213pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xac\xc2", "vfnmadd213pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xac\x06", "vfnmadd213pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xad\xc2", "vfnmadd213ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xad\x06", "vfnmadd213ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\xad\xc2", "vfnmadd213sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xad\x06", "vfnmadd213sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\xae\xc2", "vfnmsub213ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xae\x06", "vfnmsub213ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xae\xc2", "vfnmsub213ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xae\x06", "vfnmsub213ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xae\xc2", "vfnmsub213pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xae\x06", "vfnmsub213pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xae\xc2", "vfnmsub213pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xae\x06", "vfnmsub213pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xaf\xc2", "vfnmsub213ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xaf\x06", "vfnmsub213ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\xaf\xc2", "vfnmsub213sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xaf\x06", "vfnmsub213sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\xb6\xc2", "vfmaddsub231ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xb6\x06", "vfmaddsub231ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xb6\xc2", "vfmaddsub231ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xb6\x06", "vfmaddsub231ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xb6\xc2", "vfmaddsub231pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xb6\x06", "vfmaddsub231pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xb6\xc2", "vfmaddsub231pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xb6\x06", "vfmaddsub231pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xb7\xc2", "vfmsubadd231ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xb7\x06", "vfmsubadd231ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xb7\xc2", "vfmsubadd231ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xb7\x06", "vfmsubadd231ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xb7\xc2", "vfmsubadd231pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xb7\x06", "vfmsubadd231pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xb7\xc2", "vfmsubadd231pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xb7\x06", "vfmsubadd231pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xb8\xc2", "vfmadd231ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xb8\x06", "vfmadd231ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xb8\xc2", "vfmadd231ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xb8\x06", "vfmadd231ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xb8\xc2", "vfmadd231pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xb8\x06", "vfmadd231pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xb8\xc2", "vfmadd231pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xb8\x06", "vfmadd231pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xb9\xc2", "vfmadd231ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xb9\x06", "vfmadd231ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\xb9\xc2", "vfmadd231sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xb9\x06", "vfmadd231sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\xba\xc2", "vfmsub231ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xba\x06", "vfmsub231ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xba\xc2", "vfmsub231ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xba\x06", "vfmsub231ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xba\xc2", "vfmsub231pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xba\x06", "vfmsub231pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xba\xc2", "vfmsub231pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xba\x06", "vfmsub231pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xbb\xc2", "vfmsub231ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xbb\x06", "vfmsub231ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\xbb\xc2", "vfmsub231sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xbb\x06", "vfmsub231sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\xbc\xc2", "vfnmadd231ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xbc\x06", "vfnmadd231ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xbc\xc2", "vfnmadd231ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xbc\x06", "vfnmadd231ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xbc\xc2", "vfnmadd231pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xbc\x06", "vfnmadd231pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xbc\xc2", "vfnmadd231pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xbc\x06", "vfnmadd231pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xbd\xc2", "vfnmadd231ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xbd\x06", "vfnmadd231ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\xbd\xc2", "vfnmadd231sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xbd\x06", "vfnmadd231sd xmm0, xmm1, qword ptr [@si]");
    TEST("\xc4\xe2\x71\xbe\xc2", "vfnmsub231ps xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xbe\x06", "vfnmsub231ps xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\x75\xbe\xc2", "vfnmsub231ps ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x75\xbe\x06", "vfnmsub231ps ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\xf1\xbe\xc2", "vfnmsub231pd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xbe\x06", "vfnmsub231pd xmm0, xmm1, xmmword ptr [@si]");
    TEST("\xc4\xe2\xf5\xbe\xc2", "vfnmsub231pd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf5\xbe\x06", "vfnmsub231pd ymm0, ymm1, ymmword ptr [@si]");
    TEST("\xc4\xe2\x71\xbf\xc2", "vfnmsub231ss xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x71\xbf\x06", "vfnmsub231ss xmm0, xmm1, dword ptr [@si]");
    TEST("\xc4\xe2\xf1\xbf\xc2", "vfnmsub231sd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf1\xbf\x06", "vfnmsub231sd xmm0, xmm1, qword ptr [@si]");

    TEST("\xc4\xe2\x79\xdb\xc1", "vaesimc xmm0, xmm1");
    TEST("\xc4\xe2\x7d\xdb\xc1", "UD"); // VEX.L != 0
    TEST("\xc4\xe3\x79\xdf\xc1\xae", "vaeskeygenassist xmm0, xmm1, 0xae");
    TEST("\xc4\xe3\x7d\xdf\xc1\xae", "UD"); // VEX.L != 0
    TEST("\xc4\xe2\x71\xdc\xc2", "vaesenc xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\xdc\xc2", "vaesenc ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x71\xdd\xc2", "vaesenclast xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\xdd\xc2", "vaesenclast ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x71\xde\xc2", "vaesdec xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\xde\xc2", "vaesdec ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x71\xdf\xc2", "vaesdeclast xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\xdf\xc2", "vaesdeclast ymm0, ymm1, ymm2");

    TEST("\xc4\xe2\x70\x50\xc2", "vpdpbuud xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x74\x50\xc2", "vpdpbuud ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x71\x50\xc2", "vpdpbusd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\x50\xc2", "vpdpbusd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x72\x50\xc2", "vpdpbsud xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x76\x50\xc2", "vpdpbsud ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x73\x50\xc2", "vpdpbssd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x77\x50\xc2", "vpdpbssd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x70\x51\xc2", "vpdpbuuds xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x74\x51\xc2", "vpdpbuuds ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x71\x51\xc2", "vpdpbusds xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\x51\xc2", "vpdpbusds ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x72\x51\xc2", "vpdpbsuds xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x76\x51\xc2", "vpdpbsuds ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x73\x51\xc2", "vpdpbssds xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x77\x51\xc2", "vpdpbssds ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x71\x52\xc2", "vpdpwssd xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\x52\xc2", "vpdpwssd ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\x71\x53\xc2", "vpdpwssds xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\x75\x53\xc2", "vpdpwssds ymm0, ymm1, ymm2");

    TEST("\xc4\xe2\x78\xb0\xc8", "UD"); // Must have memory operand
    TEST("\xc4\xe2\x78\xb0\x08", "vcvtneoph2ps xmm1, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x7c\xb0\x08", "vcvtneoph2ps ymm1, ymmword ptr [@ax]");
    TEST("\xc4\xe2\x79\xb0\xc8", "UD"); // Must have memory operand
    TEST("\xc4\xe2\x79\xb0\x08", "vcvtneeph2ps xmm1, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x7d\xb0\x08", "vcvtneeph2ps ymm1, ymmword ptr [@ax]");
    TEST("\xc4\xe2\x7a\xb0\xc8", "UD"); // Must have memory operand
    TEST("\xc4\xe2\x7a\xb0\x08", "vcvtneebf162ps xmm1, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x7e\xb0\x08", "vcvtneebf162ps ymm1, ymmword ptr [@ax]");
    TEST("\xc4\xe2\x7b\xb0\xc8", "UD"); // Must have memory operand
    TEST("\xc4\xe2\x7b\xb0\x08", "vcvtneobf162ps xmm1, xmmword ptr [@ax]");
    TEST("\xc4\xe2\x7f\xb0\x08", "vcvtneobf162ps ymm1, ymmword ptr [@ax]");
    TEST("\xc4\xe2\x79\xb1\xc8", "UD"); // Must have memory operand
    TEST("\xc4\xe2\x79\xb1\x08", "vbcstnesh2ps xmm1, word ptr [@ax]");
    TEST("\xc4\xe2\x7d\xb1\x08", "vbcstnesh2ps ymm1, word ptr [@ax]");
    TEST("\xc4\xe2\x7a\xb1\xc8", "UD"); // Must have memory operand
    TEST("\xc4\xe2\x7a\xb1\x08", "vbcstnebf162ps xmm1, word ptr [@ax]");
    TEST("\xc4\xe2\x7e\xb1\x08", "vbcstnebf162ps ymm1, word ptr [@ax]");
    TEST("\xc4\xe2\x7a\x72\xc1", "vcvtneps2bf16 xmm0, xmm1");
    TEST("\xc4\xe2\x7e\x72\xc1", "vcvtneps2bf16 xmm0, ymm1");

    TEST("\xc4\xe2\xf1\xb4\xc2", "vpmadd52luq xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf5\xb4\xc2", "vpmadd52luq ymm0, ymm1, ymm2");
    TEST("\xc4\xe2\xf1\xb5\xc2", "vpmadd52huq xmm0, xmm1, xmm2");
    TEST("\xc4\xe2\xf5\xb5\xc2", "vpmadd52huq ymm0, ymm1, ymm2");

    TEST("\xc4\xe2\x71\x92\xc0", "UD"); // Must have memory operand
    TEST("\xc4\xe2\x71\x92\x00", "UD"); // Must have SIB byte
    TEST("\xc4\xe2\x71\x92\x05\x00\x00\x00\x00", "UD"); // Must have SIB byte
    TEST3264("\x67\xc4\xe2\x71\x92\x04\xe7", "UD", "vgatherdps xmm0, dword ptr [edi+8*xmm4], xmm1"); // VSIB + 16-bit addrsize is UD
    TEST("\xc4\xe2\x71\x92\x04\xe7", "vgatherdps xmm0, dword ptr [@di+8*xmm4], xmm1");
    TEST("\xc4\xe2\x75\x92\x04\xe7", "vgatherdps ymm0, dword ptr [@di+8*ymm4], ymm1");
    TEST("\xc4\xe2\x71\x93\x04\xe7", "vgatherqps xmm0, dword ptr [@di+8*xmm4], xmm1");
    TEST("\xc4\xe2\x75\x93\x04\xe7", "vgatherqps xmm0, dword ptr [@di+8*ymm4], xmm1");
    TEST("\xc4\xe2\xf1\x92\x04\xe7", "vgatherdpd xmm0, qword ptr [@di+8*xmm4], xmm1");
    TEST("\xc4\xe2\xf5\x92\x04\xe7", "vgatherdpd ymm0, qword ptr [@di+8*xmm4], ymm1");
    TEST("\xc4\xe2\xf1\x93\x04\xe7", "vgatherqpd xmm0, qword ptr [@di+8*xmm4], xmm1");
    TEST("\xc4\xe2\xf5\x93\x04\xe7", "vgatherqpd ymm0, qword ptr [@di+8*ymm4], ymm1");
    TEST("\xc4\xe2\x71\x90\x04\xe7", "vpgatherdd xmm0, dword ptr [@di+8*xmm4], xmm1");
    TEST("\xc4\xe2\x75\x90\x04\xe7", "vpgatherdd ymm0, dword ptr [@di+8*ymm4], ymm1");
    TEST("\xc4\xe2\x71\x91\x04\xe7", "vpgatherqd xmm0, dword ptr [@di+8*xmm4], xmm1");
    TEST("\xc4\xe2\x75\x91\x04\xe7", "vpgatherqd xmm0, dword ptr [@di+8*ymm4], xmm1");
    TEST("\xc4\xe2\xf1\x90\x04\xe7", "vpgatherdq xmm0, qword ptr [@di+8*xmm4], xmm1");
    TEST("\xc4\xe2\xf5\x90\x04\xe7", "vpgatherdq ymm0, qword ptr [@di+8*xmm4], ymm1");
    TEST("\xc4\xe2\xf1\x91\x04\xe7", "vpgatherqq xmm0, qword ptr [@di+8*xmm4], xmm1");
    TEST("\xc4\xe2\xf5\x91\x04\xe7", "vpgatherqq ymm0, qword ptr [@di+8*ymm4], ymm1");

    TEST("\xc4\xe2\x7d\x5a\x20", "vbroadcasti128 ymm4, xmmword ptr [@ax]");
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

    TEST("\x0f\xae\x00", "fxsave [@ax]");
    TEST64("\x48\x0f\xae\x00", "fxsave64 [rax]");
    TEST("\x0f\xae\x08", "fxrstor [@ax]");
    TEST64("\x48\x0f\xae\x08", "fxrstor64 [rax]");
    TEST("\x0f\xae\x20", "xsave [@ax]");
    TEST64("\x48\x0f\xae\x20", "xsave64 [rax]");
    TEST("\x0f\xc7\x20", "xsavec [@ax]");
    TEST64("\x48\x0f\xc7\x20", "xsavec64 [rax]");
    TEST("\x0f\xae\x30", "xsaveopt [@ax]");
    TEST64("\x48\x0f\xae\x30", "xsaveopt64 [rax]");
    TEST("\x0f\xc7\x28", "xsaves [@ax]");
    TEST64("\x48\x0f\xc7\x28", "xsaves64 [rax]");
    TEST("\x0f\xae\x28", "xrstor [@ax]");
    TEST64("\x48\x0f\xae\x28", "xrstor64 [rax]");
    TEST("\x0f\xc7\x18", "xrstors [@ax]");
    TEST64("\x48\x0f\xc7\x18", "xrstors64 [rax]");
    TEST("\xff\xe0", "jmp @ax");
    TEST3264("\x66\xff\xe0", "jmp ax", "jmp rax");
    TEST64("\x48\xff\xe0", "jmp rax");
    TEST("\xff\xd0", "call @ax");
    TEST3264("\x66\xff\xd0", "call ax", "call rax");
    TEST64("\x48\xff\xd0", "call rax");
    TEST3264("\x66\x70\x00", "jow 0x3", "jo 0x3");
    TEST("\xe3\xfe", "j@cxz 0x0");
    TEST3264("\x67\xe3\xfd", "jcxz 0x0", "jecxz 0x0");
    TEST3264("\xff\x20", "jmp dword ptr [eax]", "jmp qword ptr [rax]");
    TEST3264("\x66\xff\x20", "jmp word ptr [eax]", "jmp qword ptr [rax]");
    TEST64("\x48\xff\x20", "jmp qword ptr [rax]");
    TEST("\xff\x28", "jmp far fword ptr [@ax]");
    TEST("\x66\xff\x28", "jmp far dword ptr [@ax]");
    TEST64("\x48\xff\x28", "jmp far tbyte ptr [rax]");
    TEST3264("\xea\x11\x22\x33\x44\x55\x66", "jmp far 0x6655:0x44332211", "UD");
    TEST3264("\x66\xea\x11\x22\x33\x44", "jmp far 0x4433:0x2211", "UD");
    TEST32("\x66\x9a\x23\x01\x23\x00", "call far 0x23:0x123");
    TEST32("\x9a\x67\x45\x23\x01\x23\x00", "call far 0x23:0x1234567");
    TEST32("\x9a\xff\xff\xff\xff\xff\xff", "call far 0xffff:0xffffffff");
    TEST("\x66\xff\x1f", "call far dword ptr [@di]");
    TEST("\xff\x1f", "call far fword ptr [@di]");
    TEST64("\x48\xff\x1f", "call far tbyte ptr [rdi]");
    TEST("\x0f\xb4", "PARTIAL");
    TEST("\x66\x0f\xb4\x07", "lfs ax, dword ptr [@di]");
    TEST("\x0f\xb4\x07", "lfs eax, fword ptr [@di]");
    TEST64("\x48\x0f\xb4\x07", "lfs rax, tbyte ptr [rdi]");
    TEST("\xa5", "movsd");
    TEST("\x64\xa5", "fs movsd");
    TEST3264("\x2e\xa5", "cs movsd", "movsd");
    TEST3264("\x67\xa5", "addr16 movsd", "addr32 movsd");
    TEST("\xaf", "scasd");
    TEST("\x64\xaf", "scasd"); // SCAS doesn't use segment overrides
    TEST("\xec", "inb");
    TEST("\x66\xed", "inw");
    TEST("\xed", "ind");
    // TEST64("\x48\xed", "ind"); // TODO
    // TEST64("\x66\x48\xed", "ind"); // TODO
    TEST("\xee", "outb");
    TEST("\x66\xef", "outw");
    TEST("\xef", "outd");
    // TEST64("\x48\xef", "outd"); // TODO
    // TEST64("\x66\x48\xef", "outd"); // TODO
    TEST("\xe4\x00", "in al, 0x0");
    TEST("\xe4\xff", "in al, 0xff");
    TEST("\x66\xe5\xff", "in ax, 0xff");
    TEST("\xe5\xff", "in eax, 0xff");
    // TEST64("\x66\x48\xe5\xff", "in eax, 0xff"); // TODO
    // TEST64("\x48\xe5\xff", "in eax, 0xff"); // TODO
    TEST("\xe6\x00", "out al, 0x0");
    TEST("\xe6\xff", "out al, 0xff");
    TEST("\x66\xe7\xff", "out ax, 0xff");
    TEST("\xe7\xff", "out eax, 0xff");
    // TEST64("\x66\x48\xe7\xff", "out eax, 0xff"); // TODO
    // TEST64("\x48\xe7\xff", "out eax, 0xff"); // TODO
    TEST32("\x66\x61", "popaw");
    TEST32("\x61", "popad");
    TEST("\x66\x9c", "pushfw");
    TEST3264("\x9c", "pushfd", "pushfq");
    TEST("\x66\x9d", "popfw");
    TEST3264("\x9d", "popfd", "popfq");
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
    TEST("\x0f\x21\xd0", "mov @ax, dr2");
    TEST32("\x62\x00", "bound eax, qword ptr [eax]");
    TEST32("\x66\x62\x00", "bound ax, dword ptr [eax]");
    TEST("\x0f\xae\x38", "clflush byte ptr [@ax]");
    TEST("\xdd\x00", "fld qword ptr [@ax]");
    TEST("\xdb\x28", "fld tbyte ptr [@ax]");
    TEST("\xd9\x20", "fldenv [@ax]");

    // MPX
#if 0
    TEST("\x66\x0f\x1a\xc1", "bndmov bnd0, bnd1");
    TEST("\x66\x0f\x1a\xc4", "UD"); // ModRM bnd4 is undefined
    TEST64("\x41\x66\x0f\x1a\xc0", "UD"); // ModRM bnd8 is undefined
    TEST("\xf3\x0f\x1b\x00", "bndmk bnd0, [@ax]");
    TEST64("\x0f\x1a\x05\x00\x00\x00\x00", "UD"); // BNDSTX+RIP-rel = UD
    TEST64("\x0f\x1b\x05\x00\x00\x00\x00", "UD"); // BNDLDX+RIP-rel = UD
    TEST64("\xf3\x0f\x1b\x05\x00\x00\x00\x00", "UD"); // BNDMK+RIP-rel = UD
#endif
    TEST("\xf3\x0f\x1b\xc0", "nop eax, eax"); // BNDMK with reg/reg remains NOP

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

    TEST("\x0f\x01\xfc", "clzero eax");
    TEST("\x66\x0f\x01\xfc", "clzero ax");
    TEST64("\x48\x0f\x01\xfc", "clzero rax");

    // VIA PadLock
    TEST("\x0f\xa7\xc0", "xstore");
    TEST("\xf3\x0f\xa7\xc0", "rep xstore");
    TEST("\xf2\x0f\xa7\xc0", "UD");
    TEST("\x0f\xa7\xe8 ", "UD");
    TEST("\xf2\x0f\xa7\xe8", "UD");
    TEST("\xf3\x0f\xa7\xe8", "rep xcryptofb");

    // Maximum instruction length is 15 bytes.
    TEST("\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x90", "PARTIAL");

    // AMX
    TEST64("\xc4\xe2\x78\x49\x00", "ldtilecfg [rax]");
    TEST64("\xc4\xe2\x79\x49\x00", "sttilecfg [rax]");
    TEST64("\xc4\xe2\x78\x49\xc0", "tilerelease");
    TEST64("\xc4\xe2\x7b\x49\x00", "UD"); // ModRM.mod != 11
    TEST64("\xc4\xe2\x7b\x49\xc0", "tilezero tmm0");
    TEST64("\xc4\xe2\x7b\x49\xc1", "UD"); // ModRM.rm != 0
    TEST64("\xc4\xe2\x7b\x49\xc7", "UD"); // ModRM.rm != 0
    TEST64("\xc4\xe2\x7b\x49\xc8", "tilezero tmm1");
    TEST64("\xc4\xe2\x7b\x49\xf8", "tilezero tmm7");
    TEST64("\xc4\x02\x7b\x49\xf8", "tilezero tmm7"); // VEX.RXB ignored
    TEST64("\xc4\xe2\x7b\x4b\x04\x10", "tileloadd tmm0, [rax+1*rdx]");
    TEST64("\xc4\xe2\x7b\x4b\x04\x20", "tileloadd tmm0, [rax]"); // riz
    TEST64("\xc4\x02\x7b\x4b\x3c\x10", "tileloadd tmm7, [r8+1*r10]"); // VEX.R ignored
    TEST64("\xc4\xe2\x7b\x4b\x00", "UD"); // must have SIB byte
    TEST64("\xc4\xe2\x7b\x4b\xff", "UD"); // must have memory operand
    TEST64("\xc4\xe2\x79\x4b\x04\x10", "tileloaddt1 tmm0, [rax+1*rdx]");
    TEST64("\xc4\xe2\x79\x4b\x04\x20", "tileloaddt1 tmm0, [rax]"); // riz
    TEST64("\xc4\x02\x79\x4b\x3c\x10", "tileloaddt1 tmm7, [r8+1*r10]"); // VEX.R ignored
    TEST64("\xc4\xe2\x79\x4b\x00", "UD"); // must have SIB byte
    TEST64("\xc4\xe2\x79\x4b\xff", "UD"); // must have memory operand
    TEST64("\xc4\xe2\x7a\x4b\x04\x10", "tilestored [rax+1*rdx], tmm0");
    TEST64("\xc4\xe2\x7a\x4b\x04\x20", "tilestored [rax], tmm0"); // riz
    TEST64("\xc4\x02\x7a\x4b\x3c\x10", "tilestored [r8+1*r10], tmm7"); // VEX.R ignored
    TEST64("\xc4\xe2\x7a\x4b\x00", "UD"); // must have SIB byte
    TEST64("\xc4\xe2\x7a\x4b\xff", "UD"); // must have memory operand
    TEST64("\xc4\xe2\x68\x5e\x00", "UD"); // must have register operand
    TEST64("\xc4\xe2\x68\x5e\xc8", "tdpbuud tmm1, tmm0, tmm2");
    TEST64("\xc4\x02\x28\x5e\xc8", "tdpbuud tmm1, tmm0, tmm2"); // VEX.RBV3 ignored
    // TODO: enforce that all registers must be different
    //TEST64("\xc4\xe2\x68\x5e\xc0", "UD"); // ModRM.rm == ModRM.reg
    //TEST64("\xc4\xe2\x68\x5e\xca", "UD"); // ModRM.rm == VEX.vvvv
    //TEST64("\xc4\xe2\x68\x5e\xd0", "UD"); // ModRM.reg == VEX.vvvv
    TEST64("\xc4\xe2\x6a\x5c\xc8", "tdpbf16ps tmm1, tmm0, tmm2");
    TEST64("\xc4\xe2\x6b\x5c\xc8", "tdpfp16ps tmm1, tmm0, tmm2");
    TEST64("\xc4\xe2\x68\x5e\xc8", "tdpbuud tmm1, tmm0, tmm2");
    TEST64("\xc4\xe2\x69\x5e\xc8", "tdpbusd tmm1, tmm0, tmm2");
    TEST64("\xc4\xe2\x6a\x5e\xc8", "tdpbsud tmm1, tmm0, tmm2");
    TEST64("\xc4\xe2\x6b\x5e\xc8", "tdpbssd tmm1, tmm0, tmm2");
    TEST64("\xc4\xe2\x68\x6c\xc8", "tcmmrlfp16ps tmm1, tmm0, tmm2");
    TEST64("\xc4\xe2\x69\x6c\xc8", "tcmmimfp16ps tmm1, tmm0, tmm2");

    // Complete test of VADDPS and all encoding options
    TEST("\x62", "PARTIAL");
    TEST("\x62\xf1", "PARTIAL");
    TEST("\x62\xf1\x74", "PARTIAL");
    TEST("\x62\xf1\x74\x18", "PARTIAL");
    TEST("\x62\xf1\x74\x18\x58", "PARTIAL");
    TEST("\x62\xf1\x74\x18\x58\xc2", "vaddps zmm0, zmm1, zmm2, {rn-sae}");
    TEST("\x62\xf1\x74\x38\x58\xc2", "vaddps zmm0, zmm1, zmm2, {rd-sae}");
    TEST("\x62\xf1\x74\x58\x58\xc2", "vaddps zmm0, zmm1, zmm2, {ru-sae}");
    TEST("\x62\xf1\x74\x78\x58\xc2", "vaddps zmm0, zmm1, zmm2, {rz-sae}");
    TEST("\x62\xf1\x74\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2");
    TEST("\x62\xf1\x74\x09\x58\xc2", "vaddps xmm0{k1}, xmm1, xmm2");
    TEST("\x62\xf1\x74\x89\x58\xc2", "vaddps xmm0{k1}{z}, xmm1, xmm2");
    TEST("\x62\xf1\x74\x88\x58\xc2", "UD"); // EVEX.z = 1
    TEST("\x62\xf1\x74\x28\x58\xc2", "vaddps ymm0, ymm1, ymm2");
    TEST("\x62\xf1\x74\x29\x58\xc2", "vaddps ymm0{k1}, ymm1, ymm2");
    TEST("\x62\xf1\x74\xa9\x58\xc2", "vaddps ymm0{k1}{z}, ymm1, ymm2");
    TEST("\x62\xf1\x74\xa8\x58\xc2", "UD"); // EVEX.z = 1
    TEST("\x62\xf1\x74\x48\x58\xc2", "vaddps zmm0, zmm1, zmm2");
    TEST("\x62\xf1\x74\x49\x58\xc2", "vaddps zmm0{k1}, zmm1, zmm2");
    TEST("\x62\xf1\x74\xc9\x58\xc2", "vaddps zmm0{k1}{z}, zmm1, zmm2");
    TEST("\x62\xf1\x74\xc8\x58\xc2", "UD"); // EVEX.z = 1
    TEST("\x62\xf1\x74\x68\x58\xc2", "UD"); // EVEX.L'Lb = 110    TEST32("\x62\xf1\x74\x08\x58\x00", "vaddps xmm0, xmm1, xmmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\x08\x58\x00", "vaddps xmm0, xmm1, xmmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\x08\x58\x00", "vaddps xmm0, xmm1, xmmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\x08\x58\x00", "vaddps xmm0, xmm1, xmmword ptr [eax]");
    TEST32("\x62\xf1\x74\x0a\x58\x00", "vaddps xmm0{k2}, xmm1, xmmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\x0a\x58\x00", "vaddps xmm0{k2}, xmm1, xmmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\x0a\x58\x00", "vaddps xmm0{k2}, xmm1, xmmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\x0a\x58\x00", "vaddps xmm0{k2}, xmm1, xmmword ptr [eax]");
    TEST32("\x62\xf1\x74\x8a\x58\x00", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\x8a\x58\x00", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\x8a\x58\x00", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\x8a\x58\x00", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [eax]");
    TEST32("\x62\xf1\x74\x88\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\x88\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\x88\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\x88\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x18\x58\x00", "vaddps xmm0, xmm1, dword ptr [eax]{1to4}");
    TEST32("\x67\x62\xf1\x74\x18\x58\x00", "vaddps xmm0, xmm1, dword ptr [bx+1*si]{1to4}");
    TEST64("\x62\xf1\x74\x18\x58\x00", "vaddps xmm0, xmm1, dword ptr [rax]{1to4}");
    TEST64("\x67\x62\xf1\x74\x18\x58\x00", "vaddps xmm0, xmm1, dword ptr [eax]{1to4}");
    TEST32("\x62\xf1\x74\x1a\x58\x00", "vaddps xmm0{k2}, xmm1, dword ptr [eax]{1to4}");
    TEST32("\x67\x62\xf1\x74\x1a\x58\x00", "vaddps xmm0{k2}, xmm1, dword ptr [bx+1*si]{1to4}");
    TEST64("\x62\xf1\x74\x1a\x58\x00", "vaddps xmm0{k2}, xmm1, dword ptr [rax]{1to4}");
    TEST64("\x67\x62\xf1\x74\x1a\x58\x00", "vaddps xmm0{k2}, xmm1, dword ptr [eax]{1to4}");
    TEST32("\x62\xf1\x74\x9a\x58\x00", "vaddps xmm0{k2}{z}, xmm1, dword ptr [eax]{1to4}");
    TEST32("\x67\x62\xf1\x74\x9a\x58\x00", "vaddps xmm0{k2}{z}, xmm1, dword ptr [bx+1*si]{1to4}");
    TEST64("\x62\xf1\x74\x9a\x58\x00", "vaddps xmm0{k2}{z}, xmm1, dword ptr [rax]{1to4}");
    TEST64("\x67\x62\xf1\x74\x9a\x58\x00", "vaddps xmm0{k2}{z}, xmm1, dword ptr [eax]{1to4}");
    TEST32("\x62\xf1\x74\x98\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\x98\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\x98\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\x98\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x28\x58\x00", "vaddps ymm0, ymm1, ymmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\x28\x58\x00", "vaddps ymm0, ymm1, ymmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\x28\x58\x00", "vaddps ymm0, ymm1, ymmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\x28\x58\x00", "vaddps ymm0, ymm1, ymmword ptr [eax]");
    TEST32("\x62\xf1\x74\x2a\x58\x00", "vaddps ymm0{k2}, ymm1, ymmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\x2a\x58\x00", "vaddps ymm0{k2}, ymm1, ymmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\x2a\x58\x00", "vaddps ymm0{k2}, ymm1, ymmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\x2a\x58\x00", "vaddps ymm0{k2}, ymm1, ymmword ptr [eax]");
    TEST32("\x62\xf1\x74\xaa\x58\x00", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\xaa\x58\x00", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\xaa\x58\x00", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\xaa\x58\x00", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [eax]");
    TEST32("\x62\xf1\x74\xa8\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xa8\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xa8\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xa8\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x38\x58\x00", "vaddps ymm0, ymm1, dword ptr [eax]{1to8}");
    TEST32("\x67\x62\xf1\x74\x38\x58\x00", "vaddps ymm0, ymm1, dword ptr [bx+1*si]{1to8}");
    TEST64("\x62\xf1\x74\x38\x58\x00", "vaddps ymm0, ymm1, dword ptr [rax]{1to8}");
    TEST64("\x67\x62\xf1\x74\x38\x58\x00", "vaddps ymm0, ymm1, dword ptr [eax]{1to8}");
    TEST32("\x62\xf1\x74\x3a\x58\x00", "vaddps ymm0{k2}, ymm1, dword ptr [eax]{1to8}");
    TEST32("\x67\x62\xf1\x74\x3a\x58\x00", "vaddps ymm0{k2}, ymm1, dword ptr [bx+1*si]{1to8}");
    TEST64("\x62\xf1\x74\x3a\x58\x00", "vaddps ymm0{k2}, ymm1, dword ptr [rax]{1to8}");
    TEST64("\x67\x62\xf1\x74\x3a\x58\x00", "vaddps ymm0{k2}, ymm1, dword ptr [eax]{1to8}");
    TEST32("\x62\xf1\x74\xba\x58\x00", "vaddps ymm0{k2}{z}, ymm1, dword ptr [eax]{1to8}");
    TEST32("\x67\x62\xf1\x74\xba\x58\x00", "vaddps ymm0{k2}{z}, ymm1, dword ptr [bx+1*si]{1to8}");
    TEST64("\x62\xf1\x74\xba\x58\x00", "vaddps ymm0{k2}{z}, ymm1, dword ptr [rax]{1to8}");
    TEST64("\x67\x62\xf1\x74\xba\x58\x00", "vaddps ymm0{k2}{z}, ymm1, dword ptr [eax]{1to8}");
    TEST32("\x62\xf1\x74\xb8\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xb8\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xb8\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xb8\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x48\x58\x00", "vaddps zmm0, zmm1, zmmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\x48\x58\x00", "vaddps zmm0, zmm1, zmmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\x48\x58\x00", "vaddps zmm0, zmm1, zmmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\x48\x58\x00", "vaddps zmm0, zmm1, zmmword ptr [eax]");
    TEST32("\x62\xf1\x74\x4a\x58\x00", "vaddps zmm0{k2}, zmm1, zmmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\x4a\x58\x00", "vaddps zmm0{k2}, zmm1, zmmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\x4a\x58\x00", "vaddps zmm0{k2}, zmm1, zmmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\x4a\x58\x00", "vaddps zmm0{k2}, zmm1, zmmword ptr [eax]");
    TEST32("\x62\xf1\x74\xca\x58\x00", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [eax]");
    TEST32("\x67\x62\xf1\x74\xca\x58\x00", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [bx+1*si]");
    TEST64("\x62\xf1\x74\xca\x58\x00", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [rax]");
    TEST64("\x67\x62\xf1\x74\xca\x58\x00", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [eax]");
    TEST32("\x62\xf1\x74\xc8\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xc8\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xc8\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xc8\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x58\x58\x00", "vaddps zmm0, zmm1, dword ptr [eax]{1to16}");
    TEST32("\x67\x62\xf1\x74\x58\x58\x00", "vaddps zmm0, zmm1, dword ptr [bx+1*si]{1to16}");
    TEST64("\x62\xf1\x74\x58\x58\x00", "vaddps zmm0, zmm1, dword ptr [rax]{1to16}");
    TEST64("\x67\x62\xf1\x74\x58\x58\x00", "vaddps zmm0, zmm1, dword ptr [eax]{1to16}");
    TEST32("\x62\xf1\x74\x5a\x58\x00", "vaddps zmm0{k2}, zmm1, dword ptr [eax]{1to16}");
    TEST32("\x67\x62\xf1\x74\x5a\x58\x00", "vaddps zmm0{k2}, zmm1, dword ptr [bx+1*si]{1to16}");
    TEST64("\x62\xf1\x74\x5a\x58\x00", "vaddps zmm0{k2}, zmm1, dword ptr [rax]{1to16}");
    TEST64("\x67\x62\xf1\x74\x5a\x58\x00", "vaddps zmm0{k2}, zmm1, dword ptr [eax]{1to16}");
    TEST32("\x62\xf1\x74\xda\x58\x00", "vaddps zmm0{k2}{z}, zmm1, dword ptr [eax]{1to16}");
    TEST32("\x67\x62\xf1\x74\xda\x58\x00", "vaddps zmm0{k2}{z}, zmm1, dword ptr [bx+1*si]{1to16}");
    TEST64("\x62\xf1\x74\xda\x58\x00", "vaddps zmm0{k2}{z}, zmm1, dword ptr [rax]{1to16}");
    TEST64("\x67\x62\xf1\x74\xda\x58\x00", "vaddps zmm0{k2}{z}, zmm1, dword ptr [eax]{1to16}");
    TEST32("\x62\xf1\x74\xd8\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xd8\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xd8\x58\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xd8\x58\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x68\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x68\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x68\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x68\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x6a\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x6a\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x6a\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x6a\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xea\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xea\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xea\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xea\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xe8\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xe8\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xe8\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xe8\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x78\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x78\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x78\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x78\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x7a\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x7a\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x7a\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x7a\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xfa\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xfa\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xfa\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xfa\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xf8\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xf8\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xf8\x58\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xf8\x58\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x08\x58\x40\x01", "vaddps xmm0, xmm1, xmmword ptr [eax+0x10]");
    TEST32("\x67\x62\xf1\x74\x08\x58\x40\x01", "vaddps xmm0, xmm1, xmmword ptr [bx+1*si+0x10]");
    TEST64("\x62\xf1\x74\x08\x58\x40\x01", "vaddps xmm0, xmm1, xmmword ptr [rax+0x10]");
    TEST64("\x67\x62\xf1\x74\x08\x58\x40\x01", "vaddps xmm0, xmm1, xmmword ptr [eax+0x10]");
    TEST32("\x62\xf1\x74\x0a\x58\x40\x01", "vaddps xmm0{k2}, xmm1, xmmword ptr [eax+0x10]");
    TEST32("\x67\x62\xf1\x74\x0a\x58\x40\x01", "vaddps xmm0{k2}, xmm1, xmmword ptr [bx+1*si+0x10]");
    TEST64("\x62\xf1\x74\x0a\x58\x40\x01", "vaddps xmm0{k2}, xmm1, xmmword ptr [rax+0x10]");
    TEST64("\x67\x62\xf1\x74\x0a\x58\x40\x01", "vaddps xmm0{k2}, xmm1, xmmword ptr [eax+0x10]");
    TEST32("\x62\xf1\x74\x8a\x58\x40\x01", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [eax+0x10]");
    TEST32("\x67\x62\xf1\x74\x8a\x58\x40\x01", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [bx+1*si+0x10]");
    TEST64("\x62\xf1\x74\x8a\x58\x40\x01", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [rax+0x10]");
    TEST64("\x67\x62\xf1\x74\x8a\x58\x40\x01", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [eax+0x10]");
    TEST32("\x62\xf1\x74\x88\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\x88\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\x88\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\x88\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x18\x58\x40\x01", "vaddps xmm0, xmm1, dword ptr [eax+0x4]{1to4}");
    TEST32("\x67\x62\xf1\x74\x18\x58\x40\x01", "vaddps xmm0, xmm1, dword ptr [bx+1*si+0x4]{1to4}");
    TEST64("\x62\xf1\x74\x18\x58\x40\x01", "vaddps xmm0, xmm1, dword ptr [rax+0x4]{1to4}");
    TEST64("\x67\x62\xf1\x74\x18\x58\x40\x01", "vaddps xmm0, xmm1, dword ptr [eax+0x4]{1to4}");
    TEST32("\x62\xf1\x74\x1a\x58\x40\x01", "vaddps xmm0{k2}, xmm1, dword ptr [eax+0x4]{1to4}");
    TEST32("\x67\x62\xf1\x74\x1a\x58\x40\x01", "vaddps xmm0{k2}, xmm1, dword ptr [bx+1*si+0x4]{1to4}");
    TEST64("\x62\xf1\x74\x1a\x58\x40\x01", "vaddps xmm0{k2}, xmm1, dword ptr [rax+0x4]{1to4}");
    TEST64("\x67\x62\xf1\x74\x1a\x58\x40\x01", "vaddps xmm0{k2}, xmm1, dword ptr [eax+0x4]{1to4}");
    TEST32("\x62\xf1\x74\x9a\x58\x40\x01", "vaddps xmm0{k2}{z}, xmm1, dword ptr [eax+0x4]{1to4}");
    TEST32("\x67\x62\xf1\x74\x9a\x58\x40\x01", "vaddps xmm0{k2}{z}, xmm1, dword ptr [bx+1*si+0x4]{1to4}");
    TEST64("\x62\xf1\x74\x9a\x58\x40\x01", "vaddps xmm0{k2}{z}, xmm1, dword ptr [rax+0x4]{1to4}");
    TEST64("\x67\x62\xf1\x74\x9a\x58\x40\x01", "vaddps xmm0{k2}{z}, xmm1, dword ptr [eax+0x4]{1to4}");
    TEST32("\x62\xf1\x74\x98\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\x98\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\x98\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\x98\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x28\x58\x40\x01", "vaddps ymm0, ymm1, ymmword ptr [eax+0x20]");
    TEST32("\x67\x62\xf1\x74\x28\x58\x40\x01", "vaddps ymm0, ymm1, ymmword ptr [bx+1*si+0x20]");
    TEST64("\x62\xf1\x74\x28\x58\x40\x01", "vaddps ymm0, ymm1, ymmword ptr [rax+0x20]");
    TEST64("\x67\x62\xf1\x74\x28\x58\x40\x01", "vaddps ymm0, ymm1, ymmword ptr [eax+0x20]");
    TEST32("\x62\xf1\x74\x2a\x58\x40\x01", "vaddps ymm0{k2}, ymm1, ymmword ptr [eax+0x20]");
    TEST32("\x67\x62\xf1\x74\x2a\x58\x40\x01", "vaddps ymm0{k2}, ymm1, ymmword ptr [bx+1*si+0x20]");
    TEST64("\x62\xf1\x74\x2a\x58\x40\x01", "vaddps ymm0{k2}, ymm1, ymmword ptr [rax+0x20]");
    TEST64("\x67\x62\xf1\x74\x2a\x58\x40\x01", "vaddps ymm0{k2}, ymm1, ymmword ptr [eax+0x20]");
    TEST32("\x62\xf1\x74\xaa\x58\x40\x01", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [eax+0x20]");
    TEST32("\x67\x62\xf1\x74\xaa\x58\x40\x01", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [bx+1*si+0x20]");
    TEST64("\x62\xf1\x74\xaa\x58\x40\x01", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [rax+0x20]");
    TEST64("\x67\x62\xf1\x74\xaa\x58\x40\x01", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [eax+0x20]");
    TEST32("\x62\xf1\x74\xa8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xa8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xa8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xa8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x38\x58\x40\x01", "vaddps ymm0, ymm1, dword ptr [eax+0x4]{1to8}");
    TEST32("\x67\x62\xf1\x74\x38\x58\x40\x01", "vaddps ymm0, ymm1, dword ptr [bx+1*si+0x4]{1to8}");
    TEST64("\x62\xf1\x74\x38\x58\x40\x01", "vaddps ymm0, ymm1, dword ptr [rax+0x4]{1to8}");
    TEST64("\x67\x62\xf1\x74\x38\x58\x40\x01", "vaddps ymm0, ymm1, dword ptr [eax+0x4]{1to8}");
    TEST32("\x62\xf1\x74\x3a\x58\x40\x01", "vaddps ymm0{k2}, ymm1, dword ptr [eax+0x4]{1to8}");
    TEST32("\x67\x62\xf1\x74\x3a\x58\x40\x01", "vaddps ymm0{k2}, ymm1, dword ptr [bx+1*si+0x4]{1to8}");
    TEST64("\x62\xf1\x74\x3a\x58\x40\x01", "vaddps ymm0{k2}, ymm1, dword ptr [rax+0x4]{1to8}");
    TEST64("\x67\x62\xf1\x74\x3a\x58\x40\x01", "vaddps ymm0{k2}, ymm1, dword ptr [eax+0x4]{1to8}");
    TEST32("\x62\xf1\x74\xba\x58\x40\x01", "vaddps ymm0{k2}{z}, ymm1, dword ptr [eax+0x4]{1to8}");
    TEST32("\x67\x62\xf1\x74\xba\x58\x40\x01", "vaddps ymm0{k2}{z}, ymm1, dword ptr [bx+1*si+0x4]{1to8}");
    TEST64("\x62\xf1\x74\xba\x58\x40\x01", "vaddps ymm0{k2}{z}, ymm1, dword ptr [rax+0x4]{1to8}");
    TEST64("\x67\x62\xf1\x74\xba\x58\x40\x01", "vaddps ymm0{k2}{z}, ymm1, dword ptr [eax+0x4]{1to8}");
    TEST32("\x62\xf1\x74\xb8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xb8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xb8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xb8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x48\x58\x40\x01", "vaddps zmm0, zmm1, zmmword ptr [eax+0x40]");
    TEST32("\x67\x62\xf1\x74\x48\x58\x40\x01", "vaddps zmm0, zmm1, zmmword ptr [bx+1*si+0x40]");
    TEST64("\x62\xf1\x74\x48\x58\x40\x01", "vaddps zmm0, zmm1, zmmword ptr [rax+0x40]");
    TEST64("\x67\x62\xf1\x74\x48\x58\x40\x01", "vaddps zmm0, zmm1, zmmword ptr [eax+0x40]");
    TEST32("\x62\xf1\x74\x4a\x58\x40\x01", "vaddps zmm0{k2}, zmm1, zmmword ptr [eax+0x40]");
    TEST32("\x67\x62\xf1\x74\x4a\x58\x40\x01", "vaddps zmm0{k2}, zmm1, zmmword ptr [bx+1*si+0x40]");
    TEST64("\x62\xf1\x74\x4a\x58\x40\x01", "vaddps zmm0{k2}, zmm1, zmmword ptr [rax+0x40]");
    TEST64("\x67\x62\xf1\x74\x4a\x58\x40\x01", "vaddps zmm0{k2}, zmm1, zmmword ptr [eax+0x40]");
    TEST32("\x62\xf1\x74\xca\x58\x40\x01", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [eax+0x40]");
    TEST32("\x67\x62\xf1\x74\xca\x58\x40\x01", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [bx+1*si+0x40]");
    TEST64("\x62\xf1\x74\xca\x58\x40\x01", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [rax+0x40]");
    TEST64("\x67\x62\xf1\x74\xca\x58\x40\x01", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [eax+0x40]");
    TEST32("\x62\xf1\x74\xc8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xc8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xc8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xc8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x58\x58\x40\x01", "vaddps zmm0, zmm1, dword ptr [eax+0x4]{1to16}");
    TEST32("\x67\x62\xf1\x74\x58\x58\x40\x01", "vaddps zmm0, zmm1, dword ptr [bx+1*si+0x4]{1to16}");
    TEST64("\x62\xf1\x74\x58\x58\x40\x01", "vaddps zmm0, zmm1, dword ptr [rax+0x4]{1to16}");
    TEST64("\x67\x62\xf1\x74\x58\x58\x40\x01", "vaddps zmm0, zmm1, dword ptr [eax+0x4]{1to16}");
    TEST32("\x62\xf1\x74\x5a\x58\x40\x01", "vaddps zmm0{k2}, zmm1, dword ptr [eax+0x4]{1to16}");
    TEST32("\x67\x62\xf1\x74\x5a\x58\x40\x01", "vaddps zmm0{k2}, zmm1, dword ptr [bx+1*si+0x4]{1to16}");
    TEST64("\x62\xf1\x74\x5a\x58\x40\x01", "vaddps zmm0{k2}, zmm1, dword ptr [rax+0x4]{1to16}");
    TEST64("\x67\x62\xf1\x74\x5a\x58\x40\x01", "vaddps zmm0{k2}, zmm1, dword ptr [eax+0x4]{1to16}");
    TEST32("\x62\xf1\x74\xda\x58\x40\x01", "vaddps zmm0{k2}{z}, zmm1, dword ptr [eax+0x4]{1to16}");
    TEST32("\x67\x62\xf1\x74\xda\x58\x40\x01", "vaddps zmm0{k2}{z}, zmm1, dword ptr [bx+1*si+0x4]{1to16}");
    TEST64("\x62\xf1\x74\xda\x58\x40\x01", "vaddps zmm0{k2}{z}, zmm1, dword ptr [rax+0x4]{1to16}");
    TEST64("\x67\x62\xf1\x74\xda\x58\x40\x01", "vaddps zmm0{k2}{z}, zmm1, dword ptr [eax+0x4]{1to16}");
    TEST32("\x62\xf1\x74\xd8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xd8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xd8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xd8\x58\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x68\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x68\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x68\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x68\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x6a\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x6a\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x6a\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x6a\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xea\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xea\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xea\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xea\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xe8\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xe8\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xe8\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xe8\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x78\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x78\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x78\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x78\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x7a\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x7a\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x7a\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x7a\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xfa\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xfa\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xfa\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xfa\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xf8\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xf8\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xf8\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xf8\x58\x40\x01", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x08\x58\x40\xff", "vaddps xmm0, xmm1, xmmword ptr [eax-0x10]");
    TEST32("\x67\x62\xf1\x74\x08\x58\x40\xff", "vaddps xmm0, xmm1, xmmword ptr [bx+1*si-0x10]");
    TEST64("\x62\xf1\x74\x08\x58\x40\xff", "vaddps xmm0, xmm1, xmmword ptr [rax-0x10]");
    TEST64("\x67\x62\xf1\x74\x08\x58\x40\xff", "vaddps xmm0, xmm1, xmmword ptr [eax-0x10]");
    TEST32("\x62\xf1\x74\x0a\x58\x40\xff", "vaddps xmm0{k2}, xmm1, xmmword ptr [eax-0x10]");
    TEST32("\x67\x62\xf1\x74\x0a\x58\x40\xff", "vaddps xmm0{k2}, xmm1, xmmword ptr [bx+1*si-0x10]");
    TEST64("\x62\xf1\x74\x0a\x58\x40\xff", "vaddps xmm0{k2}, xmm1, xmmword ptr [rax-0x10]");
    TEST64("\x67\x62\xf1\x74\x0a\x58\x40\xff", "vaddps xmm0{k2}, xmm1, xmmword ptr [eax-0x10]");
    TEST32("\x62\xf1\x74\x8a\x58\x40\xff", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [eax-0x10]");
    TEST32("\x67\x62\xf1\x74\x8a\x58\x40\xff", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [bx+1*si-0x10]");
    TEST64("\x62\xf1\x74\x8a\x58\x40\xff", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [rax-0x10]");
    TEST64("\x67\x62\xf1\x74\x8a\x58\x40\xff", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [eax-0x10]");
    TEST32("\x62\xf1\x74\x88\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\x88\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\x88\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\x88\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x18\x58\x40\xff", "vaddps xmm0, xmm1, dword ptr [eax-0x4]{1to4}");
    TEST32("\x67\x62\xf1\x74\x18\x58\x40\xff", "vaddps xmm0, xmm1, dword ptr [bx+1*si-0x4]{1to4}");
    TEST64("\x62\xf1\x74\x18\x58\x40\xff", "vaddps xmm0, xmm1, dword ptr [rax-0x4]{1to4}");
    TEST64("\x67\x62\xf1\x74\x18\x58\x40\xff", "vaddps xmm0, xmm1, dword ptr [eax-0x4]{1to4}");
    TEST32("\x62\xf1\x74\x1a\x58\x40\xff", "vaddps xmm0{k2}, xmm1, dword ptr [eax-0x4]{1to4}");
    TEST32("\x67\x62\xf1\x74\x1a\x58\x40\xff", "vaddps xmm0{k2}, xmm1, dword ptr [bx+1*si-0x4]{1to4}");
    TEST64("\x62\xf1\x74\x1a\x58\x40\xff", "vaddps xmm0{k2}, xmm1, dword ptr [rax-0x4]{1to4}");
    TEST64("\x67\x62\xf1\x74\x1a\x58\x40\xff", "vaddps xmm0{k2}, xmm1, dword ptr [eax-0x4]{1to4}");
    TEST32("\x62\xf1\x74\x9a\x58\x40\xff", "vaddps xmm0{k2}{z}, xmm1, dword ptr [eax-0x4]{1to4}");
    TEST32("\x67\x62\xf1\x74\x9a\x58\x40\xff", "vaddps xmm0{k2}{z}, xmm1, dword ptr [bx+1*si-0x4]{1to4}");
    TEST64("\x62\xf1\x74\x9a\x58\x40\xff", "vaddps xmm0{k2}{z}, xmm1, dword ptr [rax-0x4]{1to4}");
    TEST64("\x67\x62\xf1\x74\x9a\x58\x40\xff", "vaddps xmm0{k2}{z}, xmm1, dword ptr [eax-0x4]{1to4}");
    TEST32("\x62\xf1\x74\x98\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\x98\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\x98\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\x98\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x28\x58\x40\xff", "vaddps ymm0, ymm1, ymmword ptr [eax-0x20]");
    TEST32("\x67\x62\xf1\x74\x28\x58\x40\xff", "vaddps ymm0, ymm1, ymmword ptr [bx+1*si-0x20]");
    TEST64("\x62\xf1\x74\x28\x58\x40\xff", "vaddps ymm0, ymm1, ymmword ptr [rax-0x20]");
    TEST64("\x67\x62\xf1\x74\x28\x58\x40\xff", "vaddps ymm0, ymm1, ymmword ptr [eax-0x20]");
    TEST32("\x62\xf1\x74\x2a\x58\x40\xff", "vaddps ymm0{k2}, ymm1, ymmword ptr [eax-0x20]");
    TEST32("\x67\x62\xf1\x74\x2a\x58\x40\xff", "vaddps ymm0{k2}, ymm1, ymmword ptr [bx+1*si-0x20]");
    TEST64("\x62\xf1\x74\x2a\x58\x40\xff", "vaddps ymm0{k2}, ymm1, ymmword ptr [rax-0x20]");
    TEST64("\x67\x62\xf1\x74\x2a\x58\x40\xff", "vaddps ymm0{k2}, ymm1, ymmword ptr [eax-0x20]");
    TEST32("\x62\xf1\x74\xaa\x58\x40\xff", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [eax-0x20]");
    TEST32("\x67\x62\xf1\x74\xaa\x58\x40\xff", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [bx+1*si-0x20]");
    TEST64("\x62\xf1\x74\xaa\x58\x40\xff", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [rax-0x20]");
    TEST64("\x67\x62\xf1\x74\xaa\x58\x40\xff", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [eax-0x20]");
    TEST32("\x62\xf1\x74\xa8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xa8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xa8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xa8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x38\x58\x40\xff", "vaddps ymm0, ymm1, dword ptr [eax-0x4]{1to8}");
    TEST32("\x67\x62\xf1\x74\x38\x58\x40\xff", "vaddps ymm0, ymm1, dword ptr [bx+1*si-0x4]{1to8}");
    TEST64("\x62\xf1\x74\x38\x58\x40\xff", "vaddps ymm0, ymm1, dword ptr [rax-0x4]{1to8}");
    TEST64("\x67\x62\xf1\x74\x38\x58\x40\xff", "vaddps ymm0, ymm1, dword ptr [eax-0x4]{1to8}");
    TEST32("\x62\xf1\x74\x3a\x58\x40\xff", "vaddps ymm0{k2}, ymm1, dword ptr [eax-0x4]{1to8}");
    TEST32("\x67\x62\xf1\x74\x3a\x58\x40\xff", "vaddps ymm0{k2}, ymm1, dword ptr [bx+1*si-0x4]{1to8}");
    TEST64("\x62\xf1\x74\x3a\x58\x40\xff", "vaddps ymm0{k2}, ymm1, dword ptr [rax-0x4]{1to8}");
    TEST64("\x67\x62\xf1\x74\x3a\x58\x40\xff", "vaddps ymm0{k2}, ymm1, dword ptr [eax-0x4]{1to8}");
    TEST32("\x62\xf1\x74\xba\x58\x40\xff", "vaddps ymm0{k2}{z}, ymm1, dword ptr [eax-0x4]{1to8}");
    TEST32("\x67\x62\xf1\x74\xba\x58\x40\xff", "vaddps ymm0{k2}{z}, ymm1, dword ptr [bx+1*si-0x4]{1to8}");
    TEST64("\x62\xf1\x74\xba\x58\x40\xff", "vaddps ymm0{k2}{z}, ymm1, dword ptr [rax-0x4]{1to8}");
    TEST64("\x67\x62\xf1\x74\xba\x58\x40\xff", "vaddps ymm0{k2}{z}, ymm1, dword ptr [eax-0x4]{1to8}");
    TEST32("\x62\xf1\x74\xb8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xb8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xb8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xb8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x48\x58\x40\xff", "vaddps zmm0, zmm1, zmmword ptr [eax-0x40]");
    TEST32("\x67\x62\xf1\x74\x48\x58\x40\xff", "vaddps zmm0, zmm1, zmmword ptr [bx+1*si-0x40]");
    TEST64("\x62\xf1\x74\x48\x58\x40\xff", "vaddps zmm0, zmm1, zmmword ptr [rax-0x40]");
    TEST64("\x67\x62\xf1\x74\x48\x58\x40\xff", "vaddps zmm0, zmm1, zmmword ptr [eax-0x40]");
    TEST32("\x62\xf1\x74\x4a\x58\x40\xff", "vaddps zmm0{k2}, zmm1, zmmword ptr [eax-0x40]");
    TEST32("\x67\x62\xf1\x74\x4a\x58\x40\xff", "vaddps zmm0{k2}, zmm1, zmmword ptr [bx+1*si-0x40]");
    TEST64("\x62\xf1\x74\x4a\x58\x40\xff", "vaddps zmm0{k2}, zmm1, zmmword ptr [rax-0x40]");
    TEST64("\x67\x62\xf1\x74\x4a\x58\x40\xff", "vaddps zmm0{k2}, zmm1, zmmword ptr [eax-0x40]");
    TEST32("\x62\xf1\x74\xca\x58\x40\xff", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [eax-0x40]");
    TEST32("\x67\x62\xf1\x74\xca\x58\x40\xff", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [bx+1*si-0x40]");
    TEST64("\x62\xf1\x74\xca\x58\x40\xff", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [rax-0x40]");
    TEST64("\x67\x62\xf1\x74\xca\x58\x40\xff", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [eax-0x40]");
    TEST32("\x62\xf1\x74\xc8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xc8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xc8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xc8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x58\x58\x40\xff", "vaddps zmm0, zmm1, dword ptr [eax-0x4]{1to16}");
    TEST32("\x67\x62\xf1\x74\x58\x58\x40\xff", "vaddps zmm0, zmm1, dword ptr [bx+1*si-0x4]{1to16}");
    TEST64("\x62\xf1\x74\x58\x58\x40\xff", "vaddps zmm0, zmm1, dword ptr [rax-0x4]{1to16}");
    TEST64("\x67\x62\xf1\x74\x58\x58\x40\xff", "vaddps zmm0, zmm1, dword ptr [eax-0x4]{1to16}");
    TEST32("\x62\xf1\x74\x5a\x58\x40\xff", "vaddps zmm0{k2}, zmm1, dword ptr [eax-0x4]{1to16}");
    TEST32("\x67\x62\xf1\x74\x5a\x58\x40\xff", "vaddps zmm0{k2}, zmm1, dword ptr [bx+1*si-0x4]{1to16}");
    TEST64("\x62\xf1\x74\x5a\x58\x40\xff", "vaddps zmm0{k2}, zmm1, dword ptr [rax-0x4]{1to16}");
    TEST64("\x67\x62\xf1\x74\x5a\x58\x40\xff", "vaddps zmm0{k2}, zmm1, dword ptr [eax-0x4]{1to16}");
    TEST32("\x62\xf1\x74\xda\x58\x40\xff", "vaddps zmm0{k2}{z}, zmm1, dword ptr [eax-0x4]{1to16}");
    TEST32("\x67\x62\xf1\x74\xda\x58\x40\xff", "vaddps zmm0{k2}{z}, zmm1, dword ptr [bx+1*si-0x4]{1to16}");
    TEST64("\x62\xf1\x74\xda\x58\x40\xff", "vaddps zmm0{k2}{z}, zmm1, dword ptr [rax-0x4]{1to16}");
    TEST64("\x67\x62\xf1\x74\xda\x58\x40\xff", "vaddps zmm0{k2}{z}, zmm1, dword ptr [eax-0x4]{1to16}");
    TEST32("\x62\xf1\x74\xd8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xd8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xd8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xd8\x58\x40\xff", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x68\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x68\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x68\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x68\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x6a\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x6a\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x6a\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x6a\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xea\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xea\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xea\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xea\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xe8\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xe8\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xe8\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xe8\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x78\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x78\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x78\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x78\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x7a\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x7a\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x7a\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x7a\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xfa\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xfa\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xfa\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xfa\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xf8\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xf8\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xf8\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xf8\x58\x40\xff", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x08\x58\x80\x01\x00\x00\x00", "vaddps xmm0, xmm1, xmmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\x08\x58\x80\x01\x00", "vaddps xmm0, xmm1, xmmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\x08\x58\x80\x01\x00\x00\x00", "vaddps xmm0, xmm1, xmmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\x08\x58\x80\x01\x00\x00\x00", "vaddps xmm0, xmm1, xmmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\x0a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}, xmm1, xmmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\x0a\x58\x80\x01\x00", "vaddps xmm0{k2}, xmm1, xmmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\x0a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}, xmm1, xmmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\x0a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}, xmm1, xmmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\x8a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\x8a\x58\x80\x01\x00", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\x8a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\x8a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}{z}, xmm1, xmmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\x88\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\x88\x58\x80\x01\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\x88\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\x88\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x18\x58\x80\x01\x00\x00\x00", "vaddps xmm0, xmm1, dword ptr [eax+0x1]{1to4}");
    TEST32("\x67\x62\xf1\x74\x18\x58\x80\x01\x00", "vaddps xmm0, xmm1, dword ptr [bx+1*si+0x1]{1to4}");
    TEST64("\x62\xf1\x74\x18\x58\x80\x01\x00\x00\x00", "vaddps xmm0, xmm1, dword ptr [rax+0x1]{1to4}");
    TEST64("\x67\x62\xf1\x74\x18\x58\x80\x01\x00\x00\x00", "vaddps xmm0, xmm1, dword ptr [eax+0x1]{1to4}");
    TEST32("\x62\xf1\x74\x1a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}, xmm1, dword ptr [eax+0x1]{1to4}");
    TEST32("\x67\x62\xf1\x74\x1a\x58\x80\x01\x00", "vaddps xmm0{k2}, xmm1, dword ptr [bx+1*si+0x1]{1to4}");
    TEST64("\x62\xf1\x74\x1a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}, xmm1, dword ptr [rax+0x1]{1to4}");
    TEST64("\x67\x62\xf1\x74\x1a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}, xmm1, dword ptr [eax+0x1]{1to4}");
    TEST32("\x62\xf1\x74\x9a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}{z}, xmm1, dword ptr [eax+0x1]{1to4}");
    TEST32("\x67\x62\xf1\x74\x9a\x58\x80\x01\x00", "vaddps xmm0{k2}{z}, xmm1, dword ptr [bx+1*si+0x1]{1to4}");
    TEST64("\x62\xf1\x74\x9a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}{z}, xmm1, dword ptr [rax+0x1]{1to4}");
    TEST64("\x67\x62\xf1\x74\x9a\x58\x80\x01\x00\x00\x00", "vaddps xmm0{k2}{z}, xmm1, dword ptr [eax+0x1]{1to4}");
    TEST32("\x62\xf1\x74\x98\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\x98\x58\x80\x01\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\x98\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\x98\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x28\x58\x80\x01\x00\x00\x00", "vaddps ymm0, ymm1, ymmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\x28\x58\x80\x01\x00", "vaddps ymm0, ymm1, ymmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\x28\x58\x80\x01\x00\x00\x00", "vaddps ymm0, ymm1, ymmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\x28\x58\x80\x01\x00\x00\x00", "vaddps ymm0, ymm1, ymmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\x2a\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}, ymm1, ymmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\x2a\x58\x80\x01\x00", "vaddps ymm0{k2}, ymm1, ymmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\x2a\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}, ymm1, ymmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\x2a\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}, ymm1, ymmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\xaa\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\xaa\x58\x80\x01\x00", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\xaa\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\xaa\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}{z}, ymm1, ymmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\xa8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xa8\x58\x80\x01\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xa8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xa8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x38\x58\x80\x01\x00\x00\x00", "vaddps ymm0, ymm1, dword ptr [eax+0x1]{1to8}");
    TEST32("\x67\x62\xf1\x74\x38\x58\x80\x01\x00", "vaddps ymm0, ymm1, dword ptr [bx+1*si+0x1]{1to8}");
    TEST64("\x62\xf1\x74\x38\x58\x80\x01\x00\x00\x00", "vaddps ymm0, ymm1, dword ptr [rax+0x1]{1to8}");
    TEST64("\x67\x62\xf1\x74\x38\x58\x80\x01\x00\x00\x00", "vaddps ymm0, ymm1, dword ptr [eax+0x1]{1to8}");
    TEST32("\x62\xf1\x74\x3a\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}, ymm1, dword ptr [eax+0x1]{1to8}");
    TEST32("\x67\x62\xf1\x74\x3a\x58\x80\x01\x00", "vaddps ymm0{k2}, ymm1, dword ptr [bx+1*si+0x1]{1to8}");
    TEST64("\x62\xf1\x74\x3a\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}, ymm1, dword ptr [rax+0x1]{1to8}");
    TEST64("\x67\x62\xf1\x74\x3a\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}, ymm1, dword ptr [eax+0x1]{1to8}");
    TEST32("\x62\xf1\x74\xba\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}{z}, ymm1, dword ptr [eax+0x1]{1to8}");
    TEST32("\x67\x62\xf1\x74\xba\x58\x80\x01\x00", "vaddps ymm0{k2}{z}, ymm1, dword ptr [bx+1*si+0x1]{1to8}");
    TEST64("\x62\xf1\x74\xba\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}{z}, ymm1, dword ptr [rax+0x1]{1to8}");
    TEST64("\x67\x62\xf1\x74\xba\x58\x80\x01\x00\x00\x00", "vaddps ymm0{k2}{z}, ymm1, dword ptr [eax+0x1]{1to8}");
    TEST32("\x62\xf1\x74\xb8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xb8\x58\x80\x01\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xb8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xb8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x48\x58\x80\x01\x00\x00\x00", "vaddps zmm0, zmm1, zmmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\x48\x58\x80\x01\x00", "vaddps zmm0, zmm1, zmmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\x48\x58\x80\x01\x00\x00\x00", "vaddps zmm0, zmm1, zmmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\x48\x58\x80\x01\x00\x00\x00", "vaddps zmm0, zmm1, zmmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\x4a\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}, zmm1, zmmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\x4a\x58\x80\x01\x00", "vaddps zmm0{k2}, zmm1, zmmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\x4a\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}, zmm1, zmmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\x4a\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}, zmm1, zmmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\xca\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [eax+0x1]");
    TEST32("\x67\x62\xf1\x74\xca\x58\x80\x01\x00", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [bx+1*si+0x1]");
    TEST64("\x62\xf1\x74\xca\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [rax+0x1]");
    TEST64("\x67\x62\xf1\x74\xca\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}{z}, zmm1, zmmword ptr [eax+0x1]");
    TEST32("\x62\xf1\x74\xc8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xc8\x58\x80\x01\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xc8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xc8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x58\x58\x80\x01\x00\x00\x00", "vaddps zmm0, zmm1, dword ptr [eax+0x1]{1to16}");
    TEST32("\x67\x62\xf1\x74\x58\x58\x80\x01\x00", "vaddps zmm0, zmm1, dword ptr [bx+1*si+0x1]{1to16}");
    TEST64("\x62\xf1\x74\x58\x58\x80\x01\x00\x00\x00", "vaddps zmm0, zmm1, dword ptr [rax+0x1]{1to16}");
    TEST64("\x67\x62\xf1\x74\x58\x58\x80\x01\x00\x00\x00", "vaddps zmm0, zmm1, dword ptr [eax+0x1]{1to16}");
    TEST32("\x62\xf1\x74\x5a\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}, zmm1, dword ptr [eax+0x1]{1to16}");
    TEST32("\x67\x62\xf1\x74\x5a\x58\x80\x01\x00", "vaddps zmm0{k2}, zmm1, dword ptr [bx+1*si+0x1]{1to16}");
    TEST64("\x62\xf1\x74\x5a\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}, zmm1, dword ptr [rax+0x1]{1to16}");
    TEST64("\x67\x62\xf1\x74\x5a\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}, zmm1, dword ptr [eax+0x1]{1to16}");
    TEST32("\x62\xf1\x74\xda\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}{z}, zmm1, dword ptr [eax+0x1]{1to16}");
    TEST32("\x67\x62\xf1\x74\xda\x58\x80\x01\x00", "vaddps zmm0{k2}{z}, zmm1, dword ptr [bx+1*si+0x1]{1to16}");
    TEST64("\x62\xf1\x74\xda\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}{z}, zmm1, dword ptr [rax+0x1]{1to16}");
    TEST64("\x67\x62\xf1\x74\xda\x58\x80\x01\x00\x00\x00", "vaddps zmm0{k2}{z}, zmm1, dword ptr [eax+0x1]{1to16}");
    TEST32("\x62\xf1\x74\xd8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf1\x74\xd8\x58\x80\x01\x00", "UD"); // EVEX.z = 1
    TEST64("\x62\xf1\x74\xd8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf1\x74\xd8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.z = 1
    TEST32("\x62\xf1\x74\x68\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x68\x58\x80\x01\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x68\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x68\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x6a\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x6a\x58\x80\x01\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x6a\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x6a\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xea\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xea\x58\x80\x01\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xea\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xea\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xe8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xe8\x58\x80\x01\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xe8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xe8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x78\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x78\x58\x80\x01\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x78\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x78\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\x7a\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\x7a\x58\x80\x01\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\x7a\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\x7a\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xfa\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xfa\x58\x80\x01\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xfa\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xfa\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x62\xf1\x74\xf8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST32("\x67\x62\xf1\x74\xf8\x58\x80\x01\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x62\xf1\x74\xf8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11
    TEST64("\x67\x62\xf1\x74\xf8\x58\x80\x01\x00\x00\x00", "UD"); // EVEX.L'L = 11

    // Test register extensions encoded in EVEX prefixs
    TEST3264("\x62\xf1\x74\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2", "vaddps xmm0, xmm1, xmm2");
    TEST3264("\x62\xd1\x74\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2", "vaddps xmm0, xmm1, xmm10");
    TEST64("\x62\xb1\x74\x08\x58\xc2", "vaddps xmm0, xmm1, xmm18");
    TEST64("\x62\x91\x74\x08\x58\xc2", "vaddps xmm0, xmm1, xmm26");
    TEST3264("\x62\xf1\x34\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2", "vaddps xmm0, xmm9, xmm2");
    TEST3264("\x62\xd1\x34\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2", "vaddps xmm0, xmm9, xmm10");
    TEST64("\x62\xb1\x34\x08\x58\xc2", "vaddps xmm0, xmm9, xmm18");
    TEST64("\x62\x91\x34\x08\x58\xc2", "vaddps xmm0, xmm9, xmm26");
    TEST3264("\x62\xf1\x74\x00\x58\xc2", "UD", "vaddps xmm0, xmm17, xmm2"); // EVEX.V' = 0
    TEST3264("\x62\xd1\x74\x00\x58\xc2", "UD", "vaddps xmm0, xmm17, xmm10"); // EVEX.V' = 0
    TEST64("\x62\xb1\x74\x00\x58\xc2", "vaddps xmm0, xmm17, xmm18");
    TEST64("\x62\x91\x74\x00\x58\xc2", "vaddps xmm0, xmm17, xmm26");
    TEST3264("\x62\xf1\x34\x00\x58\xc2", "UD", "vaddps xmm0, xmm25, xmm2"); // EVEX.V' = 0
    TEST3264("\x62\xd1\x34\x00\x58\xc2", "UD", "vaddps xmm0, xmm25, xmm10"); // EVEX.V' = 0
    TEST64("\x62\xb1\x34\x00\x58\xc2", "vaddps xmm0, xmm25, xmm18");
    TEST64("\x62\x91\x34\x00\x58\xc2", "vaddps xmm0, xmm25, xmm26");
    TEST64("\x62\x71\x74\x08\x58\xc2", "vaddps xmm8, xmm1, xmm2");
    TEST64("\x62\x51\x74\x08\x58\xc2", "vaddps xmm8, xmm1, xmm10");
    TEST64("\x62\x31\x74\x08\x58\xc2", "vaddps xmm8, xmm1, xmm18");
    TEST64("\x62\x11\x74\x08\x58\xc2", "vaddps xmm8, xmm1, xmm26");
    TEST64("\x62\x71\x34\x08\x58\xc2", "vaddps xmm8, xmm9, xmm2");
    TEST64("\x62\x51\x34\x08\x58\xc2", "vaddps xmm8, xmm9, xmm10");
    TEST64("\x62\x31\x34\x08\x58\xc2", "vaddps xmm8, xmm9, xmm18");
    TEST64("\x62\x11\x34\x08\x58\xc2", "vaddps xmm8, xmm9, xmm26");
    TEST64("\x62\x71\x74\x00\x58\xc2", "vaddps xmm8, xmm17, xmm2");
    TEST64("\x62\x51\x74\x00\x58\xc2", "vaddps xmm8, xmm17, xmm10");
    TEST64("\x62\x31\x74\x00\x58\xc2", "vaddps xmm8, xmm17, xmm18");
    TEST64("\x62\x11\x74\x00\x58\xc2", "vaddps xmm8, xmm17, xmm26");
    TEST64("\x62\x71\x34\x00\x58\xc2", "vaddps xmm8, xmm25, xmm2");
    TEST64("\x62\x51\x34\x00\x58\xc2", "vaddps xmm8, xmm25, xmm10");
    TEST64("\x62\x31\x34\x00\x58\xc2", "vaddps xmm8, xmm25, xmm18");
    TEST64("\x62\x11\x34\x00\x58\xc2", "vaddps xmm8, xmm25, xmm26");
    TEST3264("\x62\xe1\x74\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2", "vaddps xmm16, xmm1, xmm2");
    TEST3264("\x62\xc1\x74\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2", "vaddps xmm16, xmm1, xmm10");
    TEST64("\x62\xa1\x74\x08\x58\xc2", "vaddps xmm16, xmm1, xmm18");
    TEST64("\x62\x81\x74\x08\x58\xc2", "vaddps xmm16, xmm1, xmm26");
    TEST3264("\x62\xe1\x34\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2", "vaddps xmm16, xmm9, xmm2");
    TEST3264("\x62\xc1\x34\x08\x58\xc2", "vaddps xmm0, xmm1, xmm2", "vaddps xmm16, xmm9, xmm10");
    TEST64("\x62\xa1\x34\x08\x58\xc2", "vaddps xmm16, xmm9, xmm18");
    TEST64("\x62\x81\x34\x08\x58\xc2", "vaddps xmm16, xmm9, xmm26");
    TEST3264("\x62\xe1\x74\x00\x58\xc2", "UD", "vaddps xmm16, xmm17, xmm2"); // EVEX.V' = 0
    TEST3264("\x62\xc1\x74\x00\x58\xc2", "UD", "vaddps xmm16, xmm17, xmm10"); // EVEX.V' = 0
    TEST64("\x62\xa1\x74\x00\x58\xc2", "vaddps xmm16, xmm17, xmm18");
    TEST64("\x62\x81\x74\x00\x58\xc2", "vaddps xmm16, xmm17, xmm26");
    TEST3264("\x62\xe1\x34\x00\x58\xc2", "UD", "vaddps xmm16, xmm25, xmm2"); // EVEX.V' = 0
    TEST3264("\x62\xc1\x34\x00\x58\xc2", "UD", "vaddps xmm16, xmm25, xmm10"); // EVEX.V' = 0
    TEST64("\x62\xa1\x34\x00\x58\xc2", "vaddps xmm16, xmm25, xmm18");
    TEST64("\x62\x81\x34\x00\x58\xc2", "vaddps xmm16, xmm25, xmm26");
    TEST64("\x62\x61\x74\x08\x58\xc2", "vaddps xmm24, xmm1, xmm2");
    TEST64("\x62\x41\x74\x08\x58\xc2", "vaddps xmm24, xmm1, xmm10");
    TEST64("\x62\x21\x74\x08\x58\xc2", "vaddps xmm24, xmm1, xmm18");
    TEST64("\x62\x01\x74\x08\x58\xc2", "vaddps xmm24, xmm1, xmm26");
    TEST64("\x62\x61\x34\x08\x58\xc2", "vaddps xmm24, xmm9, xmm2");
    TEST64("\x62\x41\x34\x08\x58\xc2", "vaddps xmm24, xmm9, xmm10");
    TEST64("\x62\x21\x34\x08\x58\xc2", "vaddps xmm24, xmm9, xmm18");
    TEST64("\x62\x01\x34\x08\x58\xc2", "vaddps xmm24, xmm9, xmm26");
    TEST64("\x62\x61\x74\x00\x58\xc2", "vaddps xmm24, xmm17, xmm2");
    TEST64("\x62\x41\x74\x00\x58\xc2", "vaddps xmm24, xmm17, xmm10");
    TEST64("\x62\x21\x74\x00\x58\xc2", "vaddps xmm24, xmm17, xmm18");
    TEST64("\x62\x01\x74\x00\x58\xc2", "vaddps xmm24, xmm17, xmm26");
    TEST64("\x62\x61\x34\x00\x58\xc2", "vaddps xmm24, xmm25, xmm2");
    TEST64("\x62\x41\x34\x00\x58\xc2", "vaddps xmm24, xmm25, xmm10");
    TEST64("\x62\x21\x34\x00\x58\xc2", "vaddps xmm24, xmm25, xmm18");
    TEST64("\x62\x01\x34\x00\x58\xc2", "vaddps xmm24, xmm25, xmm26");

    // VMOVDDUP has special tuple size for L0.
    TEST("\x62\xf1\xff\x08\x12\x48\x01", "vmovddup xmm1, qword ptr [@ax+0x8]");
    TEST("\x62\xf1\xff\x08\x12\xc8", "vmovddup xmm1, xmm0");
    TEST("\x62\xf1\xff\x28\x12\x48\x01", "vmovddup ymm1, ymmword ptr [@ax+0x20]");
    TEST("\x62\xf1\xff\x28\x12\xc8", "vmovddup ymm1, ymm0");
    TEST("\x62\xf1\xff\x48\x12\x48\x01", "vmovddup zmm1, zmmword ptr [@ax+0x40]");
    TEST("\x62\xf1\xff\x48\x12\xc8", "vmovddup zmm1, zmm0");

    // Check EVEX.L'L constraints
    TEST("\x62\xf2\x7d\x08\x18\x48\x01", "vbroadcastss xmm1, dword ptr [@ax+0x4]");
    TEST("\x62\xf2\x7d\x08\x18\xc8", "vbroadcastss xmm1, xmm0");
    TEST("\x62\xf2\x7d\x28\x18\x48\x01", "vbroadcastss ymm1, dword ptr [@ax+0x4]");
    TEST("\x62\xf2\x7d\x28\x18\xc8", "vbroadcastss ymm1, xmm0");
    TEST("\x62\xf2\x7d\x48\x18\x48\x01", "vbroadcastss zmm1, dword ptr [@ax+0x4]");
    TEST("\x62\xf2\x7d\x48\x18\xc8", "vbroadcastss zmm1, xmm0");
    TEST("\x62\xf2\x7d\x68\x18\x48\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\x7d\x68\x18\xc8", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\x7d\x08\x19\x48\x01", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\x7d\x08\x19\xc8", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\x7d\x28\x19\x48\x01", "vbroadcastf32x2 ymm1, qword ptr [@ax+0x8]");
    TEST("\x62\xf2\x7d\x28\x19\xc8", "vbroadcastf32x2 ymm1, xmm0");
    TEST("\x62\xf2\x7d\x48\x19\x48\x01", "vbroadcastf32x2 zmm1, qword ptr [@ax+0x8]");
    TEST("\x62\xf2\x7d\x48\x19\xc8", "vbroadcastf32x2 zmm1, xmm0");
    TEST("\x62\xf2\x7d\x68\x19\x48\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\x7d\x68\x19\xc8", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\xfd\x08\x19\x48\x01", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\xfd\x08\x19\xc8", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\xfd\x28\x19\x48\x01", "vbroadcastsd ymm1, qword ptr [@ax+0x8]");
    TEST("\x62\xf2\xfd\x28\x19\xc8", "vbroadcastsd ymm1, xmm0");
    TEST("\x62\xf2\xfd\x48\x19\x48\x01", "vbroadcastsd zmm1, qword ptr [@ax+0x8]");
    TEST("\x62\xf2\xfd\x48\x19\xc8", "vbroadcastsd zmm1, xmm0");
    TEST("\x62\xf2\xfd\x68\x19\x48\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\xfd\x68\x19\xc8", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\x7d\x08\x1a\x48\x01", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\x7d\x08\x1a\xc8", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\x7d\x28\x1a\x48\x01", "vbroadcastf32x4 ymm1, xmmword ptr [@ax+0x10]");
    TEST("\x62\xf2\x7d\x28\x1a\xc8", "UD"); // must have a memory operand
    TEST("\x62\xf2\x7d\x48\x1a\x48\x01", "vbroadcastf32x4 zmm1, xmmword ptr [@ax+0x10]");
    TEST("\x62\xf2\x7d\x48\x1a\xc8", "UD"); // must have a memory operand
    TEST("\x62\xf2\x7d\x68\x1a\x48\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\x7d\x68\x1a\xc8", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\xfd\x08\x1a\x48\x01", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\xfd\x08\x1a\xc8", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\xfd\x28\x1a\x48\x01", "vbroadcastf64x2 ymm1, xmmword ptr [@ax+0x10]");
    TEST("\x62\xf2\xfd\x28\x1a\xc8", "UD"); // must have a memory operand
    TEST("\x62\xf2\xfd\x48\x1a\x48\x01", "vbroadcastf64x2 zmm1, xmmword ptr [@ax+0x10]");
    TEST("\x62\xf2\xfd\x48\x1a\xc8", "UD"); // must have a memory operand
    TEST("\x62\xf2\xfd\x68\x1a\x48\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\xfd\x68\x1a\xc8", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\x7d\x08\x1b\x48\x01", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\x7d\x08\x1b\xc8", "UD"); // EVEX.L'L = 0
    TEST3264("\x62\xf2\x7d\x28\x1b\x48\x01", "UD", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf2\x7d\x28\x1b\xc8", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf2\x7d\x48\x1b\x48\x01", "vbroadcastf32x8 zmm1, ymmword ptr [@ax+0x20]");
    TEST("\x62\xf2\x7d\x48\x1b\xc8", "UD"); // must have a memory operand
    TEST("\x62\xf2\x7d\x68\x1b\x48\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\x7d\x68\x1b\xc8", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\xfd\x08\x1b\x48\x01", "UD"); // EVEX.L'L = 0
    TEST("\x62\xf2\xfd\x08\x1b\xc8", "UD"); // EVEX.L'L = 0
    TEST3264("\x62\xf2\xfd\x28\x1b\x48\x01", "UD", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf2\xfd\x28\x1b\xc8", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf2\xfd\x48\x1b\x48\x01", "vbroadcastf64x4 zmm1, ymmword ptr [@ax+0x20]");
    TEST("\x62\xf2\xfd\x48\x1b\xc8", "UD"); // must have a memory operand
    TEST("\x62\xf2\xfd\x68\x1b\x48\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\xfd\x68\x1b\xc8", "UD"); // EVEX.L'L = 3

    // EVEX PEXTR/PINSR/MOV_G2X/MOV_X2G/PBROADCAST ignore EVEX.W in 32-bit mode
    // and have different mnemonics on due to this distinction.
    TEST("\x62\xf3\x7d\x08\x14\x00\x01", "vpextrb byte ptr [@ax], xmm0, 0x1");
    TEST("\x62\xf3\x7d\x08\x14\x40\x01\x01", "vpextrb byte ptr [@ax+0x1], xmm0, 0x1");
    TEST("\x62\xf3\x7d\x08\x14\xc0\x01", "vpextrb eax, xmm0, 0x1");
    TEST("\x62\xf3\x7d\x18\x14\xc0\x01", "UD"); // EVEX.b != 0
    TEST("\x62\xf3\x7d\x28\x14\xc0\x01", "UD"); // EVEX.L'L != 0
    TEST("\x62\xf3\x7d\x48\x14\xc0\x01", "UD"); // EVEX.L'L != 0
    TEST("\x62\xf3\x7d\x88\x14\xc0\x01", "UD"); // EVEX.z != 0
    TEST("\x62\xf3\x7d\x09\x14\xc0\x01", "UD"); // EVEX.aaa != 0
    TEST("\x62\xf3\x7d\x08\x15\x00\x01", "vpextrw word ptr [@ax], xmm0, 0x1");
    TEST("\x62\xf3\x7d\x08\x15\x40\x01\x01", "vpextrw word ptr [@ax+0x2], xmm0, 0x1");
    TEST("\x62\xf3\x7d\x08\x15\xc0\x01", "vpextrw eax, xmm0, 0x1");
    TEST("\x62\xf1\x7d\x08\xc5\xc0\x01", "vpextrw eax, xmm0, 0x1");
    TEST("\x62\xf1\x7d\x08\xc5\x00\x01", "UD"); // must have register operand
    TEST("\x62\xf3\x7d\x08\x16\x00\x01", "vpextrd dword ptr [@ax], xmm0, 0x1");
    TEST("\x62\xf3\x7d\x08\x16\x40\x01\x01", "vpextrd dword ptr [@ax+0x4], xmm0, 0x1");
    TEST("\x62\xf3\x7d\x08\x16\xc0\x01", "vpextrd eax, xmm0, 0x1");
    TEST3264("\x62\xf3\xfd\x08\x16\x00\x01", "vpextrd dword ptr [eax], xmm0, 0x1", "vpextrq qword ptr [rax], xmm0, 0x1"); // EVEX.W ignored
    TEST3264("\x62\xf3\xfd\x08\x16\x40\x01\x01", "vpextrd dword ptr [eax+0x4], xmm0, 0x1", "vpextrq qword ptr [rax+0x8], xmm0, 0x1"); // EVEX.W ignored
    TEST3264("\x62\xf3\xfd\x08\x16\xc0\x01", "vpextrd eax, xmm0, 0x1", "vpextrq rax, xmm0, 0x1"); // EVEX.W ignored
    TEST("\x62\xf3\x75\x08\x20\x00\x01", "vpinsrb xmm0, xmm1, byte ptr [@ax], 0x1");
    TEST("\x62\xf3\x75\x08\x20\x40\x01\x01", "vpinsrb xmm0, xmm1, byte ptr [@ax+0x1], 0x1");
    TEST("\x62\xf3\x75\x08\x20\xc0\x01", "vpinsrb xmm0, xmm1, al, 0x1");
    TEST("\x62\xf1\x75\x08\xc4\x00\x01", "vpinsrw xmm0, xmm1, word ptr [@ax], 0x1");
    TEST("\x62\xf1\x75\x08\xc4\x40\x01\x01", "vpinsrw xmm0, xmm1, word ptr [@ax+0x2], 0x1");
    TEST("\x62\xf1\x75\x08\xc4\xc0\x01", "vpinsrw xmm0, xmm1, ax, 0x1");
    TEST("\x62\xf3\x75\x08\x22\x00\x01", "vpinsrd xmm0, xmm1, dword ptr [@ax], 0x1");
    TEST("\x62\xf3\x75\x08\x22\x40\x01\x01", "vpinsrd xmm0, xmm1, dword ptr [@ax+0x4], 0x1");
    TEST("\x62\xf3\x75\x08\x22\xc0\x01", "vpinsrd xmm0, xmm1, eax, 0x1");
    TEST3264("\x62\xf3\xf5\x08\x22\x00\x01", "vpinsrd xmm0, xmm1, dword ptr [eax], 0x1", "vpinsrq xmm0, xmm1, qword ptr [rax], 0x1"); // EVEX.W ignored
    TEST3264("\x62\xf3\xf5\x08\x22\x40\x01\x01", "vpinsrd xmm0, xmm1, dword ptr [eax+0x4], 0x1", "vpinsrq xmm0, xmm1, qword ptr [rax+0x8], 0x1"); // EVEX.W ignored
    TEST3264("\x62\xf3\xf5\x08\x22\xc0\x01", "vpinsrd xmm0, xmm1, eax, 0x1", "vpinsrq xmm0, xmm1, rax, 0x1"); // EVEX.W ignored
    TEST("\x62\xf1\x7d\x08\x6e\x40\x01", "vmovd xmm0, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x7d\x28\x6e\x40\x01", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf1\x7d\x48\x6e\x40\x01", "UD"); // EVEX.L'L = 2
    TEST("\x62\xf1\x7d\x68\x6e\x40\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf1\x7d\x08\x6e\xc1", "vmovd xmm0, ecx");
    TEST("\x62\xf1\x7d\x28\x6e\xc1", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf1\x7d\x48\x6e\xc1", "UD"); // EVEX.L'L = 2
    TEST("\x62\xf1\x7d\x68\x6e\xc1", "UD"); // EVEX.L'L = 3
    TEST3264("\x62\xf1\xfd\x08\x6e\x40\x01", "vmovd xmm0, dword ptr [eax+0x4]", "vmovq xmm0, qword ptr [rax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xfd\x28\x6e\x40\x01", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf1\xfd\x48\x6e\x40\x01", "UD"); // EVEX.L'L = 2
    TEST("\x62\xf1\xfd\x68\x6e\x40\x01", "UD"); // EVEX.L'L = 3
    TEST3264("\x62\xf1\xfd\x08\x6e\xc1", "vmovd xmm0, ecx", "vmovq xmm0, rcx"); // EVEX.W ignored
    TEST("\x62\xf1\xfd\x28\x6e\xc1", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf1\xfd\x48\x6e\xc1", "UD"); // EVEX.L'L = 2
    TEST("\x62\xf1\xfd\x68\x6e\xc1", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf1\x7d\x08\x7e\x40\x01", "vmovd dword ptr [@ax+0x4], xmm0");
    TEST("\x62\xf1\x7d\x28\x7e\x40\x01", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf1\x7d\x48\x7e\x40\x01", "UD"); // EVEX.L'L = 2
    TEST("\x62\xf1\x7d\x68\x7e\x40\x01", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf1\x7d\x08\x7e\xc1", "vmovd ecx, xmm0");
    TEST("\x62\xf1\x7d\x28\x7e\xc1", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf1\x7d\x48\x7e\xc1", "UD"); // EVEX.L'L = 2
    TEST("\x62\xf1\x7d\x68\x7e\xc1", "UD"); // EVEX.L'L = 3
    TEST3264("\x62\xf1\xfd\x08\x7e\x40\x01", "vmovd dword ptr [eax+0x4], xmm0", "vmovq qword ptr [rax+0x8], xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xfd\x28\x7e\x40\x01", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf1\xfd\x48\x7e\x40\x01", "UD"); // EVEX.L'L = 2
    TEST("\x62\xf1\xfd\x68\x7e\x40\x01", "UD"); // EVEX.L'L = 3
    TEST3264("\x62\xf1\xfd\x08\x7e\xc1", "vmovd ecx, xmm0", "vmovq rcx, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xfd\x28\x7e\xc1", "UD"); // EVEX.L'L = 1
    TEST("\x62\xf1\xfd\x48\x7e\xc1", "UD"); // EVEX.L'L = 2
    TEST("\x62\xf1\xfd\x68\x7e\xc1", "UD"); // EVEX.L'L = 3
    TEST("\x62\xf2\x7d\x08\x7a\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\x7d\x08\x7a\xc0", "vpbroadcastb xmm0, al");
    TEST("\x62\xf2\x7d\x28\x7a\xc0", "vpbroadcastb ymm0, al");
    TEST("\x62\xf2\x7d\x48\x7a\xc0", "vpbroadcastb zmm0, al");
    TEST("\x62\xf2\xfd\x08\x7a\xc0", "UD"); // EVEX.W = 1
    TEST("\x62\xf2\x7d\x18\x7a\xc0", "UD"); // EVEX.b = 1
    TEST("\x62\xf2\x7d\x09\x7a\xc0", "vpbroadcastb xmm0{k1}, al");
    TEST("\x62\xf2\x7d\x89\x7a\xc0", "vpbroadcastb xmm0{k1}{z}, al");
    TEST("\x62\xf2\x7d\x08\x7b\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\x7d\x08\x7b\xc0", "vpbroadcastw xmm0, ax");
    TEST("\x62\xf2\x7d\x28\x7b\xc0", "vpbroadcastw ymm0, ax");
    TEST("\x62\xf2\x7d\x48\x7b\xc0", "vpbroadcastw zmm0, ax");
    TEST("\x62\xf2\xfd\x08\x7b\xc0", "UD"); // EVEX.W = 1
    TEST("\x62\xf2\x7d\x18\x7b\xc0", "UD"); // EVEX.b = 1
    TEST("\x62\xf2\x7d\x09\x7b\xc0", "vpbroadcastw xmm0{k1}, ax");
    TEST("\x62\xf2\x7d\x89\x7b\xc0", "vpbroadcastw xmm0{k1}{z}, ax");
    TEST("\x62\xf2\x7d\x08\x7c\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\x7d\x08\x7c\xc0", "vpbroadcastd xmm0, eax");
    TEST("\x62\xf2\x7d\x28\x7c\xc0", "vpbroadcastd ymm0, eax");
    TEST("\x62\xf2\x7d\x48\x7c\xc0", "vpbroadcastd zmm0, eax");
    TEST("\x62\xf2\x7d\x18\x7c\xc0", "UD"); // EVEX.b = 1
    TEST("\x62\xf2\x7d\x09\x7c\xc0", "vpbroadcastd xmm0{k1}, eax");
    TEST("\x62\xf2\x7d\x89\x7c\xc0", "vpbroadcastd xmm0{k1}{z}, eax");
    TEST("\x62\xf2\xfd\x08\x7c\x00", "UD"); // Must have register operand
    TEST3264("\x62\xf2\xfd\x08\x7c\xc0", "vpbroadcastd xmm0, eax", "vpbroadcastq xmm0, rax"); // EVEX.W ignored
    TEST3264("\x62\xf2\xfd\x28\x7c\xc0", "vpbroadcastd ymm0, eax", "vpbroadcastq ymm0, rax"); // EVEX.W ignored
    TEST3264("\x62\xf2\xfd\x48\x7c\xc0", "vpbroadcastd zmm0, eax", "vpbroadcastq zmm0, rax"); // EVEX.W ignored
    TEST("\x62\xf2\xfd\x18\x7c\xc0", "UD"); // EVEX.b = 1
    TEST3264("\x62\xf2\xfd\x09\x7c\xc0", "vpbroadcastd xmm0{k1}, eax", "vpbroadcastq xmm0{k1}, rax"); // EVEX.W ignored
    TEST3264("\x62\xf2\xfd\x89\x7c\xc0", "vpbroadcastd xmm0{k1}{z}, eax", "vpbroadcastq xmm0{k1}{z}, rax"); // EVEX.W ignored

    // EVEX.z with memory or mask destination is UD
    TEST32("\x62\xf2\x7d\x08\x63\x40\x01", "vpcompressb byte ptr [eax+0x1], xmm0");
    TEST32("\x67\x62\xf2\x7d\x08\x63\x40\x01", "vpcompressb byte ptr [bx+1*si+0x1], xmm0");
    TEST64("\x62\xf2\x7d\x08\x63\x40\x01", "vpcompressb byte ptr [rax+0x1], xmm0");
    TEST64("\x67\x62\xf2\x7d\x08\x63\x40\x01", "vpcompressb byte ptr [eax+0x1], xmm0");
    TEST32("\x62\xf2\x7d\x88\x63\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf2\x7d\x88\x63\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x62\xf2\x7d\x88\x63\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf2\x7d\x88\x63\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x62\xf2\x7d\x09\x63\x40\x01", "vpcompressb byte ptr [eax+0x1]{k1}, xmm0");
    TEST32("\x67\x62\xf2\x7d\x09\x63\x40\x01", "vpcompressb byte ptr [bx+1*si+0x1]{k1}, xmm0");
    TEST64("\x62\xf2\x7d\x09\x63\x40\x01", "vpcompressb byte ptr [rax+0x1]{k1}, xmm0");
    TEST64("\x67\x62\xf2\x7d\x09\x63\x40\x01", "vpcompressb byte ptr [eax+0x1]{k1}, xmm0");
    TEST32("\x62\xf2\x7d\x89\x63\x40\x01", "UD"); // EVEX.z = 1
    TEST32("\x67\x62\xf2\x7d\x89\x63\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x62\xf2\x7d\x89\x63\x40\x01", "UD"); // EVEX.z = 1
    TEST64("\x67\x62\xf2\x7d\x89\x63\x40\x01", "UD"); // EVEX.z = 1
    TEST("\x62\xf2\x7d\x08\x63\xc1", "vpcompressb xmm1, xmm0");
    TEST("\x62\xf2\x7d\x09\x63\xc1", "vpcompressb xmm1{k1}, xmm0");
    TEST("\x62\xf2\x7d\x88\x63\xc1", "UD"); // EVEX.z = 1
    TEST("\x62\xf2\x7d\x89\x63\xc1", "vpcompressb xmm1{k1}{z}, xmm0");
    TEST("\x62\xf1\x75\x08\x74\xc2", "vpcmpeqb k0, xmm1, xmm2");
    TEST("\x62\xf1\x75\x09\x74\xc2", "vpcmpeqb k0{k1}, xmm1, xmm2");
    TEST("\x62\xf1\x75\x88\x74\xc2", "UD"); // EVEX.z = 1
    TEST("\x62\xf1\x75\x89\x74\xc2", "UD"); // EVEX.z = 1

    // CVT(T?S[SD]2U?SI|U?SI2S[SD]) ignore EVEX.W in 32-bit mode.
    TEST("\x62\xf1\x7e\x08\x2c\x40\x01", "vcvttss2si eax, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x7e\x18\x2c\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x7e\x08\x2c\xc0", "vcvttss2si eax, xmm0");
    TEST("\x62\xf1\x7e\x18\x2c\xc0", "vcvttss2si eax, xmm0, {sae}");
    TEST("\x62\xf1\xfe\x08\x2c\x40\x01", "vcvttss2si @ax, dword ptr [@ax+0x4]"); // EVEX.W ignored
    TEST("\x62\xf1\xfe\x08\x2c\xc0", "vcvttss2si @ax, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xfe\x18\x2c\xc0", "vcvttss2si @ax, xmm0, {sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x7f\x08\x2c\x40\x01", "vcvttsd2si eax, qword ptr [@ax+0x8]");
    TEST("\x62\xf1\x7f\x18\x2c\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x7f\x08\x2c\xc0", "vcvttsd2si eax, xmm0");
    TEST("\x62\xf1\x7f\x18\x2c\xc0", "vcvttsd2si eax, xmm0, {sae}");
    TEST("\x62\xf1\xff\x08\x2c\x40\x01", "vcvttsd2si @ax, qword ptr [@ax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xff\x08\x2c\xc0", "vcvttsd2si @ax, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xff\x18\x2c\xc0", "vcvttsd2si @ax, xmm0, {sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x7e\x08\x2d\x40\x01", "vcvtss2si eax, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x7e\x18\x2d\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x7e\x08\x2d\xc0", "vcvtss2si eax, xmm0");
    TEST("\x62\xf1\x7e\x18\x2d\xc0", "vcvtss2si eax, xmm0, {rn-sae}");
    TEST("\x62\xf1\xfe\x08\x2d\x40\x01", "vcvtss2si @ax, dword ptr [@ax+0x4]"); // EVEX.W ignored
    TEST("\x62\xf1\xfe\x08\x2d\xc0", "vcvtss2si @ax, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xfe\x18\x2d\xc0", "vcvtss2si @ax, xmm0, {rn-sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x7f\x08\x2d\x40\x01", "vcvtsd2si eax, qword ptr [@ax+0x8]");
    TEST("\x62\xf1\x7f\x18\x2d\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x7f\x08\x2d\xc0", "vcvtsd2si eax, xmm0");
    TEST("\x62\xf1\x7f\x18\x2d\xc0", "vcvtsd2si eax, xmm0, {rn-sae}");
    TEST("\x62\xf1\xff\x08\x2d\x40\x01", "vcvtsd2si @ax, qword ptr [@ax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xff\x08\x2d\xc0", "vcvtsd2si @ax, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xff\x18\x2d\xc0", "vcvtsd2si @ax, xmm0, {rn-sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x7e\x08\x78\x40\x01", "vcvttss2usi eax, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x7e\x18\x78\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x7e\x08\x78\xc0", "vcvttss2usi eax, xmm0");
    TEST("\x62\xf1\x7e\x18\x78\xc0", "vcvttss2usi eax, xmm0, {sae}");
    TEST("\x62\xf1\xfe\x08\x78\x40\x01", "vcvttss2usi @ax, dword ptr [@ax+0x4]"); // EVEX.W ignored
    TEST("\x62\xf1\xfe\x08\x78\xc0", "vcvttss2usi @ax, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xfe\x18\x78\xc0", "vcvttss2usi @ax, xmm0, {sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x7f\x08\x78\x40\x01", "vcvttsd2usi eax, qword ptr [@ax+0x8]");
    TEST("\x62\xf1\x7f\x18\x78\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x7f\x08\x78\xc0", "vcvttsd2usi eax, xmm0");
    TEST("\x62\xf1\x7f\x18\x78\xc0", "vcvttsd2usi eax, xmm0, {sae}");
    TEST("\x62\xf1\xff\x08\x78\x40\x01", "vcvttsd2usi @ax, qword ptr [@ax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xff\x08\x78\xc0", "vcvttsd2usi @ax, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xff\x18\x78\xc0", "vcvttsd2usi @ax, xmm0, {sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x7e\x08\x79\x40\x01", "vcvtss2usi eax, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x7e\x18\x79\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x7e\x08\x79\xc0", "vcvtss2usi eax, xmm0");
    TEST("\x62\xf1\x7e\x18\x79\xc0", "vcvtss2usi eax, xmm0, {rn-sae}");
    TEST("\x62\xf1\xfe\x08\x79\x40\x01", "vcvtss2usi @ax, dword ptr [@ax+0x4]"); // EVEX.W ignored
    TEST("\x62\xf1\xfe\x08\x79\xc0", "vcvtss2usi @ax, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xfe\x18\x79\xc0", "vcvtss2usi @ax, xmm0, {rn-sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x7f\x08\x79\x40\x01", "vcvtsd2usi eax, qword ptr [@ax+0x8]");
    TEST("\x62\xf1\x7f\x18\x79\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x7f\x08\x79\xc0", "vcvtsd2usi eax, xmm0");
    TEST("\x62\xf1\x7f\x18\x79\xc0", "vcvtsd2usi eax, xmm0, {rn-sae}");
    TEST("\x62\xf1\xff\x08\x79\x40\x01", "vcvtsd2usi @ax, qword ptr [@ax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xff\x08\x79\xc0", "vcvtsd2usi @ax, xmm0"); // EVEX.W ignored
    TEST("\x62\xf1\xff\x18\x79\xc0", "vcvtsd2usi @ax, xmm0, {rn-sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x6e\x08\x2a\x40\x01", "vcvtsi2ss xmm0, xmm2, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x6e\x18\x2a\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x6e\x08\x2a\xc0", "vcvtsi2ss xmm0, xmm2, eax");
    TEST("\x62\xf1\x6e\x18\x2a\xc0", "vcvtsi2ss xmm0, xmm2, eax, {rn-sae}");
    TEST3264("\x62\xf1\xee\x08\x2a\x40\x01", "vcvtsi2ss xmm0, xmm2, dword ptr [eax+0x4]", "vcvtsi2ss xmm0, xmm2, qword ptr [rax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xee\x08\x2a\xc0", "vcvtsi2ss xmm0, xmm2, @ax"); // EVEX.W ignored
    TEST("\x62\xf1\xee\x18\x2a\xc0", "vcvtsi2ss xmm0, xmm2, @ax, {rn-sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x6f\x08\x2a\x40\x01", "vcvtsi2sd xmm0, xmm2, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x6f\x18\x2a\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x6f\x08\x2a\xc0", "vcvtsi2sd xmm0, xmm2, eax");
    TEST("\x62\xf1\x6f\x18\x2a\xc0", "vcvtsi2sd xmm0, xmm2, eax, {rn-sae}");
    TEST3264("\x62\xf1\xef\x08\x2a\x40\x01", "vcvtsi2sd xmm0, xmm2, dword ptr [eax+0x4]", "vcvtsi2sd xmm0, xmm2, qword ptr [rax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xef\x08\x2a\xc0", "vcvtsi2sd xmm0, xmm2, @ax"); // EVEX.W ignored
    TEST("\x62\xf1\xef\x18\x2a\xc0", "vcvtsi2sd xmm0, xmm2, @ax, {rn-sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x6e\x08\x7b\x40\x01", "vcvtusi2ss xmm0, xmm2, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x6e\x18\x7b\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x6e\x08\x7b\xc0", "vcvtusi2ss xmm0, xmm2, eax");
    TEST("\x62\xf1\x6e\x18\x7b\xc0", "vcvtusi2ss xmm0, xmm2, eax, {rn-sae}");
    TEST3264("\x62\xf1\xee\x08\x7b\x40\x01", "vcvtusi2ss xmm0, xmm2, dword ptr [eax+0x4]", "vcvtusi2ss xmm0, xmm2, qword ptr [rax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xee\x08\x7b\xc0", "vcvtusi2ss xmm0, xmm2, @ax"); // EVEX.W ignored
    TEST("\x62\xf1\xee\x18\x7b\xc0", "vcvtusi2ss xmm0, xmm2, @ax, {rn-sae}"); // EVEX.W ignored
    TEST("\x62\xf1\x6f\x08\x7b\x40\x01", "vcvtusi2sd xmm0, xmm2, dword ptr [@ax+0x4]");
    TEST("\x62\xf1\x6f\x18\x7b\x40\x01", "UD"); // EVEX.b with memory operand
    TEST("\x62\xf1\x6f\x08\x7b\xc0", "vcvtusi2sd xmm0, xmm2, eax");
    TEST("\x62\xf1\x6f\x18\x7b\xc0", "vcvtusi2sd xmm0, xmm2, eax, {rn-sae}");
    TEST3264("\x62\xf1\xef\x08\x7b\x40\x01", "vcvtusi2sd xmm0, xmm2, dword ptr [eax+0x4]", "vcvtusi2sd xmm0, xmm2, qword ptr [rax+0x8]"); // EVEX.W ignored
    TEST("\x62\xf1\xef\x08\x7b\xc0", "vcvtusi2sd xmm0, xmm2, @ax"); // EVEX.W ignored
    TEST("\x62\xf1\xef\x18\x7b\xc0", "vcvtusi2sd xmm0, xmm2, @ax, {rn-sae}"); // EVEX.W ignored

    // 32-bit mode: no UD constraints for K-reg
    // 64-bit mode: EVEX.R/EVEX.vvvv=0xxx causes UD for K-reg; EVEX.B is ignored
    TEST("\xc5\xed\x41\x00", "UD"); // Must have register operand
    TEST("\xc5\xed\x41\xcb", "kandb k1, k2, k3");
    TEST("\xc4\xe1\x6d\x41\xcb", "kandb k1, k2, k3"); // 3-byte VEX encoding
    TEST("\xc4\xc1\x6d\x41\xcb", "kandb k1, k2, k3"); // VEX.B is ignored
    TEST64("\xc4\x61\x6d\x41\xcb", "UD"); // VEX.R is UD
    TEST3264("\xc4\xe1\x2d\x41\xcb", "kandb k1, k2, k3", "UD"); // 32-bit: VEX.vvvv MSB is ignored, 64-bit: VEX.vvvv = 0xxx
    TEST64("\xc5\xad\x41\xcb", "UD"); // VEX.vvvv = 0xxx

    TEST("\x62\xf2\x7e\x08\x28\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\x7e\x08\x28\xc1", "vpmovm2b xmm0, k1");
    TEST3264("\x62\xe2\x7e\x08\x28\xc1", "vpmovm2b xmm0, k1", "vpmovm2b xmm16, k1"); // EVEX.R' ignored
    TEST("\x62\xd2\x7e\x08\x28\xc1", "vpmovm2b xmm0, k1"); // EVEX.B ignored
    TEST64("\x62\xb2\x7e\x08\x28\xc1", "vpmovm2b xmm0, k1"); // EVEX.X ignored
    TEST64("\x62\x72\x7e\x08\x28\xc1", "vpmovm2b xmm8, k1");
    TEST("\x62\xf2\xfe\x08\x28\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\xfe\x08\x28\xc1", "vpmovm2w xmm0, k1");
    TEST3264("\x62\xe2\xfe\x08\x28\xc1", "vpmovm2w xmm0, k1", "vpmovm2w xmm16, k1"); // EVEX.R' ignored
    TEST("\x62\xd2\xfe\x08\x28\xc1", "vpmovm2w xmm0, k1"); // EVEX.B ignored
    TEST64("\x62\xb2\xfe\x08\x28\xc1", "vpmovm2w xmm0, k1"); // EVEX.X ignored
    TEST64("\x62\x72\xfe\x08\x28\xc1", "vpmovm2w xmm8, k1");
    TEST("\x62\xf2\x7e\x08\x38\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\x7e\x08\x38\xc1", "vpmovm2d xmm0, k1");
    TEST3264("\x62\xe2\x7e\x08\x38\xc1", "vpmovm2d xmm0, k1", "vpmovm2d xmm16, k1"); // EVEX.R' ignored
    TEST("\x62\xd2\x7e\x08\x38\xc1", "vpmovm2d xmm0, k1"); // EVEX.B ignored
    TEST64("\x62\xb2\x7e\x08\x38\xc1", "vpmovm2d xmm0, k1"); // EVEX.X ignored
    TEST64("\x62\x72\x7e\x08\x38\xc1", "vpmovm2d xmm8, k1");
    TEST("\x62\xf2\xfe\x08\x38\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\xfe\x08\x38\xc1", "vpmovm2q xmm0, k1");
    TEST3264("\x62\xe2\xfe\x08\x38\xc1", "vpmovm2q xmm0, k1", "vpmovm2q xmm16, k1"); // EVEX.R' ignored
    TEST("\x62\xd2\xfe\x08\x38\xc1", "vpmovm2q xmm0, k1"); // EVEX.B ignored
    TEST64("\x62\xb2\xfe\x08\x38\xc1", "vpmovm2q xmm0, k1"); // EVEX.X ignored
    TEST64("\x62\x72\xfe\x08\x38\xc1", "vpmovm2q xmm8, k1");

    TEST("\x62\xf2\x7e\x08\x29\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\x7e\x08\x29\xc1", "vpmovb2m k0, xmm1");
    TEST3264("\x62\xe2\x7e\x08\x29\xc1", "vpmovb2m k0, xmm1", "UD"); // 32-bit: EVEX.R' ignored, 64-bit: EVEX.R' for mask is UD
    TEST3264("\x62\xd2\x7e\x08\x29\xc1", "vpmovb2m k0, xmm1", "vpmovb2m k0, xmm9"); // EVEX.B ignored
    TEST64("\x62\xb2\x7e\x08\x29\xc1", "vpmovb2m k0, xmm17");
    TEST64("\x62\x72\x7e\x08\x29\xc1", "UD"); // EVEX.R for mask is UD
    TEST("\x62\xf2\xfe\x08\x29\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\xfe\x08\x29\xc1", "vpmovw2m k0, xmm1");
    TEST3264("\x62\xe2\xfe\x08\x29\xc1", "vpmovw2m k0, xmm1", "UD"); // 32-bit: EVEX.R' ignored, 64-bit: EVEX.R' for mask is UD
    TEST3264("\x62\xd2\xfe\x08\x29\xc1", "vpmovw2m k0, xmm1", "vpmovw2m k0, xmm9"); // EVEX.B ignored
    TEST64("\x62\xb2\xfe\x08\x29\xc1", "vpmovw2m k0, xmm17");
    TEST64("\x62\x72\xfe\x08\x29\xc1", "UD"); // EVEX.R for mask is UD
    TEST("\x62\xf2\x7e\x08\x39\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\x7e\x08\x39\xc1", "vpmovd2m k0, xmm1");
    TEST3264("\x62\xe2\x7e\x08\x39\xc1", "vpmovd2m k0, xmm1", "UD"); // 32-bit: EVEX.R' ignored, 64-bit: EVEX.R' for mask is UD
    TEST3264("\x62\xd2\x7e\x08\x39\xc1", "vpmovd2m k0, xmm1", "vpmovd2m k0, xmm9"); // EVEX.B ignored
    TEST64("\x62\xb2\x7e\x08\x39\xc1", "vpmovd2m k0, xmm17");
    TEST64("\x62\x72\x7e\x08\x39\xc1", "UD"); // EVEX.R for mask is UD
    TEST("\x62\xf2\xfe\x08\x39\x00", "UD"); // Must have register operand
    TEST("\x62\xf2\xfe\x08\x39\xc1", "vpmovq2m k0, xmm1");
    TEST3264("\x62\xe2\xfe\x08\x39\xc1", "vpmovq2m k0, xmm1", "UD"); // 32-bit: EVEX.R' ignored, 64-bit: EVEX.R' for mask is UD
    TEST3264("\x62\xd2\xfe\x08\x39\xc1", "vpmovq2m k0, xmm1", "vpmovq2m k0, xmm9"); // EVEX.B ignored
    TEST64("\x62\xb2\xfe\x08\x39\xc1", "vpmovq2m k0, xmm17");
    TEST64("\x62\x72\xfe\x08\x39\xc1", "UD"); // EVEX.R for mask is UD

    // VSIB encoding, test all combinations of EVEX.RXBR'V' once
    TEST("\x62\xf2\x7d\x0a\xa2\xcc", "UD"); // Must have memory operand
    TEST("\x62\xf2\x7d\x0a\xa2\x01", "UD"); // Must have SIB byte
    TEST("\x62\xf2\x7d\x08\xa2\x0c\xe7", "UD"); // EVEX.aaa = 000
    TEST3264("\x67\x62\xf2\x7d\x0a\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [edi+8*xmm4]{k2}, xmm1"); // VISB and 16-bit addrsize is UD
    TEST("\x62\xf2\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [@di+8*xmm4]{k2}, xmm1");
    TEST3264("\x62\xd2\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterdps dword ptr [r15+8*xmm4]{k2}, xmm1");
    TEST64("\x62\xb2\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm12]{k2}, xmm1");
    TEST64("\x62\x92\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm12]{k2}, xmm1");
    TEST3264("\x62\xf2\x7d\x02\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [rdi+8*xmm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\x7d\x02\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [r15+8*xmm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm28]{k2}, xmm1");
    TEST64("\x62\x92\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm28]{k2}, xmm1");
    TEST64("\x62\x72\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm4]{k2}, xmm9");
    TEST64("\x62\x52\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm4]{k2}, xmm9");
    TEST64("\x62\x32\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm12]{k2}, xmm9");
    TEST64("\x62\x12\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm12]{k2}, xmm9");
    TEST64("\x62\x72\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm20]{k2}, xmm9");
    TEST64("\x62\x52\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm20]{k2}, xmm9");
    TEST64("\x62\x32\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm28]{k2}, xmm9");
    TEST64("\x62\x12\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm28]{k2}, xmm9");
    TEST3264("\x62\xe2\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterdps dword ptr [rdi+8*xmm4]{k2}, xmm17");
    TEST3264("\x62\xc2\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterdps dword ptr [r15+8*xmm4]{k2}, xmm17");
    TEST64("\x62\xa2\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm12]{k2}, xmm17");
    TEST64("\x62\x82\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm12]{k2}, xmm17");
    TEST3264("\x62\xe2\x7d\x02\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [rdi+8*xmm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\x7d\x02\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [r15+8*xmm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm28]{k2}, xmm17");
    TEST64("\x62\x82\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm28]{k2}, xmm17");
    TEST64("\x62\x62\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm4]{k2}, xmm25");
    TEST64("\x62\x42\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm4]{k2}, xmm25");
    TEST64("\x62\x22\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm12]{k2}, xmm25");
    TEST64("\x62\x02\x7d\x0a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm12]{k2}, xmm25");
    TEST64("\x62\x62\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm20]{k2}, xmm25");
    TEST64("\x62\x42\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm20]{k2}, xmm25");
    TEST64("\x62\x22\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*xmm28]{k2}, xmm25");
    TEST64("\x62\x02\x7d\x02\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*xmm28]{k2}, xmm25");
    TEST("\x62\xf2\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [@di+8*ymm4]{k2}, ymm1");
    TEST3264("\x62\xd2\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*ymm4]{k2}, ymm1", "vscatterdps dword ptr [r15+8*ymm4]{k2}, ymm1");
    TEST64("\x62\xb2\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm12]{k2}, ymm1");
    TEST64("\x62\x92\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm12]{k2}, ymm1");
    TEST3264("\x62\xf2\x7d\x22\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [rdi+8*ymm20]{k2}, ymm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\x7d\x22\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [r15+8*ymm20]{k2}, ymm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm28]{k2}, ymm1");
    TEST64("\x62\x92\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm28]{k2}, ymm1");
    TEST64("\x62\x72\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm4]{k2}, ymm9");
    TEST64("\x62\x52\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm4]{k2}, ymm9");
    TEST64("\x62\x32\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm12]{k2}, ymm9");
    TEST64("\x62\x12\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm12]{k2}, ymm9");
    TEST64("\x62\x72\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm20]{k2}, ymm9");
    TEST64("\x62\x52\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm20]{k2}, ymm9");
    TEST64("\x62\x32\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm28]{k2}, ymm9");
    TEST64("\x62\x12\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm28]{k2}, ymm9");
    TEST3264("\x62\xe2\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*ymm4]{k2}, ymm1", "vscatterdps dword ptr [rdi+8*ymm4]{k2}, ymm17");
    TEST3264("\x62\xc2\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*ymm4]{k2}, ymm1", "vscatterdps dword ptr [r15+8*ymm4]{k2}, ymm17");
    TEST64("\x62\xa2\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm12]{k2}, ymm17");
    TEST64("\x62\x82\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm12]{k2}, ymm17");
    TEST3264("\x62\xe2\x7d\x22\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [rdi+8*ymm20]{k2}, ymm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\x7d\x22\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [r15+8*ymm20]{k2}, ymm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm28]{k2}, ymm17");
    TEST64("\x62\x82\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm28]{k2}, ymm17");
    TEST64("\x62\x62\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm4]{k2}, ymm25");
    TEST64("\x62\x42\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm4]{k2}, ymm25");
    TEST64("\x62\x22\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm12]{k2}, ymm25");
    TEST64("\x62\x02\x7d\x2a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm12]{k2}, ymm25");
    TEST64("\x62\x62\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm20]{k2}, ymm25");
    TEST64("\x62\x42\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm20]{k2}, ymm25");
    TEST64("\x62\x22\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*ymm28]{k2}, ymm25");
    TEST64("\x62\x02\x7d\x22\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*ymm28]{k2}, ymm25");
    TEST("\x62\xf2\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [@di+8*zmm4]{k2}, zmm1");
    TEST3264("\x62\xd2\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*zmm4]{k2}, zmm1", "vscatterdps dword ptr [r15+8*zmm4]{k2}, zmm1");
    TEST64("\x62\xb2\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm12]{k2}, zmm1");
    TEST64("\x62\x92\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm12]{k2}, zmm1");
    TEST3264("\x62\xf2\x7d\x42\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [rdi+8*zmm20]{k2}, zmm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\x7d\x42\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [r15+8*zmm20]{k2}, zmm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm28]{k2}, zmm1");
    TEST64("\x62\x92\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm28]{k2}, zmm1");
    TEST64("\x62\x72\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm4]{k2}, zmm9");
    TEST64("\x62\x52\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm4]{k2}, zmm9");
    TEST64("\x62\x32\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm12]{k2}, zmm9");
    TEST64("\x62\x12\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm12]{k2}, zmm9");
    TEST64("\x62\x72\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm20]{k2}, zmm9");
    TEST64("\x62\x52\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm20]{k2}, zmm9");
    TEST64("\x62\x32\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm28]{k2}, zmm9");
    TEST64("\x62\x12\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm28]{k2}, zmm9");
    TEST3264("\x62\xe2\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*zmm4]{k2}, zmm1", "vscatterdps dword ptr [rdi+8*zmm4]{k2}, zmm17");
    TEST3264("\x62\xc2\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [edi+8*zmm4]{k2}, zmm1", "vscatterdps dword ptr [r15+8*zmm4]{k2}, zmm17");
    TEST64("\x62\xa2\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm12]{k2}, zmm17");
    TEST64("\x62\x82\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm12]{k2}, zmm17");
    TEST3264("\x62\xe2\x7d\x42\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [rdi+8*zmm20]{k2}, zmm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\x7d\x42\xa2\x0c\xe7", "UD", "vscatterdps dword ptr [r15+8*zmm20]{k2}, zmm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm28]{k2}, zmm17");
    TEST64("\x62\x82\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm28]{k2}, zmm17");
    TEST64("\x62\x62\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm4]{k2}, zmm25");
    TEST64("\x62\x42\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm4]{k2}, zmm25");
    TEST64("\x62\x22\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm12]{k2}, zmm25");
    TEST64("\x62\x02\x7d\x4a\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm12]{k2}, zmm25");
    TEST64("\x62\x62\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm20]{k2}, zmm25");
    TEST64("\x62\x42\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm20]{k2}, zmm25");
    TEST64("\x62\x22\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [rdi+8*zmm28]{k2}, zmm25");
    TEST64("\x62\x02\x7d\x42\xa2\x0c\xe7", "vscatterdps dword ptr [r15+8*zmm28]{k2}, zmm25");
    TEST("\x62\xf2\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [@di+8*xmm4]{k2}, xmm1");
    TEST3264("\x62\xd2\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterqps dword ptr [r15+8*xmm4]{k2}, xmm1");
    TEST64("\x62\xb2\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm12]{k2}, xmm1");
    TEST64("\x62\x92\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm12]{k2}, xmm1");
    TEST3264("\x62\xf2\x7d\x02\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [rdi+8*xmm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\x7d\x02\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [r15+8*xmm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm28]{k2}, xmm1");
    TEST64("\x62\x92\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm28]{k2}, xmm1");
    TEST64("\x62\x72\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm4]{k2}, xmm9");
    TEST64("\x62\x52\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm4]{k2}, xmm9");
    TEST64("\x62\x32\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm12]{k2}, xmm9");
    TEST64("\x62\x12\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm12]{k2}, xmm9");
    TEST64("\x62\x72\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm20]{k2}, xmm9");
    TEST64("\x62\x52\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm20]{k2}, xmm9");
    TEST64("\x62\x32\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm28]{k2}, xmm9");
    TEST64("\x62\x12\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm28]{k2}, xmm9");
    TEST3264("\x62\xe2\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterqps dword ptr [rdi+8*xmm4]{k2}, xmm17");
    TEST3264("\x62\xc2\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterqps dword ptr [r15+8*xmm4]{k2}, xmm17");
    TEST64("\x62\xa2\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm12]{k2}, xmm17");
    TEST64("\x62\x82\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm12]{k2}, xmm17");
    TEST3264("\x62\xe2\x7d\x02\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [rdi+8*xmm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\x7d\x02\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [r15+8*xmm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm28]{k2}, xmm17");
    TEST64("\x62\x82\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm28]{k2}, xmm17");
    TEST64("\x62\x62\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm4]{k2}, xmm25");
    TEST64("\x62\x42\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm4]{k2}, xmm25");
    TEST64("\x62\x22\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm12]{k2}, xmm25");
    TEST64("\x62\x02\x7d\x0a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm12]{k2}, xmm25");
    TEST64("\x62\x62\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm20]{k2}, xmm25");
    TEST64("\x62\x42\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm20]{k2}, xmm25");
    TEST64("\x62\x22\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*xmm28]{k2}, xmm25");
    TEST64("\x62\x02\x7d\x02\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*xmm28]{k2}, xmm25");
    TEST("\x62\xf2\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [@di+8*ymm4]{k2}, xmm1");
    TEST3264("\x62\xd2\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*ymm4]{k2}, xmm1", "vscatterqps dword ptr [r15+8*ymm4]{k2}, xmm1");
    TEST64("\x62\xb2\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm12]{k2}, xmm1");
    TEST64("\x62\x92\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm12]{k2}, xmm1");
    TEST3264("\x62\xf2\x7d\x22\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [rdi+8*ymm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\x7d\x22\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [r15+8*ymm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm28]{k2}, xmm1");
    TEST64("\x62\x92\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm28]{k2}, xmm1");
    TEST64("\x62\x72\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm4]{k2}, xmm9");
    TEST64("\x62\x52\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm4]{k2}, xmm9");
    TEST64("\x62\x32\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm12]{k2}, xmm9");
    TEST64("\x62\x12\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm12]{k2}, xmm9");
    TEST64("\x62\x72\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm20]{k2}, xmm9");
    TEST64("\x62\x52\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm20]{k2}, xmm9");
    TEST64("\x62\x32\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm28]{k2}, xmm9");
    TEST64("\x62\x12\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm28]{k2}, xmm9");
    TEST3264("\x62\xe2\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*ymm4]{k2}, xmm1", "vscatterqps dword ptr [rdi+8*ymm4]{k2}, xmm17");
    TEST3264("\x62\xc2\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*ymm4]{k2}, xmm1", "vscatterqps dword ptr [r15+8*ymm4]{k2}, xmm17");
    TEST64("\x62\xa2\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm12]{k2}, xmm17");
    TEST64("\x62\x82\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm12]{k2}, xmm17");
    TEST3264("\x62\xe2\x7d\x22\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [rdi+8*ymm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\x7d\x22\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [r15+8*ymm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm28]{k2}, xmm17");
    TEST64("\x62\x82\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm28]{k2}, xmm17");
    TEST64("\x62\x62\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm4]{k2}, xmm25");
    TEST64("\x62\x42\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm4]{k2}, xmm25");
    TEST64("\x62\x22\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm12]{k2}, xmm25");
    TEST64("\x62\x02\x7d\x2a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm12]{k2}, xmm25");
    TEST64("\x62\x62\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm20]{k2}, xmm25");
    TEST64("\x62\x42\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm20]{k2}, xmm25");
    TEST64("\x62\x22\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*ymm28]{k2}, xmm25");
    TEST64("\x62\x02\x7d\x22\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*ymm28]{k2}, xmm25");
    TEST("\x62\xf2\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [@di+8*zmm4]{k2}, ymm1");
    TEST3264("\x62\xd2\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*zmm4]{k2}, ymm1", "vscatterqps dword ptr [r15+8*zmm4]{k2}, ymm1");
    TEST64("\x62\xb2\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm12]{k2}, ymm1");
    TEST64("\x62\x92\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm12]{k2}, ymm1");
    TEST3264("\x62\xf2\x7d\x42\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [rdi+8*zmm20]{k2}, ymm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\x7d\x42\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [r15+8*zmm20]{k2}, ymm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm28]{k2}, ymm1");
    TEST64("\x62\x92\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm28]{k2}, ymm1");
    TEST64("\x62\x72\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm4]{k2}, ymm9");
    TEST64("\x62\x52\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm4]{k2}, ymm9");
    TEST64("\x62\x32\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm12]{k2}, ymm9");
    TEST64("\x62\x12\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm12]{k2}, ymm9");
    TEST64("\x62\x72\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm20]{k2}, ymm9");
    TEST64("\x62\x52\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm20]{k2}, ymm9");
    TEST64("\x62\x32\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm28]{k2}, ymm9");
    TEST64("\x62\x12\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm28]{k2}, ymm9");
    TEST3264("\x62\xe2\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*zmm4]{k2}, ymm1", "vscatterqps dword ptr [rdi+8*zmm4]{k2}, ymm17");
    TEST3264("\x62\xc2\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [edi+8*zmm4]{k2}, ymm1", "vscatterqps dword ptr [r15+8*zmm4]{k2}, ymm17");
    TEST64("\x62\xa2\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm12]{k2}, ymm17");
    TEST64("\x62\x82\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm12]{k2}, ymm17");
    TEST3264("\x62\xe2\x7d\x42\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [rdi+8*zmm20]{k2}, ymm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\x7d\x42\xa3\x0c\xe7", "UD", "vscatterqps dword ptr [r15+8*zmm20]{k2}, ymm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm28]{k2}, ymm17");
    TEST64("\x62\x82\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm28]{k2}, ymm17");
    TEST64("\x62\x62\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm4]{k2}, ymm25");
    TEST64("\x62\x42\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm4]{k2}, ymm25");
    TEST64("\x62\x22\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm12]{k2}, ymm25");
    TEST64("\x62\x02\x7d\x4a\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm12]{k2}, ymm25");
    TEST64("\x62\x62\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm20]{k2}, ymm25");
    TEST64("\x62\x42\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm20]{k2}, ymm25");
    TEST64("\x62\x22\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [rdi+8*zmm28]{k2}, ymm25");
    TEST64("\x62\x02\x7d\x42\xa3\x0c\xe7", "vscatterqps dword ptr [r15+8*zmm28]{k2}, ymm25");
    TEST("\x62\xf2\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [@di+8*xmm4]{k2}, xmm1");
    TEST3264("\x62\xd2\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterdpd qword ptr [r15+8*xmm4]{k2}, xmm1");
    TEST64("\x62\xb2\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm12]{k2}, xmm1");
    TEST64("\x62\x92\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm12]{k2}, xmm1");
    TEST3264("\x62\xf2\xfd\x02\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [rdi+8*xmm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\xfd\x02\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [r15+8*xmm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm28]{k2}, xmm1");
    TEST64("\x62\x92\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm28]{k2}, xmm1");
    TEST64("\x62\x72\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm4]{k2}, xmm9");
    TEST64("\x62\x52\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm4]{k2}, xmm9");
    TEST64("\x62\x32\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm12]{k2}, xmm9");
    TEST64("\x62\x12\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm12]{k2}, xmm9");
    TEST64("\x62\x72\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm20]{k2}, xmm9");
    TEST64("\x62\x52\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm20]{k2}, xmm9");
    TEST64("\x62\x32\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm28]{k2}, xmm9");
    TEST64("\x62\x12\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm28]{k2}, xmm9");
    TEST3264("\x62\xe2\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterdpd qword ptr [rdi+8*xmm4]{k2}, xmm17");
    TEST3264("\x62\xc2\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterdpd qword ptr [r15+8*xmm4]{k2}, xmm17");
    TEST64("\x62\xa2\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm12]{k2}, xmm17");
    TEST64("\x62\x82\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm12]{k2}, xmm17");
    TEST3264("\x62\xe2\xfd\x02\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [rdi+8*xmm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\xfd\x02\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [r15+8*xmm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm28]{k2}, xmm17");
    TEST64("\x62\x82\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm28]{k2}, xmm17");
    TEST64("\x62\x62\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm4]{k2}, xmm25");
    TEST64("\x62\x42\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm4]{k2}, xmm25");
    TEST64("\x62\x22\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm12]{k2}, xmm25");
    TEST64("\x62\x02\xfd\x0a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm12]{k2}, xmm25");
    TEST64("\x62\x62\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm20]{k2}, xmm25");
    TEST64("\x62\x42\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm20]{k2}, xmm25");
    TEST64("\x62\x22\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm28]{k2}, xmm25");
    TEST64("\x62\x02\xfd\x02\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm28]{k2}, xmm25");
    TEST("\x62\xf2\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [@di+8*xmm4]{k2}, ymm1");
    TEST3264("\x62\xd2\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*xmm4]{k2}, ymm1", "vscatterdpd qword ptr [r15+8*xmm4]{k2}, ymm1");
    TEST64("\x62\xb2\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm12]{k2}, ymm1");
    TEST64("\x62\x92\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm12]{k2}, ymm1");
    TEST3264("\x62\xf2\xfd\x22\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [rdi+8*xmm20]{k2}, ymm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\xfd\x22\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [r15+8*xmm20]{k2}, ymm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm28]{k2}, ymm1");
    TEST64("\x62\x92\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm28]{k2}, ymm1");
    TEST64("\x62\x72\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm4]{k2}, ymm9");
    TEST64("\x62\x52\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm4]{k2}, ymm9");
    TEST64("\x62\x32\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm12]{k2}, ymm9");
    TEST64("\x62\x12\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm12]{k2}, ymm9");
    TEST64("\x62\x72\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm20]{k2}, ymm9");
    TEST64("\x62\x52\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm20]{k2}, ymm9");
    TEST64("\x62\x32\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm28]{k2}, ymm9");
    TEST64("\x62\x12\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm28]{k2}, ymm9");
    TEST3264("\x62\xe2\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*xmm4]{k2}, ymm1", "vscatterdpd qword ptr [rdi+8*xmm4]{k2}, ymm17");
    TEST3264("\x62\xc2\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*xmm4]{k2}, ymm1", "vscatterdpd qword ptr [r15+8*xmm4]{k2}, ymm17");
    TEST64("\x62\xa2\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm12]{k2}, ymm17");
    TEST64("\x62\x82\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm12]{k2}, ymm17");
    TEST3264("\x62\xe2\xfd\x22\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [rdi+8*xmm20]{k2}, ymm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\xfd\x22\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [r15+8*xmm20]{k2}, ymm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm28]{k2}, ymm17");
    TEST64("\x62\x82\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm28]{k2}, ymm17");
    TEST64("\x62\x62\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm4]{k2}, ymm25");
    TEST64("\x62\x42\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm4]{k2}, ymm25");
    TEST64("\x62\x22\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm12]{k2}, ymm25");
    TEST64("\x62\x02\xfd\x2a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm12]{k2}, ymm25");
    TEST64("\x62\x62\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm20]{k2}, ymm25");
    TEST64("\x62\x42\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm20]{k2}, ymm25");
    TEST64("\x62\x22\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*xmm28]{k2}, ymm25");
    TEST64("\x62\x02\xfd\x22\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*xmm28]{k2}, ymm25");
    TEST("\x62\xf2\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [@di+8*ymm4]{k2}, zmm1");
    TEST3264("\x62\xd2\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*ymm4]{k2}, zmm1", "vscatterdpd qword ptr [r15+8*ymm4]{k2}, zmm1");
    TEST64("\x62\xb2\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm12]{k2}, zmm1");
    TEST64("\x62\x92\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm12]{k2}, zmm1");
    TEST3264("\x62\xf2\xfd\x42\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [rdi+8*ymm20]{k2}, zmm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\xfd\x42\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [r15+8*ymm20]{k2}, zmm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm28]{k2}, zmm1");
    TEST64("\x62\x92\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm28]{k2}, zmm1");
    TEST64("\x62\x72\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm4]{k2}, zmm9");
    TEST64("\x62\x52\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm4]{k2}, zmm9");
    TEST64("\x62\x32\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm12]{k2}, zmm9");
    TEST64("\x62\x12\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm12]{k2}, zmm9");
    TEST64("\x62\x72\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm20]{k2}, zmm9");
    TEST64("\x62\x52\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm20]{k2}, zmm9");
    TEST64("\x62\x32\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm28]{k2}, zmm9");
    TEST64("\x62\x12\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm28]{k2}, zmm9");
    TEST3264("\x62\xe2\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*ymm4]{k2}, zmm1", "vscatterdpd qword ptr [rdi+8*ymm4]{k2}, zmm17");
    TEST3264("\x62\xc2\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [edi+8*ymm4]{k2}, zmm1", "vscatterdpd qword ptr [r15+8*ymm4]{k2}, zmm17");
    TEST64("\x62\xa2\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm12]{k2}, zmm17");
    TEST64("\x62\x82\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm12]{k2}, zmm17");
    TEST3264("\x62\xe2\xfd\x42\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [rdi+8*ymm20]{k2}, zmm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\xfd\x42\xa2\x0c\xe7", "UD", "vscatterdpd qword ptr [r15+8*ymm20]{k2}, zmm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm28]{k2}, zmm17");
    TEST64("\x62\x82\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm28]{k2}, zmm17");
    TEST64("\x62\x62\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm4]{k2}, zmm25");
    TEST64("\x62\x42\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm4]{k2}, zmm25");
    TEST64("\x62\x22\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm12]{k2}, zmm25");
    TEST64("\x62\x02\xfd\x4a\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm12]{k2}, zmm25");
    TEST64("\x62\x62\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm20]{k2}, zmm25");
    TEST64("\x62\x42\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm20]{k2}, zmm25");
    TEST64("\x62\x22\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [rdi+8*ymm28]{k2}, zmm25");
    TEST64("\x62\x02\xfd\x42\xa2\x0c\xe7", "vscatterdpd qword ptr [r15+8*ymm28]{k2}, zmm25");
    TEST("\x62\xf2\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [@di+8*xmm4]{k2}, xmm1");
    TEST3264("\x62\xd2\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterqpd qword ptr [r15+8*xmm4]{k2}, xmm1");
    TEST64("\x62\xb2\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm12]{k2}, xmm1");
    TEST64("\x62\x92\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm12]{k2}, xmm1");
    TEST3264("\x62\xf2\xfd\x02\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [rdi+8*xmm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\xfd\x02\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [r15+8*xmm20]{k2}, xmm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm28]{k2}, xmm1");
    TEST64("\x62\x92\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm28]{k2}, xmm1");
    TEST64("\x62\x72\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm4]{k2}, xmm9");
    TEST64("\x62\x52\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm4]{k2}, xmm9");
    TEST64("\x62\x32\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm12]{k2}, xmm9");
    TEST64("\x62\x12\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm12]{k2}, xmm9");
    TEST64("\x62\x72\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm20]{k2}, xmm9");
    TEST64("\x62\x52\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm20]{k2}, xmm9");
    TEST64("\x62\x32\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm28]{k2}, xmm9");
    TEST64("\x62\x12\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm28]{k2}, xmm9");
    TEST3264("\x62\xe2\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterqpd qword ptr [rdi+8*xmm4]{k2}, xmm17");
    TEST3264("\x62\xc2\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*xmm4]{k2}, xmm1", "vscatterqpd qword ptr [r15+8*xmm4]{k2}, xmm17");
    TEST64("\x62\xa2\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm12]{k2}, xmm17");
    TEST64("\x62\x82\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm12]{k2}, xmm17");
    TEST3264("\x62\xe2\xfd\x02\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [rdi+8*xmm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\xfd\x02\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [r15+8*xmm20]{k2}, xmm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm28]{k2}, xmm17");
    TEST64("\x62\x82\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm28]{k2}, xmm17");
    TEST64("\x62\x62\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm4]{k2}, xmm25");
    TEST64("\x62\x42\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm4]{k2}, xmm25");
    TEST64("\x62\x22\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm12]{k2}, xmm25");
    TEST64("\x62\x02\xfd\x0a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm12]{k2}, xmm25");
    TEST64("\x62\x62\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm20]{k2}, xmm25");
    TEST64("\x62\x42\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm20]{k2}, xmm25");
    TEST64("\x62\x22\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*xmm28]{k2}, xmm25");
    TEST64("\x62\x02\xfd\x02\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*xmm28]{k2}, xmm25");
    TEST("\x62\xf2\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [@di+8*ymm4]{k2}, ymm1");
    TEST3264("\x62\xd2\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*ymm4]{k2}, ymm1", "vscatterqpd qword ptr [r15+8*ymm4]{k2}, ymm1");
    TEST64("\x62\xb2\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm12]{k2}, ymm1");
    TEST64("\x62\x92\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm12]{k2}, ymm1");
    TEST3264("\x62\xf2\xfd\x22\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [rdi+8*ymm20]{k2}, ymm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\xfd\x22\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [r15+8*ymm20]{k2}, ymm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm28]{k2}, ymm1");
    TEST64("\x62\x92\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm28]{k2}, ymm1");
    TEST64("\x62\x72\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm4]{k2}, ymm9");
    TEST64("\x62\x52\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm4]{k2}, ymm9");
    TEST64("\x62\x32\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm12]{k2}, ymm9");
    TEST64("\x62\x12\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm12]{k2}, ymm9");
    TEST64("\x62\x72\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm20]{k2}, ymm9");
    TEST64("\x62\x52\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm20]{k2}, ymm9");
    TEST64("\x62\x32\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm28]{k2}, ymm9");
    TEST64("\x62\x12\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm28]{k2}, ymm9");
    TEST3264("\x62\xe2\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*ymm4]{k2}, ymm1", "vscatterqpd qword ptr [rdi+8*ymm4]{k2}, ymm17");
    TEST3264("\x62\xc2\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*ymm4]{k2}, ymm1", "vscatterqpd qword ptr [r15+8*ymm4]{k2}, ymm17");
    TEST64("\x62\xa2\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm12]{k2}, ymm17");
    TEST64("\x62\x82\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm12]{k2}, ymm17");
    TEST3264("\x62\xe2\xfd\x22\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [rdi+8*ymm20]{k2}, ymm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\xfd\x22\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [r15+8*ymm20]{k2}, ymm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm28]{k2}, ymm17");
    TEST64("\x62\x82\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm28]{k2}, ymm17");
    TEST64("\x62\x62\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm4]{k2}, ymm25");
    TEST64("\x62\x42\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm4]{k2}, ymm25");
    TEST64("\x62\x22\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm12]{k2}, ymm25");
    TEST64("\x62\x02\xfd\x2a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm12]{k2}, ymm25");
    TEST64("\x62\x62\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm20]{k2}, ymm25");
    TEST64("\x62\x42\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm20]{k2}, ymm25");
    TEST64("\x62\x22\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*ymm28]{k2}, ymm25");
    TEST64("\x62\x02\xfd\x22\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*ymm28]{k2}, ymm25");
    TEST("\x62\xf2\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [@di+8*zmm4]{k2}, zmm1");
    TEST3264("\x62\xd2\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*zmm4]{k2}, zmm1", "vscatterqpd qword ptr [r15+8*zmm4]{k2}, zmm1");
    TEST64("\x62\xb2\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm12]{k2}, zmm1");
    TEST64("\x62\x92\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm12]{k2}, zmm1");
    TEST3264("\x62\xf2\xfd\x42\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [rdi+8*zmm20]{k2}, zmm1"); // EVEX.V' == 0
    TEST3264("\x62\xd2\xfd\x42\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [r15+8*zmm20]{k2}, zmm1"); // EVEX.V' == 0
    TEST64("\x62\xb2\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm28]{k2}, zmm1");
    TEST64("\x62\x92\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm28]{k2}, zmm1");
    TEST64("\x62\x72\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm4]{k2}, zmm9");
    TEST64("\x62\x52\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm4]{k2}, zmm9");
    TEST64("\x62\x32\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm12]{k2}, zmm9");
    TEST64("\x62\x12\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm12]{k2}, zmm9");
    TEST64("\x62\x72\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm20]{k2}, zmm9");
    TEST64("\x62\x52\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm20]{k2}, zmm9");
    TEST64("\x62\x32\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm28]{k2}, zmm9");
    TEST64("\x62\x12\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm28]{k2}, zmm9");
    TEST3264("\x62\xe2\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*zmm4]{k2}, zmm1", "vscatterqpd qword ptr [rdi+8*zmm4]{k2}, zmm17");
    TEST3264("\x62\xc2\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [edi+8*zmm4]{k2}, zmm1", "vscatterqpd qword ptr [r15+8*zmm4]{k2}, zmm17");
    TEST64("\x62\xa2\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm12]{k2}, zmm17");
    TEST64("\x62\x82\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm12]{k2}, zmm17");
    TEST3264("\x62\xe2\xfd\x42\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [rdi+8*zmm20]{k2}, zmm17"); // EVEX.V' == 0
    TEST3264("\x62\xc2\xfd\x42\xa3\x0c\xe7", "UD", "vscatterqpd qword ptr [r15+8*zmm20]{k2}, zmm17"); // EVEX.V' == 0
    TEST64("\x62\xa2\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm28]{k2}, zmm17");
    TEST64("\x62\x82\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm28]{k2}, zmm17");
    TEST64("\x62\x62\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm4]{k2}, zmm25");
    TEST64("\x62\x42\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm4]{k2}, zmm25");
    TEST64("\x62\x22\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm12]{k2}, zmm25");
    TEST64("\x62\x02\xfd\x4a\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm12]{k2}, zmm25");
    TEST64("\x62\x62\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm20]{k2}, zmm25");
    TEST64("\x62\x42\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm20]{k2}, zmm25");
    TEST64("\x62\x22\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [rdi+8*zmm28]{k2}, zmm25");
    TEST64("\x62\x02\xfd\x42\xa3\x0c\xe7", "vscatterqpd qword ptr [r15+8*zmm28]{k2}, zmm25");

    // All EVEX-VSIB instructions. VSCATTER* cases additionally test scaled offset.
    TEST("\x62\xf2\x7d\x09\xa2\x44\xe7\x01", "vscatterdps dword ptr [@di+8*xmm4+0x4]{k1}, xmm0");
    TEST("\x62\xf2\x7d\x29\xa2\x44\xe7\x01", "vscatterdps dword ptr [@di+8*ymm4+0x4]{k1}, ymm0");
    TEST("\x62\xf2\x7d\x49\xa2\x44\xe7\x01", "vscatterdps dword ptr [@di+8*zmm4+0x4]{k1}, zmm0");
    TEST("\x62\xf2\x7d\x09\xa3\x44\xe7\x01", "vscatterqps dword ptr [@di+8*xmm4+0x4]{k1}, xmm0");
    TEST("\x62\xf2\x7d\x29\xa3\x44\xe7\x01", "vscatterqps dword ptr [@di+8*ymm4+0x4]{k1}, xmm0");
    TEST("\x62\xf2\x7d\x49\xa3\x44\xe7\x01", "vscatterqps dword ptr [@di+8*zmm4+0x4]{k1}, ymm0");
    TEST("\x62\xf2\xfd\x09\xa2\x44\xe7\x01", "vscatterdpd qword ptr [@di+8*xmm4+0x8]{k1}, xmm0");
    TEST("\x62\xf2\xfd\x29\xa2\x44\xe7\x01", "vscatterdpd qword ptr [@di+8*xmm4+0x8]{k1}, ymm0");
    TEST("\x62\xf2\xfd\x49\xa2\x44\xe7\x01", "vscatterdpd qword ptr [@di+8*ymm4+0x8]{k1}, zmm0");
    TEST("\x62\xf2\xfd\x09\xa3\x44\xe7\x01", "vscatterqpd qword ptr [@di+8*xmm4+0x8]{k1}, xmm0");
    TEST("\x62\xf2\xfd\x29\xa3\x44\xe7\x01", "vscatterqpd qword ptr [@di+8*ymm4+0x8]{k1}, ymm0");
    TEST("\x62\xf2\xfd\x49\xa3\x44\xe7\x01", "vscatterqpd qword ptr [@di+8*zmm4+0x8]{k1}, zmm0");
    TEST("\x62\xf2\x7d\x09\xa0\x44\xe7\x01", "vpscatterdd dword ptr [@di+8*xmm4+0x4]{k1}, xmm0");
    TEST("\x62\xf2\x7d\x29\xa0\x44\xe7\x01", "vpscatterdd dword ptr [@di+8*ymm4+0x4]{k1}, ymm0");
    TEST("\x62\xf2\x7d\x49\xa0\x44\xe7\x01", "vpscatterdd dword ptr [@di+8*zmm4+0x4]{k1}, zmm0");
    TEST("\x62\xf2\x7d\x09\xa1\x44\xe7\x01", "vpscatterqd dword ptr [@di+8*xmm4+0x4]{k1}, xmm0");
    TEST("\x62\xf2\x7d\x29\xa1\x44\xe7\x01", "vpscatterqd dword ptr [@di+8*ymm4+0x4]{k1}, xmm0");
    TEST("\x62\xf2\x7d\x49\xa1\x44\xe7\x01", "vpscatterqd dword ptr [@di+8*zmm4+0x4]{k1}, ymm0");
    TEST("\x62\xf2\xfd\x09\xa0\x44\xe7\x01", "vpscatterdq qword ptr [@di+8*xmm4+0x8]{k1}, xmm0");
    TEST("\x62\xf2\xfd\x29\xa0\x44\xe7\x01", "vpscatterdq qword ptr [@di+8*xmm4+0x8]{k1}, ymm0");
    TEST("\x62\xf2\xfd\x49\xa0\x44\xe7\x01", "vpscatterdq qword ptr [@di+8*ymm4+0x8]{k1}, zmm0");
    TEST("\x62\xf2\xfd\x09\xa1\x44\xe7\x01", "vpscatterqq qword ptr [@di+8*xmm4+0x8]{k1}, xmm0");
    TEST("\x62\xf2\xfd\x29\xa1\x44\xe7\x01", "vpscatterqq qword ptr [@di+8*ymm4+0x8]{k1}, ymm0");
    TEST("\x62\xf2\xfd\x49\xa1\x44\xe7\x01", "vpscatterqq qword ptr [@di+8*zmm4+0x8]{k1}, zmm0");
    TEST("\x62\xf2\x7d\x09\x90\x44\xe7\x01", "vpgatherdd xmm0{k1}, dword ptr [@di+8*xmm4+0x4]");
    TEST("\x62\xf2\x7d\x29\x90\x44\xe7\x01", "vpgatherdd ymm0{k1}, dword ptr [@di+8*ymm4+0x4]");
    TEST("\x62\xf2\x7d\x49\x90\x44\xe7\x01", "vpgatherdd zmm0{k1}, dword ptr [@di+8*zmm4+0x4]");
    TEST("\x62\xf2\x7d\x09\x91\x44\xe7\x01", "vpgatherqd xmm0{k1}, dword ptr [@di+8*xmm4+0x4]");
    TEST("\x62\xf2\x7d\x29\x91\x44\xe7\x01", "vpgatherqd xmm0{k1}, dword ptr [@di+8*ymm4+0x4]");
    TEST("\x62\xf2\x7d\x49\x91\x44\xe7\x01", "vpgatherqd ymm0{k1}, dword ptr [@di+8*zmm4+0x4]");
    TEST("\x62\xf2\xfd\x09\x90\x44\xe7\x01", "vpgatherdq xmm0{k1}, qword ptr [@di+8*xmm4+0x8]");
    TEST("\x62\xf2\xfd\x29\x90\x44\xe7\x01", "vpgatherdq ymm0{k1}, qword ptr [@di+8*xmm4+0x8]");
    TEST("\x62\xf2\xfd\x49\x90\x44\xe7\x01", "vpgatherdq zmm0{k1}, qword ptr [@di+8*ymm4+0x8]");
    TEST("\x62\xf2\xfd\x09\x91\x44\xe7\x01", "vpgatherqq xmm0{k1}, qword ptr [@di+8*xmm4+0x8]");
    TEST("\x62\xf2\xfd\x29\x91\x44\xe7\x01", "vpgatherqq ymm0{k1}, qword ptr [@di+8*ymm4+0x8]");
    TEST("\x62\xf2\xfd\x49\x91\x44\xe7\x01", "vpgatherqq zmm0{k1}, qword ptr [@di+8*zmm4+0x8]");
    TEST("\x62\xf2\x7d\x09\x92\x44\xe7\x01", "vgatherdps xmm0{k1}, dword ptr [@di+8*xmm4+0x4]");
    TEST("\x62\xf2\x7d\x29\x92\x44\xe7\x01", "vgatherdps ymm0{k1}, dword ptr [@di+8*ymm4+0x4]");
    TEST("\x62\xf2\x7d\x49\x92\x44\xe7\x01", "vgatherdps zmm0{k1}, dword ptr [@di+8*zmm4+0x4]");
    TEST("\x62\xf2\x7d\x09\x93\x44\xe7\x01", "vgatherqps xmm0{k1}, dword ptr [@di+8*xmm4+0x4]");
    TEST("\x62\xf2\x7d\x29\x93\x44\xe7\x01", "vgatherqps xmm0{k1}, dword ptr [@di+8*ymm4+0x4]");
    TEST("\x62\xf2\x7d\x49\x93\x44\xe7\x01", "vgatherqps ymm0{k1}, dword ptr [@di+8*zmm4+0x4]");
    TEST("\x62\xf2\xfd\x09\x92\x44\xe7\x01", "vgatherdpd xmm0{k1}, qword ptr [@di+8*xmm4+0x8]");
    TEST("\x62\xf2\xfd\x29\x92\x44\xe7\x01", "vgatherdpd ymm0{k1}, qword ptr [@di+8*xmm4+0x8]");
    TEST("\x62\xf2\xfd\x49\x92\x44\xe7\x01", "vgatherdpd zmm0{k1}, qword ptr [@di+8*ymm4+0x8]");
    TEST("\x62\xf2\xfd\x09\x93\x44\xe7\x01", "vgatherqpd xmm0{k1}, qword ptr [@di+8*xmm4+0x8]");
    TEST("\x62\xf2\xfd\x29\x93\x44\xe7\x01", "vgatherqpd ymm0{k1}, qword ptr [@di+8*ymm4+0x8]");
    TEST("\x62\xf2\xfd\x49\x93\x44\xe7\x01", "vgatherqpd zmm0{k1}, qword ptr [@di+8*zmm4+0x8]");

    // AVX512-FP16
    TEST("\x62\xf5\x74\x08\x5c\xc2", "vsubph xmm0, xmm1, xmm2");
    TEST("\x62\xf5\x74\x28\x5c\xc2", "vsubph ymm0, ymm1, ymm2");
    TEST("\x62\xf5\x74\x48\x5c\xc2", "vsubph zmm0, zmm1, zmm2");
    TEST("\x62\xf5\x74\x08\x5c\x42\x01", "vsubph xmm0, xmm1, xmmword ptr [@dx+0x10]");
    TEST("\x62\xf5\x74\x28\x5c\x42\x01", "vsubph ymm0, ymm1, ymmword ptr [@dx+0x20]");
    TEST("\x62\xf5\x74\x48\x5c\x42\x01", "vsubph zmm0, zmm1, zmmword ptr [@dx+0x40]");
    TEST("\x62\xf5\x74\x18\x5c\x42\x01", "vsubph xmm0, xmm1, word ptr [@dx+0x2]{1to8}");
    TEST("\x62\xf5\x74\x38\x5c\x42\x01", "vsubph ymm0, ymm1, word ptr [@dx+0x2]{1to16}");
    TEST("\x62\xf5\x74\x58\x5c\x42\x01", "vsubph zmm0, zmm1, word ptr [@dx+0x2]{1to32}");
    TEST64("\x62\x93\x36\x34\xc2\xeb\x89", "vcmpsh k5{k4}, xmm25, xmm27, 0x89, {sae}");
    TEST("\x62\xf5\x66\x4c\x11\xd5", "vmovsh xmm5{k4}, xmm3, xmm2");
    TEST64("\x62\x25\x66\x4c\x11\xd5", "vmovsh xmm21{k4}, xmm3, xmm26");

    // GFNI
    TEST("\x66\x0f\x38\xcf\xc1", "gf2p8mulb xmm0, xmm1");
    TEST("\x66\x0f\x3a\xce\xc1\x01", "gf2p8affineqb xmm0, xmm1, 0x1");
    TEST("\x66\x0f\x3a\xcf\xc1\x01", "gf2p8affineinvqb xmm0, xmm1, 0x1");
    TEST("\xc4\xe2\x69\xcf\xc1", "vgf2p8mulb xmm0, xmm2, xmm1");
    TEST("\xc4\xe2\x6d\xcf\xc1", "vgf2p8mulb ymm0, ymm2, ymm1");
    TEST("\xc4\xe3\xe9\xce\xc1\x01", "vgf2p8affineqb xmm0, xmm2, xmm1, 0x1");
    TEST("\xc4\xe3\xed\xce\xc1\x01", "vgf2p8affineqb ymm0, ymm2, ymm1, 0x1");
    TEST("\xc4\xe3\xe9\xcf\xc1\x01", "vgf2p8affineinvqb xmm0, xmm2, xmm1, 0x1");
    TEST("\xc4\xe3\xed\xcf\xc1\x01", "vgf2p8affineinvqb ymm0, ymm2, ymm1, 0x1");
    TEST("\x62\xf3\xdd\x18\xcf\x49\x01\x07", "vgf2p8affineinvqb xmm1, xmm4, qword ptr [@cx+0x8]{1to2}, 0x7");
    TEST64("\x62\xf3\xdd\x10\xcf\x49\x01\x07", "vgf2p8affineinvqb xmm1, xmm20, qword ptr [rcx+0x8]{1to2}, 0x7");

    // AMD RDPRU
    TEST64("\x0f\x01\xfd", "rdpru");
    TEST64("\x66\x0f\x01\xfd", "rdpru"); // 66 prefix ignored

    // AMD SNP
    TEST64("\xf3\x0f\x01\xfd", "rmpquery");
    TEST64("\xf2\x0f\x01\xfd", "rmpread");
    TEST64("\xf3\x0f\x01\xfe", "rmpadjust");
    TEST64("\xf2\x0f\x01\xfe", "rmpupdate");
    TEST64("\xf3\x0f\x01\xff", "psmash");
    TEST64("\xf2\x0f\x01\xff", "pvalidate");

    // PBNDKB
    TEST3264("\x0f\x01\xc7", "UD", "pbndkb");

    // SM4
    TEST("\xc4\xe2\x6a\xda\x01", "vsm4key4 xmm0, xmm2, xmmword ptr [@cx]");
    TEST("\xc4\xe2\x6e\xda\x01", "vsm4key4 ymm0, ymm2, ymmword ptr [@cx]");
    TEST("\xc4\xe2\x6a\xda\xc1", "vsm4key4 xmm0, xmm2, xmm1");
    TEST("\xc4\xe2\x6e\xda\xc1", "vsm4key4 ymm0, ymm2, ymm1");
    TEST("\x62\xf2\x6e\x08\xda\x01", "vsm4key4 xmm0, xmm2, xmmword ptr [@cx]");
    TEST("\x62\xf2\x6e\x28\xda\x01", "vsm4key4 ymm0, ymm2, ymmword ptr [@cx]");
    TEST("\x62\xf2\x6e\x48\xda\x01", "vsm4key4 zmm0, zmm2, zmmword ptr [@cx]");
    TEST("\x62\xf2\x6e\x08\xda\xc1", "vsm4key4 xmm0, xmm2, xmm1");
    TEST("\x62\xf2\x6e\x28\xda\xc1", "vsm4key4 ymm0, ymm2, ymm1");
    TEST("\x62\xf2\x6e\x48\xda\xc1", "vsm4key4 zmm0, zmm2, zmm1");
    TEST("\xc4\xe2\x6b\xda\x01", "vsm4rnds4 xmm0, xmm2, xmmword ptr [@cx]");
    TEST("\xc4\xe2\x6f\xda\x01", "vsm4rnds4 ymm0, ymm2, ymmword ptr [@cx]");
    TEST("\xc4\xe2\x6b\xda\xc1", "vsm4rnds4 xmm0, xmm2, xmm1");
    TEST("\xc4\xe2\x6f\xda\xc1", "vsm4rnds4 ymm0, ymm2, ymm1");
    TEST("\x62\xf2\x6f\x08\xda\x01", "vsm4rnds4 xmm0, xmm2, xmmword ptr [@cx]");
    TEST("\x62\xf2\x6f\x28\xda\x01", "vsm4rnds4 ymm0, ymm2, ymmword ptr [@cx]");
    TEST("\x62\xf2\x6f\x48\xda\x01", "vsm4rnds4 zmm0, zmm2, zmmword ptr [@cx]");
    TEST("\x62\xf2\x6f\x08\xda\xc1", "vsm4rnds4 xmm0, xmm2, xmm1");
    TEST("\x62\xf2\x6f\x28\xda\xc1", "vsm4rnds4 ymm0, ymm2, ymm1");
    TEST("\x62\xf2\x6f\x48\xda\xc1", "vsm4rnds4 zmm0, zmm2, zmm1");


    puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

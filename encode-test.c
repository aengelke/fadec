
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

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

#define TEST2(str, exp, exp_len, mnem, flags, op0, op1, op2, op3, ...) test(buf, str, FE_ ## mnem|flags, op0, op1, op2, op3, exp, exp_len)
#define TEST1(str, exp, ...) TEST2(str, exp, sizeof(exp)-1, __VA_ARGS__, 0, 0, 0, 0, 0)
#define TEST(exp, ...) failed |= TEST1(#__VA_ARGS__, exp, __VA_ARGS__)

int
main(int argc, char** argv)
{
    (void) argc; (void) argv;

    int failed = 0;
    uint8_t buf[16];

    // VSIB encoding doesn't differ for this API
#define FE_MEMV FE_MEM
#define FE_PTR(off) ((intptr_t) buf + (off))
#define FLAGMASK(flags, mask) (flags | FE_MASK(mask & 7))
#include "encode-test.inc"

    puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

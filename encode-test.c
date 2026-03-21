
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <fadec-enc.h>

#if defined(__has_attribute)
#if __has_attribute(nonstring)
#define NONSTRING __attribute__((nonstring))
#endif
#endif
#if !defined(NONSTRING)
#define NONSTRING
#endif

static
void
print_hex(const uint8_t* buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

int
main(int argc, char** argv)
{
    (void) argc; (void) argv;

    static uint8_t buf[16];
    static const struct TestCase {
        const char *name;
        uint64_t mnem;
        uint8_t exp_len;
        uint8_t exp[15] NONSTRING;
        FeOp op0, op1, op2, op3;
    } cases[] = {
    // VSIB encoding doesn't differ for this API
#define FE_MEMV FE_MEM
#define FE_PTR(off) ((intptr_t) buf + (off))
#define FLAGMASK(flags, mask) (flags | FE_MASK(mask & 7))
#define TEST1(str, exp, exp_len, mnem, flags, op0, op1, op2, op3, ...) \
        {str, FE_##mnem|flags, exp_len, exp, op0, op1, op2, op3},
#define TEST(exp, ...) TEST1(#__VA_ARGS__, exp, sizeof(exp)-1, __VA_ARGS__, 0, 0, 0, 0,)
#include "encode-test.inc"
    };

    int failed = 0;

    const struct TestCase* end = cases + sizeof(cases) / sizeof(cases[0]);
    for (const struct TestCase* tc = cases; tc != end; tc++) {
        memset(buf, 0, 16);

        uint8_t* inst = buf;
        int res = fe_enc64(&inst, tc->mnem, tc->op0, tc->op1, tc->op2, tc->op3);
        if ((res != 0) != (tc->exp_len == 0) ||
            inst - buf != (ptrdiff_t) tc->exp_len ||
            memcmp(buf, tc->exp, tc->exp_len)) {
            failed += 1;
            printf("Failed case %s:\n", tc->name);
            printf("  Exp (%2u): ", tc->exp_len);
            print_hex(tc->exp, tc->exp_len);
            printf("\n  Got (%2zd): ", inst - buf);
            print_hex(buf, inst - buf);
            printf("\n");
        }
    }

    puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

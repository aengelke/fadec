
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <fadec-enc2.h>


static
void print_hex(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

static int
check(const uint8_t* buf, const void* exp, size_t exp_len, unsigned res, const char* name) {
    if (res == exp_len && !memcmp(buf, exp, exp_len))
        return 0;
    printf("Failed case (new) %s:\n", name);
    printf("  Exp (%2zu): ", exp_len);
    print_hex((const uint8_t*)exp, exp_len);
    printf("\n  Got (%2u): ", res);
    print_hex(buf, res);
    printf("\n");
    return -1;
}

#define TEST1(str, exp, name, ...) do { \
            memset(buf, 0, sizeof buf); \
            unsigned res = fe64_ ## name(buf, __VA_ARGS__); \
            failed |= check(buf, exp, sizeof(exp) - 1, res, str); \
        } while (0)
#define TEST(exp, ...) TEST1(#__VA_ARGS__, exp, __VA_ARGS__)

int
main(void) {
    int failed = 0;
    uint8_t buf[16];

    // This API is type safe and prohibits compilation of reg-type mismatches
#define ENC_TEST_TYPESAFE
    // Silence -Warray-bounds with double cast
#define FE_PTR(off) (const void*) ((uintptr_t) buf + (off))
#define FLAGMASK(flags, mask) flags, mask
#include "encode-test.inc"

    TEST("\x90", NOP, 0);
    TEST("\x90", NOP, 1);
    TEST("\x66\x90", NOP, 2);
    TEST("\x0f\x1f\x00", NOP, 3);
    TEST("\x0f\x1f\x40\x00", NOP, 4);
    TEST("\x0f\x1f\x44\x00\x00", NOP, 5);
    TEST("\x66\x0f\x1f\x44\x00\x00", NOP, 6);
    TEST("\x0f\x1f\x80\x00\x00\x00\x00", NOP, 7);
    TEST("\x0f\x1f\x84\x00\x00\x00\x00\x00", NOP, 8);
    TEST("\x66\x0f\x1f\x84\x00\x00\x00\x00\x00", NOP, 9);
    TEST("\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x90", NOP, 10);
    TEST("\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x66\x90", NOP, 11);
    TEST("\x66\x0f\x1f\x84\x00\x00\x00\x00\x00\x0f\x1f\x00", NOP, 12);

    puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

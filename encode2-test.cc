
#include <array>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <fadec-enc2.h>


using Buffer = std::array<uint8_t, 16>;

static
void print_hex(const uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        std::printf("%02x", buf[i]);
}

static int
check(const Buffer& buf, const char* exp, size_t exp_len, unsigned res, const char* name) {
    if (res == exp_len && !std::memcmp(buf.data(), exp, exp_len))
        return 0;
    std::printf("Failed case (new) %s:\n", name);
    std::printf("  Exp (%2zu): ", exp_len);
    print_hex(reinterpret_cast<const uint8_t*>(exp), exp_len);
    std::printf("\n  Got (%2u): ", res);
    print_hex(buf.data(), res);
    std::printf("\n");
    return -1;
}

#define TEST1(str, exp, name, ...) do { \
            buf.fill(0); \
            unsigned res = fe64_ ## name(buf.data(), __VA_ARGS__); \
            failed |= check(buf, exp, sizeof(exp) - 1, res, str); \
        } while (0)
#define TEST(exp, ...) TEST1(#__VA_ARGS__, exp, __VA_ARGS__)

#define TEST_CPP1(str, exp, expr) do { \
            buf.fill(0); \
            unsigned res = (expr); \
            failed |= check(buf, exp, sizeof(exp) - 1, res, str); \
        } while (0)
#define TEST_CPP(exp, ...) TEST_CPP1(#__VA_ARGS__, exp, __VA_ARGS__)

int main() {
    int failed = 0;
    Buffer buf{};

    // This API is type safe and prohibits compilation of reg-type mismatches
#define ENC_TEST_TYPESAFE
    // Silence -Warray-bounds with double cast
#define FE_PTR(off) (const void*) ((uintptr_t) buf.data() + (off))
#define FLAGMASK(flags, mask) flags, mask
#include "encode-test.inc"

    // Test implicit conversion of parameters also on the actual functions
    TEST_CPP("\x0f\x90\xc0", fe64_SETO8r(buf.data(), 0, FE_AX));
    TEST_CPP("\x0f\x90\xc0", (fe64_SETO8r)(buf.data(), 0, FE_AX));
    TEST_CPP("\x0f\x90\xc4", fe64_SETO8r(buf.data(), 0, FE_AH));
    TEST_CPP("\x0f\x90\xc4", (fe64_SETO8r)(buf.data(), 0, FE_AH));

    std::puts(failed ? "Some tests FAILED" : "All tests PASSED");
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

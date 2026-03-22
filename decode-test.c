
#include "fadec.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  static const struct TestCase {
    uint8_t buf[22];
    uint8_t buf_len;
    uint8_t mode;
    const char* exp;
  } cases[] = {
#define TEST1(mode, buf, exp) {buf, sizeof(buf) - 1, mode, exp},
#define TEST32(buf, exp) TEST1(32, buf, exp)
#define TEST64(buf, exp) TEST1(64, buf, exp)
#define TEST3264(buf, exp32, exp64) TEST32(buf, exp32) TEST64(buf, exp64)
#define TEST(buf, exp) TEST32(buf, exp) TEST64(buf, exp)
#include "decode-test.inc"
  };

  unsigned failed = 0;
  const struct TestCase* end = cases + sizeof(cases) / sizeof(cases[0]);
  for (const struct TestCase* tc = cases; tc != end; tc++) {
    FdInstr instr;
    char fmt[128] = {0};
    int retval = fd_decode(tc->buf, tc->buf_len, tc->mode, 0, &instr);

    if (retval == FD_ERR_INTERNAL)
      continue; // not compiled with this arch-mode (32/64 bit)
    else if (retval == FD_ERR_PARTIAL)
      strcpy(fmt, "PARTIAL");
    else if (retval == FD_ERR_UD)
      strcpy(fmt, "UD");
    else
      fd_format(&instr, fmt, sizeof(fmt));

    if ((retval < 0 || (unsigned)retval == tc->buf_len)) {
      if (!strcmp(fmt, tc->exp))
        continue;
      // Consider 32/64 bit differences, e.g. for addressing mode.
      for (const char* it = tc->exp; (it = (const char*)strchr(it, '@')); it++)
        if (fmt[it - tc->exp] == (tc->mode != 64 ? 'e' : 'r'))
          fmt[it - tc->exp] = '@';
      if (!strcmp(fmt, tc->exp))
        continue;
    }

    failed += 1;
    printf("Failed case (%u-bit): ", tc->mode);
    for (size_t i = 0; i < tc->buf_len; i++)
      printf("%02x", tc->buf[i]);
    printf("\n  Exp (%2u): %s", tc->buf_len, tc->exp);
    printf("\n  Got (%2d): %s\n", retval, fmt);
  }

  puts(failed ? "Some tests FAILED" : "All tests PASSED");
  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

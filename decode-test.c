
#include "fadec.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FMTREG(exp, ...) test_fmtreg(#__VA_ARGS__, exp, __VA_ARGS__)
static unsigned test_fmtreg(const char* str, const char* exp, FdRegType ty,
                            FdReg idx, unsigned sizelog) {
  char fmt[16];
  unsigned len = fd_format_reg(ty, idx, sizelog, fmt);
  if (!strcmp(fmt, exp) && len == strlen(fmt))
    return 0;
  printf("Failed fd_format_reg case: \"%s\" != \"%s\" (%s)\n", exp, fmt, str);
  return 1;
}

int main(void) {
  unsigned failed = 0;

  failed += TEST_FMTREG("al", FD_RT_GPL, FD_REG_AX, 0);
  failed += TEST_FMTREG("ah", FD_RT_GPH, FD_REG_AH, 0);
  failed += TEST_FMTREG("ax", FD_RT_GPL, FD_REG_AX, 1);
  failed += TEST_FMTREG("eax", FD_RT_GPL, FD_REG_AX, 2);
  failed += TEST_FMTREG("rax", FD_RT_GPL, FD_REG_AX, 3);
  failed += TEST_FMTREG("xmm0", FD_RT_VEC, FD_REG_R0, 3);
  failed += TEST_FMTREG("xmm0", FD_RT_VEC, FD_REG_R0, 4);
  failed += TEST_FMTREG("ymm0", FD_RT_VEC, FD_REG_R0, 5);
  failed += TEST_FMTREG("zmm0", FD_RT_VEC, FD_REG_R0, 6);

  static const struct TestCase {
    uint8_t buf[21];
    uint8_t buf_len;
    uint8_t mode;
    uint8_t addr;
    const char* exp;
  } cases[] = {
#define TEST1(mode, buf, exp) {buf, sizeof(buf) - 1, mode, 0, exp},
#define TEST32(buf, exp) TEST1(32, buf, exp)
#define TEST64(buf, exp) TEST1(64, buf, exp)
#define TEST3264(buf, exp32, exp64) TEST32(buf, exp32) TEST64(buf, exp64)
#define TEST(buf, exp) TEST32(buf, exp) TEST64(buf, exp)
#include "decode-test.inc"
      // Test legacy absolute address mode.
      {"\x70\x00", 2, 64, /*addr=*/128, "jo 0x82"},
      // Test invalid mode.
      {"", 0, 16, 0, ""},
  };

  const struct TestCase* end = cases + sizeof(cases) / sizeof(cases[0]);
  for (const struct TestCase* tc = cases; tc != end; tc++) {
    FdInstr instr;
    char fmt[128] = {0};
    int retval = fd_decode(tc->buf, tc->buf_len, tc->mode, tc->addr, &instr);

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

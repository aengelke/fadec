
#include "fadec.h"
#include <err.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

struct DecodeStat {
  size_t insts;
  size_t bad;
};

static void opt_barrier(const void* ptr) {
  __asm__ volatile("" : : "r"(&ptr) : "memory");
}

static struct DecodeStat do_decode(unsigned rept, const uint8_t* start,
                                   const uint8_t* end) {
  FdInstr instr;
  struct DecodeStat res = {0};
  for (unsigned i = 0; i < rept; i++) {
    res = (struct DecodeStat){0};
    for (const uint8_t* addr = start; addr != end;) {
      int retval = fd_decode(addr, end - addr, 64, 0, &instr);
      retval < 0 ? (addr++, res.bad++) : (addr += retval, res.insts++);
      opt_barrier(&instr);
    }
  }
  return res;
}

static struct DecodeStat do_decode_fmt(unsigned rept, const uint8_t* start,
                                       const uint8_t* end) {
  FdInstr instr;
  struct DecodeStat res = {0};
  char format_buffer[128];
  for (unsigned i = 0; i < rept; i++) {
    res = (struct DecodeStat){0};
    for (const uint8_t* addr = start; addr != end;) {
      int retval = fd_decode(addr, end - addr, 64, 0, &instr);
      if (retval < 0) {
        addr++, res.bad++;
      } else {
        addr += retval, res.insts++;
        fd_format_abs(&instr, 0, format_buffer, sizeof(format_buffer));
        opt_barrier(&format_buffer);
      }
    }
  }
  return res;
}

int main(int argc, char** argv) {
  unsigned rept = 1;
  size_t start = 0;
  size_t len = 0;
  bool fmt = false;
  for (int opt; (opt = getopt(argc, argv, "s:l:r:f")) != -1;) {
    switch (opt) {
    case 's': start = strtoul(optarg, NULL, 0); break;
    case 'l': len = strtoul(optarg, NULL, 0); break;
    case 'r': rept = strtoul(optarg, NULL, 0); break;
    case 'f': fmt = true; break;
    default:
    usage:
      printf("usage: %s [-s off] [-l len] [-r rept] [-f] file\n", argv[0]);
      return 1;
    }
  }

  if (optind + 1 != argc)
    goto usage;

  FILE* file = fopen(argv[optind], "r");
  if (!file)
    err(1, "%s", argv[optind]);
  if (fseek(file, 0, SEEK_END) < 0)
    err(1, "%s", argv[optind]);
  size_t size = ftell(file);
  rewind(file);

  uint8_t* mem = malloc(size);
  if (!mem)
    err(1, "malloc");
  if (fread(mem, 1, size, file) != size)
    err(1, "%s", argv[optind]);
  fclose(file);

  struct timespec time_start;
  struct timespec time_end;

  opt_barrier(mem);
  clock_gettime(CLOCK_MONOTONIC, &time_start);
  struct DecodeStat (*bench_fn)(unsigned, const uint8_t*, const uint8_t*) =
      fmt ? do_decode_fmt : do_decode;
  struct DecodeStat stat = bench_fn(rept, mem + start, mem + start + len);
  clock_gettime(CLOCK_MONOTONIC, &time_end);
  opt_barrier(mem);

  uint64_t nsecs = 1000000000ull * (time_end.tv_sec - time_start.tv_sec) +
                   (time_end.tv_nsec - time_start.tv_nsec);
  uint64_t throughput = rept * 1000ull * len / nsecs;

  printf("%" PRIu64 "ns %" PRIu64 "MB/s (%zu valid, %zu bad)\n", nsecs,
         throughput, stat.insts, stat.bad);
  free(mem);
  return 0;
}

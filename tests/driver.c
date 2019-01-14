
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

#include <decode.h>


static
uint8_t
parse_nibble(const char nibble)
{
    if (nibble >= '0' && nibble <= '9')
        return nibble - '0';
    else if (nibble >= 'a' && nibble <= 'f')
        return nibble - 'a' + 10;
    else if (nibble >= 'A' && nibble <= 'F')
        return nibble - 'A' + 10;
    printf("Invalid hexadecimal number: %x\n", nibble);
    exit(1);
}

int
main(int argc, char** argv)
{
    if (argc != 3 && argc != 4)
    {
        printf("usage: %s [mode] [instruction bytes] ([repetitions])\n", argv[0]);
        return -1;
    }

    DecodeMode mode;
    size_t mode_input = strtoul(argv[1], NULL, 0);
    if (mode_input == 32)
    {
        mode = DECODE_32;
    }
    else if (mode_input == 64)
    {
        mode = DECODE_64;
    }
    else
    {
        printf("Unknown decode mode\n");
        return 1;
    }

    // Avoid allocation by transforming hex to binary in-place.
    uint8_t* code = (uint8_t*) argv[2];
    uint8_t* code_end = code;
    char* hex = argv[2];
    for (; *hex; hex += 2, code_end++)
        *code_end = (parse_nibble(hex[0]) << 4) | parse_nibble(hex[1]);

    size_t length = (size_t) (code_end - code);

    size_t repetitions = 1;
    if (argc >= 4)
        repetitions = strtoul(argv[3], NULL, 0);

    struct timespec time_start;
    struct timespec time_end;

    Instr instr;

    __asm__ volatile("" : : : "memory");
    clock_gettime(CLOCK_MONOTONIC, &time_start);
    for (size_t i = 0; i < repetitions; i++)
    {
        size_t current_off = 0;
        while (current_off != length)
        {
            size_t remaining = length - current_off;
            int retval = decode(code + current_off, remaining, mode, 0x1234000,
                                &instr);
            if (retval < 0)
                goto fail;
            current_off += retval;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &time_end);
    __asm__ volatile("" : : : "memory");

    char format_buffer[128];
    instr_format(&instr, format_buffer);
    printf("%s\n", format_buffer);

    if (repetitions > 1)
    {
        uint64_t nsecs = 1000000000ull * (time_end.tv_sec - time_start.tv_sec) +
                                        (time_end.tv_nsec - time_start.tv_nsec);

        printf("%" PRIu64 " ns\n", nsecs);
    }

    return 0;

fail:
    puts("Decoding failed.");
    return 1;
}

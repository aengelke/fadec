
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <decode.h>


static
uint8_t
parse_nibble(const char nibble)
{
    if (nibble >= '0' && nibble <= '9')
    {
        return nibble - '0';
    }
    else if (nibble >= 'a' && nibble <= 'f')
    {
        return nibble - 'a' + 10;
    }
    else if (nibble >= 'A' && nibble <= 'F')
    {
        return nibble - 'A' + 10;
    }
    else
    {
        printf("Invalid hexadecimal number: %x\n", nibble);
        exit(1);
        return 0;
    }
}

int
main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: %s [instruction bytes]\n", argv[0]);
        return -1;
    }

    void* code = mmap((void*) 0x1238000, 0x2000, PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

    uint8_t* current_code = code;
    char* hex = argv[1];
    for (; *hex && *(hex + 1); hex += 2, current_code++)
    {
        *current_code = (parse_nibble(hex[0]) << 4) | parse_nibble(hex[1]);
    }

    size_t length = (size_t) current_code - (size_t) code;

    Instr instr;
    int result = decode(code, length, &instr);
    if (result < 0)
    {
        puts("Decode failed.");
        return -1;
    }
    else if ((size_t) result != length)
    {
        printf("Decode used %u bytes, not %u.\n", (unsigned int) result, (unsigned int) length);
        return -1;
    }

    char buffer[128];
    instr_format(&instr, buffer);
    puts(buffer);

    return 0;
}

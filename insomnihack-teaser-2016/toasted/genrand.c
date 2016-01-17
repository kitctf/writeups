#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

typedef unsigned char byte;

byte next_byte(byte prev_val)
{
    int r = random();
    return prev_val + (byte)r;
}


int main(int argc, char** argv)
{
    if (argc < 2) {
        return -1;
    }

    unsigned int v = strtoull(argv[1], NULL, 16);
    srandom(v);

    for (int i = 0; i < 10000; i++) {
        printf("%i\n", next_byte(0));
    }

    return 0;
}



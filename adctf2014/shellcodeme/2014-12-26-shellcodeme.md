---
layout: post
title: "ADCTF2014 'shellcoedme' writeup"
categories: writeups adctf2014
tags: exploitation
author: niklasb
---

*shellcodeme* was a two-stage exploitation challenge at ADCTF2014.

## Stage 1

This is just standard ROP to make the buffer at `0x20000000` rwx and read the
shellcode into it.

## Stage 2

Using stage 1, we bind the program to a TCP socket, so we can precisely control
the segmentation of the stream:

    $ socat tcp4:<myserver>:6666,reuseaddr exec:shellcodeme2

On myserver:

    $ socat tcp4-listen:6666,reuseaddr tcp4-listen:7777,reuseaddr

Because we didn't find any gadgets to control rcx/rdx, we had to improvise: We
can do a custom read, because we only need to control rsi/rdi for that. So we
use the following approach:

1. Use one read to set `mmap@GOT = mprotect` and `read@GOT = pop;pop;ret`
2. Reenter main at `0x4005d6`. This will trigger `mprotect(0x20000000, 0x400,
   rwx)` and we gain back control at the call to
   `read`.
3. Use the `read` fixup routine at `0x400496` to read our shellcode into `0x20000000`
4. Jump to our shellcode

#!/bin/sh

qemu-system-arm -M versatilepb -m 64M -kernel zImage -initrd rootfs.img -append "root=/dev/ram rw console=ttyAMA0 rdinit=/sbin/init oops=panic panic=1 quiet" \
    -monitor /dev/null -nographic 2>/dev/null

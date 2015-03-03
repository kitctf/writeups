#!/bin/bash

cd rootfs
find . | cpio -o -H newc | gzip > ../rootfs.img

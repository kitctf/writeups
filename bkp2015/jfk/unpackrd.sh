#!/bin/bash

mkdir rootfs && cd rootfs
cat ../rootfs.img | gunzip | cpio --extract

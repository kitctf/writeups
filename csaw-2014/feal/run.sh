#!/bin/sh
make
python2 solve.py 2>secret.txt | ./crack
cat secret.txt

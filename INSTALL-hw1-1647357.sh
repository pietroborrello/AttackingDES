#!/bin/bash

sudo apt-get install libgcrypt20 libgcrypt20-dev
gcc -o hw1 hw1-1647357.c `libgcrypt-config --cflags --libs` -O1 -lpthread -lgpg-error

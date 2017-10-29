#!/bin/bash

sudo apt-get install libgcrypt11 libgcrypt11-dev
gcc -o hw1 hw1-1647357.c `libgcrypt-config --cflags --libs` -O1 -lpthread

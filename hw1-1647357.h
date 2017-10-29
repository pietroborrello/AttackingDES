#include <gcrypt.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define CORRECT_SIZE(x) (((x + 7) / 8) * 8)
#define MAX_ITERATIONS (72057594037927936)
#define SCALE_ITERATION (128)
#define COMPLEXITY (3)
#define THREAD_NUM 8

// init the known plaintext - cihpertext pair
unsigned char *init_crypt();

// compute the next key in key space enumeration
int next_key(unsigned char key[8]);

int main();

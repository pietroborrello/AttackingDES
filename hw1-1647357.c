#include "hw1-1647357.h"

char plain[] = "Plz keep using DES I won't spy you ;)";
unsigned char *crypted;
int tick = 0;

unsigned char *init_crypt() {
  unsigned char key[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  gcry_cipher_hd_t crypter;
  unsigned char *out;
  unsigned char plaintext[CORRECT_SIZE(sizeof(plain))] = {0};
  int keylen = 8;
  gpg_error_t err = 0;

  int n = CORRECT_SIZE(sizeof(plain));

  out = (unsigned char *)calloc(n, sizeof(unsigned char));

  memcpy(plaintext, plain, sizeof(plain));

  printf(ANSI_COLOR_CYAN "libgcrypt version: " ANSI_COLOR_RESET "%s\n",
         gcry_check_version(NULL));

  gcry_randomize(key, COMPLEXITY, GCRY_STRONG_RANDOM);
  printf(ANSI_COLOR_CYAN "randomized key: " ANSI_COLOR_RESET);
  for (int i = 0; i < sizeof(key); i++) {
    printf("%02x", key[i]);
  }
  putchar('\n');

  err = gcry_cipher_open(&crypter, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0);
  if (err) {
    printf(ANSI_COLOR_RED "open cipher failed: %s" ANSI_COLOR_RESET "\n",
           gpg_strerror(err));
    return 0;
  }

  err = gcry_cipher_setkey(crypter, key, keylen);
  if (err) {
    printf(ANSI_COLOR_RED "set key failed: %s" ANSI_COLOR_RESET "\n",
           gpg_strerror(err));
    gcry_cipher_close(crypter);
    return 0;
  }

  err = gcry_cipher_encrypt(crypter, out, n, plain, n);
  if (err) {
    printf(ANSI_COLOR_RED "encrypt failed: %s" ANSI_COLOR_RESET "\n",
           gpg_strerror(err));
    gcry_cipher_close(crypter);
    return 0;
  }

  printf(ANSI_COLOR_CYAN "known plaintext: " ANSI_COLOR_RESET "%s\n", plain);
  printf(ANSI_COLOR_CYAN "known cyphertext: " ANSI_COLOR_RESET);
  for (int i = 0; i < n; i++) {
    printf("%02x", out[i]);
  }
  putchar('\n');

  gcry_cipher_reset(crypter);
  gcry_cipher_close(crypter);
  return out;
}

int next_key(unsigned char key[8]) {
  unsigned char to_sum[8] = {2, 0, 0, 0, 0, 0, 0, 0};

  for (int i = 0; i < 8; i++) {
    unsigned char temp = key[i];
    key[i] += to_sum[i];
    if (key[i] < temp) {
      if (i == COMPLEXITY - 2) {
        // not in mutial exclusion for performance reasons:
        // increasing tick is not too frequent and
        // missing a tick won't ruin progress status
        tick++;
        double progress = (double)tick / 128;
        printf("\rsearching in key space: %0.2f%%", progress * 100);
        fflush(stdout);
      }
      if (i < 7)
        to_sum[i + 1] += 2;
      else
        return -1;
    }
  }
  return 0;
}

void *search_in_key_space(void *args) {
  uint64_t id = (uint64_t)args;
  unsigned char key[8] = {0};
  gcry_cipher_hd_t crypter;
  unsigned char in[CORRECT_SIZE(sizeof(plain))] = {0};
  int keylen = 8;
  gpg_error_t err = 0;

  int n = CORRECT_SIZE(sizeof(plain));

  // diving search space for keys, differentiating starting points
  key[COMPLEXITY - 1] = id << 5; //(8-log(num_treads))

  if (!crypted)
    return NULL;

  err = gcry_cipher_open(&crypter, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0);
  if (err) {
    printf(ANSI_COLOR_RED "open cipher failed: %s" ANSI_COLOR_RESET "\n",
           gpg_strerror(err));
    return NULL;
  }

  while (1) {

    err = gcry_cipher_setkey(crypter, key, keylen);
    if (err) {
      if (gcry_err_code(err) == GPG_ERR_WEAK_KEY) {
        goto next;
        // continue;
      }
      printf(ANSI_COLOR_RED "set key failed: %s" ANSI_COLOR_RESET "\n",
             gpg_strerror(err));
      gcry_cipher_close(crypter);
      return NULL;
    }
    /*printf("key: ");
    for (int i = 0; i < sizeof(key); i++) {
      printf("%02x", key[i]);
    }
    putchar('\n');*/
    err = gcry_cipher_decrypt(crypter, in, n, crypted, n);
    if (err) {
      printf("decryption failed: %s\n", gpg_strerror(err));
      gcry_cipher_close(crypter);
      return NULL;
    }
    gcry_cipher_reset(crypter);

    if (!memcmp(plain, in, sizeof(plain)))
      break;
  next:
    if (next_key(key)) {
      // printf(ANSI_COLOR_RED "key not found: plaintext-cyphertext pair
      // invalid\n" ANSI_COLOR_RESET);
      gcry_cipher_close(crypter);
      return NULL;
    }
  }
  printf(ANSI_COLOR_GREEN "\ndecryption OK\n");
  printf("found key: ");
  for (int i = 0; i < sizeof(key); i++) {
    printf("%02x", key[i]);
  }
  printf(ANSI_COLOR_RESET "\n");
  exit(0); // found key, all done
}

int main() {
  pthread_t tids[THREAD_NUM];

  crypted = init_crypt();

  printf(ANSI_COLOR_CYAN "starting bruteforce on key..." ANSI_COLOR_RESET "\n");

  for (uint64_t i = 0; i < THREAD_NUM; i++) {
    pthread_create(&tids[i], NULL, search_in_key_space, (void *)i);
  }

  for (int i = 0; i < THREAD_NUM; i++) {
    pthread_join(tids[i], NULL);
  }
  printf(ANSI_COLOR_RED
         "key not found: plaintext-cyphertext pair invalid\n" ANSI_COLOR_RESET);
}

#include "util.h"

#include <stdio.h>
#include <stdlib.h>

void print_hex_with_delim(const unsigned char *buf, size_t len,
                          const char delim[]) {
  size_t i;
  for (i = 0; i < len; i++) {
    printf("%02X", *(buf + i));
    if (i < len - 1) printf("%s", delim);
  }
  putchar('\n');
}

void print_hex(const unsigned char *buf, size_t len) {
  print_hex_with_delim(buf, len, "");
}

void str_to_hex(const char *buf, size_t *len, unsigned char **hex) {
  if ((*len & 1) != 0) {
    printf("str_to_hex: len should be even\n");
    return;
  }

  *hex = malloc(*len / 2);
  if (*hex == NULL) {
    return;
  }

  size_t i;
  unsigned int uchr;
  for (i = 0; i < *len; i += 2) {
    sscanf(buf + i, "%02X", &uchr);
    (*hex)[i / 2] = uchr;
  }

  *len = *len / 2;
}

#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

#define SAFE_DEL(p) if (p != NULL) free(p); p = NULL

void print_hex_with_delim(const unsigned char *buf, size_t len, char delim[]);
void print_hex(const unsigned char *buf, size_t len);
void str_to_hex(const char *buf, size_t *len, unsigned char **hex);

#endif // UTIL_H

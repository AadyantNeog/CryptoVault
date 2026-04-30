#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

int key_hex_to_bytes(const char *key_hex, unsigned char *out_bytes, size_t *out_len);
void crypto_xor_stream(unsigned char *buffer, size_t length, const char *key_hex, uint64_t *state);
int crypto_generate_key(char *key_hex, size_t size);

#endif

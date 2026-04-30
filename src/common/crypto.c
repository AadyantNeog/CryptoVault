#include "common/crypto.h"
#include "common/common.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

int key_hex_to_bytes(const char *key_hex, unsigned char *out_bytes, size_t *out_len) {
    size_t len;
    size_t i;

    if (key_hex == NULL || out_bytes == NULL || out_len == NULL) {
        return -1;
    }

    len = strlen(key_hex);
    if (len == 0 || (len % 2) != 0) {
        return -1;
    }

    for (i = 0; i < len; i += 2) {
        int high = hex_value(key_hex[i]);
        int low = hex_value(key_hex[i + 1]);
        if (high < 0 || low < 0) {
            return -1;
        }
        out_bytes[i / 2] = (unsigned char) ((high << 4) | low);
    }

    *out_len = len / 2;
    return 0;
}

/*
 * Educational stream cipher:
 * turns a hex key into a deterministic xorshift64 keystream.
 * This keeps the project self-contained in pure C/Linux without external crypto libraries.
 */
void crypto_xor_stream(unsigned char *buffer, size_t length, const char *key_hex, uint64_t *state) {
    unsigned char key_bytes[32];
    size_t key_len = 0;
    size_t i;
    uint64_t local_state;

    if (buffer == NULL || key_hex == NULL || state == NULL) {
        return;
    }

    if (*state == 0) {
        if (key_hex_to_bytes(key_hex, key_bytes, &key_len) != 0 || key_len == 0) {
            key_bytes[0] = 0xAA;
            key_len = 1;
        }
        local_state = 0x9e3779b97f4a7c15ULL;
        for (i = 0; i < key_len; ++i) {
            local_state ^= (uint64_t) key_bytes[i] << ((i % 8U) * 8U);
            local_state *= 6364136223846793005ULL;
        }
        *state = local_state;
    }

    local_state = *state;
    for (i = 0; i < length; ++i) {
        local_state ^= local_state << 13;
        local_state ^= local_state >> 7;
        local_state ^= local_state << 17;
        buffer[i] ^= (unsigned char) (local_state & 0xFFU);
    }
    *state = local_state;
}

int crypto_generate_key(char *key_hex, size_t size) {
    if (size < 33) {
        return -1;
    }
    return generate_random_hex(key_hex, 32);
}

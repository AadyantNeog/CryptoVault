#include "common/common.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int send_all(int sockfd, const void *buffer, size_t length) {
    const unsigned char *ptr = (const unsigned char *) buffer;
    size_t total = 0;

    while (total < length) {
        ssize_t sent = send(sockfd, ptr + total, length - total, 0);
        if (sent <= 0) {
            return -1;
        }
        total += (size_t) sent;
    }

    return 0;
}

int recv_all(int sockfd, void *buffer, size_t length) {
    unsigned char *ptr = (unsigned char *) buffer;
    size_t total = 0;

    while (total < length) {
        ssize_t received = recv(sockfd, ptr + total, length - total, 0);
        if (received <= 0) {
            return -1;
        }
        total += (size_t) received;
    }

    return 0;
}

int recv_line(int sockfd, char *buffer, size_t size) {
    size_t index = 0;

    if (size == 0) {
        return -1;
    }

    while (index + 1 < size) {
        char ch;
        ssize_t received = recv(sockfd, &ch, 1, 0);
        if (received <= 0) {
            return -1;
        }
        if (ch == '\n') {
            break;
        }
        buffer[index++] = ch;
    }

    buffer[index] = '\0';
    trim_newline(buffer);
    return (int) index;
}

int send_linef(int sockfd, const char *fmt, ...) {
    char buffer[MAX_LINE];
    va_list args;

    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    size_t len = strlen(buffer);
    if (len + 1 >= sizeof(buffer)) {
        return -1;
    }

    buffer[len] = '\n';
    buffer[len + 1] = '\0';
    return send_all(sockfd, buffer, len + 1);
}

void trim_newline(char *text) {
    if (text == NULL) {
        return;
    }

    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[len - 1] = '\0';
        len--;
    }
}

void safe_copy(char *dst, size_t dst_size, const char *src) {
    if (dst_size == 0) {
        return;
    }

    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    snprintf(dst, dst_size, "%s", src);
}

void simple_hash_password(const char *username, const char *password, char *out_hex, size_t out_size) {
    uint64_t hash = 1469598103934665603ULL;
    const unsigned char *ptr;

    for (ptr = (const unsigned char *) username; ptr != NULL && *ptr != '\0'; ++ptr) {
        hash ^= *ptr;
        hash *= 1099511628211ULL;
    }

    hash ^= ':';
    hash *= 1099511628211ULL;

    for (ptr = (const unsigned char *) password; ptr != NULL && *ptr != '\0'; ++ptr) {
        hash ^= *ptr;
        hash *= 1099511628211ULL;
    }

    snprintf(out_hex, out_size, "%016llx", (unsigned long long) hash);
}

int generate_random_hex(char *out_hex, size_t hex_chars) {
    static const char *hex = "0123456789abcdef";
    size_t bytes_needed = hex_chars / 2;
    unsigned char buffer[64];
    int fd;
    size_t i;

    if (hex_chars == 0 || (hex_chars % 2) != 0 || bytes_needed > sizeof(buffer)) {
        return -1;
    }

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (read(fd, buffer, bytes_needed) != (ssize_t) bytes_needed) {
        close(fd);
        return -1;
    }

    close(fd);

    for (i = 0; i < bytes_needed; ++i) {
        out_hex[i * 2] = hex[(buffer[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex[buffer[i] & 0x0F];
    }
    out_hex[hex_chars] = '\0';
    return 0;
}

int split_csv_contains(const char *csv, const char *value) {
    char copy[MAX_SHARED];
    char *saveptr = NULL;
    char *token;

    if (csv == NULL || csv[0] == '\0' || value == NULL || value[0] == '\0') {
        return 0;
    }

    safe_copy(copy, sizeof(copy), csv);
    token = strtok_r(copy, ",", &saveptr);
    while (token != NULL) {
        if (strcmp(token, value) == 0) {
            return 1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    return 0;
}

void append_csv_unique(char *csv, size_t csv_size, const char *value) {
    if (csv == NULL || value == NULL || value[0] == '\0') {
        return;
    }

    if (split_csv_contains(csv, value)) {
        return;
    }

    if (csv[0] == '\0') {
        snprintf(csv, csv_size, "%s", value);
        return;
    }

    snprintf(csv + strlen(csv), csv_size - strlen(csv), ",%s", value);
}

void current_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm tm_value;

    localtime_r(&now, &tm_value);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", &tm_value);
}

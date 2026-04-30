#ifndef COMMON_H
#define COMMON_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define MAX_LINE 1024
#define MAX_NAME 64
#define MAX_ROLE 16
#define MAX_SHARED 512
#define MAX_PATH_LEN 512
#define MAX_KEY_HEX 65
#define FILE_DB_LINE 1400

typedef struct {
    char id[32];
    char owner[MAX_NAME];
    char stored_name[128];
    char original_name[256];
    char key_hex[MAX_KEY_HEX];
    long size;
    long created_at;
    char shared_with[MAX_SHARED];
} VaultFile;

typedef struct {
    int active_clients;
    int total_clients_served;
    int total_uploads;
    int total_downloads;
    int total_commands;
} VaultStats;

int send_all(int sockfd, const void *buffer, size_t length);
int recv_all(int sockfd, void *buffer, size_t length);
int recv_line(int sockfd, char *buffer, size_t size);
int send_linef(int sockfd, const char *fmt, ...);

void trim_newline(char *text);
void safe_copy(char *dst, size_t dst_size, const char *src);
void simple_hash_password(const char *username, const char *password, char *out_hex, size_t out_size);
int generate_random_hex(char *out_hex, size_t hex_chars);
int split_csv_contains(const char *csv, const char *value);
void append_csv_unique(char *csv, size_t csv_size, const char *value);
void current_timestamp(char *buffer, size_t size);

#endif

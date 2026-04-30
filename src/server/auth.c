#include "server/auth.h"

#include "common/common.h"
#include "server/lock_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void users_path(char *buffer, size_t size, const char *storage_root) {
    snprintf(buffer, size, "%s/users.db", storage_root);
}

static int is_valid_role(const char *role) {
    return strcmp(role, "admin") == 0 || strcmp(role, "user") == 0 || strcmp(role, "guest") == 0;
}

int auth_init_defaults(const char *storage_root) {
    char path[MAX_PATH_LEN];
    FILE *fp;
    char hash[32];

    users_path(path, sizeof(path), storage_root);
    if (access(path, F_OK) == 0) {
        return 0;
    }

    fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }

    simple_hash_password("admin", "admin123", hash, sizeof(hash));
    fprintf(fp, "admin|admin|%s\n", hash);

    simple_hash_password("alice", "alice123", hash, sizeof(hash));
    fprintf(fp, "alice|user|%s\n", hash);

    simple_hash_password("guest", "guest123", hash, sizeof(hash));
    fprintf(fp, "guest|guest|%s\n", hash);

    fclose(fp);
    return 0;
}

int auth_verify_credentials(const char *storage_root, const char *username, const char *password, char *role_out, size_t role_out_size) {
    char path[MAX_PATH_LEN];
    FILE *fp;
    char line[256];
    char hash[32];

    users_path(path, sizeof(path), storage_root);
    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }

    simple_hash_password(username, password, hash, sizeof(hash));

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *saveptr = NULL;
        char *file_user = strtok_r(line, "|", &saveptr);
        char *file_role = strtok_r(NULL, "|", &saveptr);
        char *file_hash = strtok_r(NULL, "|", &saveptr);

        if (file_user == NULL || file_role == NULL || file_hash == NULL) {
            continue;
        }

        trim_newline(file_hash);
        if (strcmp(file_user, username) == 0 && strcmp(file_hash, hash) == 0) {
            safe_copy(role_out, role_out_size, file_role);
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

int auth_user_exists(const char *storage_root, const char *username) {
    char path[MAX_PATH_LEN];
    FILE *fp;
    char line[256];

    users_path(path, sizeof(path), storage_root);
    fp = fopen(path, "r");
    if (fp == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *saveptr = NULL;
        char *file_user = strtok_r(line, "|", &saveptr);
        if (file_user != NULL && strcmp(file_user, username) == 0) {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

int auth_create_user(const char *storage_root, const char *username, const char *password, const char *role) {
    char path[MAX_PATH_LEN];
    int fd;
    FILE *fp;
    char hash[32];

    if (username == NULL || password == NULL || role == NULL || !is_valid_role(role)) {
        return -1;
    }

    if (auth_user_exists(storage_root, username)) {
        return -1;
    }

    users_path(path, sizeof(path), storage_root);
    fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        return -1;
    }

    if (lock_fd(fd, F_WRLCK) != 0) {
        close(fd);
        return -1;
    }

    fp = fdopen(fd, "a");
    if (fp == NULL) {
        unlock_fd(fd);
        close(fd);
        return -1;
    }

    simple_hash_password(username, password, hash, sizeof(hash));
    fprintf(fp, "%s|%s|%s\n", username, role, hash);
    fflush(fp);

    unlock_fd(fd);
    fclose(fp);
    return 0;
}

#include "server/storage.h"

#include "common/common.h"
#include "server/auth.h"
#include "server/lock_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void files_path(char *buffer, size_t size, const char *storage_root) {
    snprintf(buffer, size, "%s/files.db", storage_root);
}

int storage_build_blob_path(const char *storage_root, const char *stored_name, char *buffer, size_t size) {
    return snprintf(buffer, size, "%s/blobs/%s", storage_root, stored_name) >= (int) size ? -1 : 0;
}

static int parse_file_line(const char *line, VaultFile *file) {
    char copy[FILE_DB_LINE];
    char *saveptr = NULL;
    char *field;

    safe_copy(copy, sizeof(copy), line);

    field = strtok_r(copy, "|", &saveptr);
    if (field == NULL) {
        return -1;
    }
    safe_copy(file->id, sizeof(file->id), field);

    field = strtok_r(NULL, "|", &saveptr);
    if (field == NULL) {
        return -1;
    }
    safe_copy(file->owner, sizeof(file->owner), field);

    field = strtok_r(NULL, "|", &saveptr);
    if (field == NULL) {
        return -1;
    }
    safe_copy(file->stored_name, sizeof(file->stored_name), field);

    field = strtok_r(NULL, "|", &saveptr);
    if (field == NULL) {
        return -1;
    }
    safe_copy(file->original_name, sizeof(file->original_name), field);

    field = strtok_r(NULL, "|", &saveptr);
    if (field == NULL) {
        return -1;
    }
    safe_copy(file->key_hex, sizeof(file->key_hex), field);

    field = strtok_r(NULL, "|", &saveptr);
    if (field == NULL) {
        return -1;
    }
    file->size = atol(field);

    field = strtok_r(NULL, "|", &saveptr);
    if (field == NULL) {
        return -1;
    }
    file->created_at = atol(field);

    field = strtok_r(NULL, "|", &saveptr);
    if (field == NULL) {
        file->shared_with[0] = '\0';
        return 0;
    }
    trim_newline(field);
    safe_copy(file->shared_with, sizeof(file->shared_with), field);
    return 0;
}

static void write_file_record(FILE *fp, const VaultFile *file) {
    fprintf(fp, "%s|%s|%s|%s|%s|%ld|%ld|%s\n",
            file->id,
            file->owner,
            file->stored_name,
            file->original_name,
            file->key_hex,
            file->size,
            file->created_at,
            file->shared_with);
}

int storage_init(const char *storage_root) {
    char blob_dir[MAX_PATH_LEN];
    char files_db[MAX_PATH_LEN];
    FILE *fp;

    snprintf(blob_dir, sizeof(blob_dir), "%s/blobs", storage_root);
    mkdir(storage_root, 0700);
    mkdir(blob_dir, 0700);

    files_path(files_db, sizeof(files_db), storage_root);
    if (access(files_db, F_OK) != 0) {
        fp = fopen(files_db, "w");
        if (fp == NULL) {
            return -1;
        }
        fclose(fp);
    }

    return auth_init_defaults(storage_root);
}

int storage_add_file(const char *storage_root, const VaultFile *file) {
    char path[MAX_PATH_LEN];
    int fd;
    FILE *fp;

    files_path(path, sizeof(path), storage_root);
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

    write_file_record(fp, file);
    fflush(fp);
    unlock_fd(fd);
    fclose(fp);
    return 0;
}

int storage_get_file(const char *storage_root, const char *file_id, VaultFile *out_file) {
    char path[MAX_PATH_LEN];
    int fd;
    FILE *fp;
    char line[FILE_DB_LINE];
    int result = -1;

    files_path(path, sizeof(path), storage_root);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (lock_fd(fd, F_RDLCK) != 0) {
        close(fd);
        return -1;
    }

    fp = fdopen(fd, "r");
    if (fp == NULL) {
        unlock_fd(fd);
        close(fd);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        VaultFile file;
        if (parse_file_line(line, &file) == 0 && strcmp(file.id, file_id) == 0) {
            *out_file = file;
            result = 0;
            break;
        }
    }

    unlock_fd(fd);
    fclose(fp);
    return result;
}

int storage_has_access(const VaultFile *file, const char *username, const char *role) {
    if (strcmp(role, "admin") == 0) {
        return 1;
    }
    if (strcmp(file->owner, username) == 0) {
        return 1;
    }
    return split_csv_contains(file->shared_with, username);
}

int storage_list_accessible(const char *storage_root, const char *username, const char *role, char *buffer, size_t size) {
    char path[MAX_PATH_LEN];
    int fd;
    FILE *fp;
    char line[FILE_DB_LINE];
    size_t used = 0;

    if (size == 0) {
        return -1;
    }

    buffer[0] = '\0';

    files_path(path, sizeof(path), storage_root);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (lock_fd(fd, F_RDLCK) != 0) {
        close(fd);
        return -1;
    }

    fp = fdopen(fd, "r");
    if (fp == NULL) {
        unlock_fd(fd);
        close(fd);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        VaultFile file;
        int written;
        if (parse_file_line(line, &file) != 0) {
            continue;
        }
        if (!storage_has_access(&file, username, role)) {
            continue;
        }

        written = snprintf(buffer + used, size - used,
                           "ID=%s OWNER=%s NAME=%s SIZE=%ld SHARED=%s\n",
                           file.id,
                           file.owner,
                           file.original_name,
                           file.size,
                           file.shared_with[0] != '\0' ? file.shared_with : "-");
        if (written < 0 || (size_t) written >= size - used) {
            break;
        }
        used += (size_t) written;
    }

    if (used == 0) {
        snprintf(buffer, size, "No accessible files found.\n");
    }

    unlock_fd(fd);
    fclose(fp);
    return 0;
}

static int rewrite_db_with_update(const char *storage_root,
                                  const char *target_file_id,
                                  int (*updater)(VaultFile *file, void *ctx),
                                  void *ctx) {
    char path[MAX_PATH_LEN];
    char temp_path[MAX_PATH_LEN];
    int fd;
    FILE *source;
    FILE *temp;
    char line[FILE_DB_LINE];
    int changed = 0;

    files_path(path, sizeof(path), storage_root);
    snprintf(temp_path, sizeof(temp_path), "%s/files.db.tmp", storage_root);

    fd = open(path, O_RDWR);
    if (fd < 0) {
        return -1;
    }
    if (lock_fd(fd, F_WRLCK) != 0) {
        close(fd);
        return -1;
    }

    source = fdopen(fd, "r");
    if (source == NULL) {
        unlock_fd(fd);
        close(fd);
        return -1;
    }

    temp = fopen(temp_path, "w");
    if (temp == NULL) {
        unlock_fd(fd);
        fclose(source);
        return -1;
    }

    while (fgets(line, sizeof(line), source) != NULL) {
        VaultFile file;
        if (parse_file_line(line, &file) != 0) {
            continue;
        }

        if (strcmp(file.id, target_file_id) == 0) {
            int action = updater(&file, ctx);
            if (action < 0) {
                fclose(temp);
                unlink(temp_path);
                unlock_fd(fd);
                fclose(source);
                return -1;
            }
            if (action == 0) {
                write_file_record(temp, &file);
            }
            changed = 1;
        } else {
            write_file_record(temp, &file);
        }
    }

    fflush(temp);
    fclose(temp);
    fflush(source);
    fclose(source);

    if (!changed) {
        unlink(temp_path);
        return -1;
    }

    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return -1;
    }

    return 0;
}

typedef struct {
    const char *requester;
    const char *role;
    const char *target_user;
} ShareContext;

static int share_updater(VaultFile *file, void *ctx) {
    ShareContext *share = (ShareContext *) ctx;

    if (strcmp(share->role, "admin") != 0 && strcmp(file->owner, share->requester) != 0) {
        return -1;
    }
    append_csv_unique(file->shared_with, sizeof(file->shared_with), share->target_user);
    return 0;
}

int storage_share_file(const char *storage_root, const char *file_id, const char *requester, const char *role, const char *target_user) {
    ShareContext ctx;

    if (!auth_user_exists(storage_root, target_user)) {
        return -1;
    }

    ctx.requester = requester;
    ctx.role = role;
    ctx.target_user = target_user;

    return rewrite_db_with_update(storage_root, file_id, share_updater, &ctx);
}

typedef struct {
    const char *requester;
    const char *role;
    char storage_root[MAX_PATH_LEN];
} DeleteContext;

static int delete_updater(VaultFile *file, void *ctx) {
    DeleteContext *del = (DeleteContext *) ctx;
    char blob_path[MAX_PATH_LEN];

    if (strcmp(del->role, "admin") != 0 && strcmp(file->owner, del->requester) != 0) {
        return -1;
    }

    if (storage_build_blob_path(del->storage_root, file->stored_name, blob_path, sizeof(blob_path)) == 0) {
        unlink(blob_path);
    }

    return 1;
}

int storage_delete_file(const char *storage_root, const char *file_id, const char *requester, const char *role) {
    DeleteContext ctx;
    ctx.requester = requester;
    ctx.role = role;
    safe_copy(ctx.storage_root, sizeof(ctx.storage_root), storage_root);
    return rewrite_db_with_update(storage_root, file_id, delete_updater, &ctx);
}

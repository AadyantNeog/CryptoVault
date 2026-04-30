#ifndef STORAGE_H
#define STORAGE_H

#include "common/common.h"

#include <stddef.h>

int storage_init(const char *storage_root);
int storage_add_file(const char *storage_root, const VaultFile *file);
int storage_get_file(const char *storage_root, const char *file_id, VaultFile *out_file);
int storage_list_accessible(const char *storage_root, const char *username, const char *role, char *buffer, size_t size);
int storage_share_file(const char *storage_root, const char *file_id, const char *requester, const char *role, const char *target_user);
int storage_delete_file(const char *storage_root, const char *file_id, const char *requester, const char *role);
int storage_build_blob_path(const char *storage_root, const char *stored_name, char *buffer, size_t size);
int storage_has_access(const VaultFile *file, const char *username, const char *role);

#endif

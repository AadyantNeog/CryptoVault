#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

int auth_init_defaults(const char *storage_root);
int auth_verify_credentials(const char *storage_root, const char *username, const char *password, char *role_out, size_t role_out_size);
int auth_user_exists(const char *storage_root, const char *username);
int auth_create_user(const char *storage_root, const char *username, const char *password, const char *role);

#endif

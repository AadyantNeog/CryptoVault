#include "server/server.h"

#include "common/common.h"
#include "server/auth.h"
#include "server/storage.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int sockfd;
    ServerContext *ctx;
    int authenticated;
    char username[MAX_NAME];
    char role[MAX_ROLE];
} ClientSession;

static int can_upload(const ClientSession *session) {
    return strcmp(session->role, "admin") == 0 || strcmp(session->role, "user") == 0;
}

static int save_upload_blob(int sockfd, const char *path, long size) {
    FILE *fp = fopen(path, "wb");
    unsigned char buffer[4096];
    long remaining = size;

    if (fp == NULL) {
        return -1;
    }

    while (remaining > 0) {
        size_t chunk = remaining > (long) sizeof(buffer) ? sizeof(buffer) : (size_t) remaining;
        if (recv_all(sockfd, buffer, chunk) != 0) {
            fclose(fp);
            return -1;
        }
        if (fwrite(buffer, 1, chunk, fp) != chunk) {
            fclose(fp);
            return -1;
        }
        remaining -= (long) chunk;
    }

    fclose(fp);
    return 0;
}

static int stream_download_blob(int sockfd, const char *path, long size) {
    FILE *fp = fopen(path, "rb");
    unsigned char buffer[4096];
    long remaining = size;

    if (fp == NULL) {
        return -1;
    }

    while (remaining > 0) {
        size_t chunk = remaining > (long) sizeof(buffer) ? sizeof(buffer) : (size_t) remaining;
        if (fread(buffer, 1, chunk, fp) != chunk) {
            fclose(fp);
            return -1;
        }
        if (send_all(sockfd, buffer, chunk) != 0) {
            fclose(fp);
            return -1;
        }
        remaining -= (long) chunk;
    }

    fclose(fp);
    return 0;
}

static int handle_upload(ClientSession *session, char *remote_name, char *size_text, char *key_hex) {
    long size;
    VaultFile file;
    char blob_name[80];
    char blob_path[MAX_PATH_LEN];

    if (!session->authenticated) {
        return send_linef(session->sockfd, "ERR Please login first");
    }
    if (!can_upload(session)) {
        return send_linef(session->sockfd, "ERR Role is not allowed to upload");
    }
    if (remote_name == NULL || size_text == NULL || key_hex == NULL) {
        return send_linef(session->sockfd, "ERR Usage: UPLOAD <remote_name> <size> <key_hex>");
    }

    size = atol(size_text);
    if (size < 0) {
        return send_linef(session->sockfd, "ERR Invalid file size");
    }

    if (generate_random_hex(file.id, 16) != 0 || generate_random_hex(blob_name, 24) != 0) {
        return send_linef(session->sockfd, "ERR Could not generate file identifiers");
    }

    snprintf(file.stored_name, sizeof(file.stored_name), "%s.bin", blob_name);
    safe_copy(file.owner, sizeof(file.owner), session->username);
    safe_copy(file.original_name, sizeof(file.original_name), remote_name);
    safe_copy(file.key_hex, sizeof(file.key_hex), key_hex);
    file.size = size;
    file.created_at = time(NULL);
    file.shared_with[0] = '\0';

    if (storage_build_blob_path(session->ctx->storage_root, file.stored_name, blob_path, sizeof(blob_path)) != 0) {
        return send_linef(session->sockfd, "ERR Internal storage path error");
    }

    if (send_linef(session->sockfd, "READY %s", file.id) != 0) {
        return -1;
    }

    sem_wait(&session->ctx->ipc.transfer_slots);
    if (save_upload_blob(session->sockfd, blob_path, size) != 0) {
        sem_post(&session->ctx->ipc.transfer_slots);
        unlink(blob_path);
        return send_linef(session->sockfd, "ERR Upload data transfer failed");
    }
    sem_post(&session->ctx->ipc.transfer_slots);

    if (storage_add_file(session->ctx->storage_root, &file) != 0) {
        unlink(blob_path);
        return send_linef(session->sockfd, "ERR Could not commit metadata");
    }

    ipc_increment_uploads(&session->ctx->ipc);
    ipc_logf(&session->ctx->ipc, "UPLOAD user=%s file_id=%s name=%s size=%ld\n",
             session->username, file.id, file.original_name, file.size);

    return send_linef(session->sockfd, "OK Upload complete. File ID: %s", file.id);
}

static int handle_download(ClientSession *session, char *file_id) {
    VaultFile file;
    char blob_path[MAX_PATH_LEN];
    char line[MAX_LINE];

    if (!session->authenticated) {
        return send_linef(session->sockfd, "ERR Please login first");
    }
    if (file_id == NULL) {
        return send_linef(session->sockfd, "ERR Usage: DOWNLOAD <file_id>");
    }
    if (storage_get_file(session->ctx->storage_root, file_id, &file) != 0) {
        return send_linef(session->sockfd, "ERR File not found");
    }
    if (!storage_has_access(&file, session->username, session->role)) {
        return send_linef(session->sockfd, "ERR Access denied");
    }
    if (storage_build_blob_path(session->ctx->storage_root, file.stored_name, blob_path, sizeof(blob_path)) != 0) {
        return send_linef(session->sockfd, "ERR Internal path error");
    }

    if (send_linef(session->sockfd, "FILE %s %ld %s", file.original_name, file.size, file.key_hex) != 0) {
        return -1;
    }
    if (recv_line(session->sockfd, line, sizeof(line)) <= 0) {
        return -1;
    }
    if (strcmp(line, "READY") != 0) {
        return send_linef(session->sockfd, "ERR Client did not acknowledge download");
    }

    sem_wait(&session->ctx->ipc.transfer_slots);
    if (stream_download_blob(session->sockfd, blob_path, file.size) != 0) {
        sem_post(&session->ctx->ipc.transfer_slots);
        return send_linef(session->sockfd, "ERR Download transfer failed");
    }
    sem_post(&session->ctx->ipc.transfer_slots);

    ipc_increment_downloads(&session->ctx->ipc);
    ipc_logf(&session->ctx->ipc, "DOWNLOAD user=%s file_id=%s name=%s\n",
             session->username, file.id, file.original_name);
    return send_linef(session->sockfd, "OK Download complete");
}

static int handle_list(ClientSession *session) {
    char listing[8192];
    char *line;
    char *saveptr = NULL;

    if (!session->authenticated) {
        return send_linef(session->sockfd, "ERR Please login first");
    }

    if (storage_list_accessible(session->ctx->storage_root, session->username, session->role, listing, sizeof(listing)) != 0) {
        return send_linef(session->sockfd, "ERR Could not read file list");
    }

    send_linef(session->sockfd, "LIST_BEGIN");
    line = strtok_r(listing, "\n", &saveptr);
    while (line != NULL) {
        send_linef(session->sockfd, "%s", line);
        line = strtok_r(NULL, "\n", &saveptr);
    }
    return send_linef(session->sockfd, "LIST_END");
}

static int handle_create_user(ClientSession *session, char *username, char *password, char *role) {
    if (!session->authenticated || strcmp(session->role, "admin") != 0) {
        return send_linef(session->sockfd, "ERR Only admin can create users");
    }
    if (username == NULL || password == NULL || role == NULL) {
        return send_linef(session->sockfd, "ERR Usage: CREATE_USER <username> <password> <role>");
    }
    if (auth_create_user(session->ctx->storage_root, username, password, role) != 0) {
        return send_linef(session->sockfd, "ERR Could not create user");
    }
    ipc_logf(&session->ctx->ipc, "CREATE_USER admin=%s user=%s role=%s\n", session->username, username, role);
    return send_linef(session->sockfd, "OK User created");
}

static int handle_share(ClientSession *session, char *file_id, char *target_user) {
    if (!session->authenticated) {
        return send_linef(session->sockfd, "ERR Please login first");
    }
    if (strcmp(session->role, "guest") == 0) {
        return send_linef(session->sockfd, "ERR Guests cannot share files");
    }
    if (file_id == NULL || target_user == NULL) {
        return send_linef(session->sockfd, "ERR Usage: SHARE <file_id> <target_user>");
    }
    if (storage_share_file(session->ctx->storage_root, file_id, session->username, session->role, target_user) != 0) {
        return send_linef(session->sockfd, "ERR Could not share file");
    }
    ipc_logf(&session->ctx->ipc, "SHARE requester=%s file_id=%s target=%s\n", session->username, file_id, target_user);
    return send_linef(session->sockfd, "OK File shared");
}

static int handle_delete(ClientSession *session, char *file_id) {
    if (!session->authenticated) {
        return send_linef(session->sockfd, "ERR Please login first");
    }
    if (file_id == NULL) {
        return send_linef(session->sockfd, "ERR Usage: DELETE <file_id>");
    }
    if (storage_delete_file(session->ctx->storage_root, file_id, session->username, session->role) != 0) {
        return send_linef(session->sockfd, "ERR Could not delete file");
    }
    ipc_logf(&session->ctx->ipc, "DELETE requester=%s file_id=%s\n", session->username, file_id);
    return send_linef(session->sockfd, "OK File deleted");
}

static int handle_stats(ClientSession *session) {
    char stats[512];
    char *line;
    char *saveptr = NULL;

    if (!session->authenticated || strcmp(session->role, "admin") != 0) {
        return send_linef(session->sockfd, "ERR Only admin can view stats");
    }

    ipc_format_stats(&session->ctx->ipc, stats, sizeof(stats));
    send_linef(session->sockfd, "STATS_BEGIN");
    line = strtok_r(stats, "\n", &saveptr);
    while (line != NULL) {
        send_linef(session->sockfd, "%s", line);
        line = strtok_r(NULL, "\n", &saveptr);
    }
    return send_linef(session->sockfd, "STATS_END");
}

static void *client_thread(void *arg) {
    ClientSession *session = (ClientSession *) arg;
    char line[MAX_LINE];

    send_linef(session->sockfd, "OK Connected to CryptoVault server");
    ipc_adjust_active_clients(&session->ctx->ipc, 1);
    ipc_increment_total_clients(&session->ctx->ipc);

    while (!*session->ctx->stop_flag) {
        char *saveptr = NULL;
        char *command;

        if (recv_line(session->sockfd, line, sizeof(line)) <= 0) {
            break;
        }
        if (line[0] == '\0') {
            continue;
        }

        ipc_increment_commands(&session->ctx->ipc);
        command = strtok_r(line, " ", &saveptr);
        if (command == NULL) {
            continue;
        }

        if (strcmp(command, "HELP") == 0) {
            send_linef(session->sockfd, "OK Commands: LOGIN CREATE_USER LIST UPLOAD DOWNLOAD SHARE DELETE STATS QUIT");
        } else if (strcmp(command, "LOGIN") == 0) {
            char *username = strtok_r(NULL, " ", &saveptr);
            char *password = strtok_r(NULL, " ", &saveptr);
            char role[MAX_ROLE];

            if (username == NULL || password == NULL) {
                send_linef(session->sockfd, "ERR Usage: LOGIN <username> <password>");
                continue;
            }
            if (auth_verify_credentials(session->ctx->storage_root, username, password, role, sizeof(role)) != 0) {
                ipc_logf(&session->ctx->ipc, "LOGIN_FAIL username=%s\n", username);
                send_linef(session->sockfd, "ERR Invalid credentials");
                continue;
            }

            session->authenticated = 1;
            safe_copy(session->username, sizeof(session->username), username);
            safe_copy(session->role, sizeof(session->role), role);
            ipc_logf(&session->ctx->ipc, "LOGIN_OK username=%s role=%s\n", username, role);
            send_linef(session->sockfd, "OK Logged in as %s (%s)", username, role);
        } else if (strcmp(command, "CREATE_USER") == 0) {
            char *username = strtok_r(NULL, " ", &saveptr);
            char *password = strtok_r(NULL, " ", &saveptr);
            char *role = strtok_r(NULL, " ", &saveptr);
            handle_create_user(session, username, password, role);
        } else if (strcmp(command, "LIST") == 0) {
            handle_list(session);
        } else if (strcmp(command, "UPLOAD") == 0) {
            char *remote_name = strtok_r(NULL, " ", &saveptr);
            char *size_text = strtok_r(NULL, " ", &saveptr);
            char *key_hex = strtok_r(NULL, " ", &saveptr);
            handle_upload(session, remote_name, size_text, key_hex);
        } else if (strcmp(command, "DOWNLOAD") == 0) {
            char *file_id = strtok_r(NULL, " ", &saveptr);
            handle_download(session, file_id);
        } else if (strcmp(command, "SHARE") == 0) {
            char *file_id = strtok_r(NULL, " ", &saveptr);
            char *target_user = strtok_r(NULL, " ", &saveptr);
            handle_share(session, file_id, target_user);
        } else if (strcmp(command, "DELETE") == 0) {
            char *file_id = strtok_r(NULL, " ", &saveptr);
            handle_delete(session, file_id);
        } else if (strcmp(command, "STATS") == 0) {
            handle_stats(session);
        } else if (strcmp(command, "QUIT") == 0) {
            send_linef(session->sockfd, "OK Goodbye");
            break;
        } else {
            send_linef(session->sockfd, "ERR Unknown command");
        }
    }

    ipc_adjust_active_clients(&session->ctx->ipc, -1);
    close(session->sockfd);
    free(session);
    return NULL;
}

int server_run(ServerContext *ctx, int port) {
    struct sockaddr_in address;

    ctx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_fd < 0) {
        perror("socket");
        return -1;
    }

    {
        int opt = 1;
        setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t) port);

    if (bind(ctx->listen_fd, (struct sockaddr *) &address, sizeof(address)) != 0) {
        perror("bind");
        close(ctx->listen_fd);
        return -1;
    }
    if (listen(ctx->listen_fd, 10) != 0) {
        perror("listen");
        close(ctx->listen_fd);
        return -1;
    }

    printf("CryptoVault server listening on port %d\n", port);
    ipc_logf(&ctx->ipc, "Server listening on port %d\n", port);

    while (!*ctx->stop_flag) {
        int client_fd;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        pthread_t thread;
        ClientSession *session;

        client_fd = accept(ctx->listen_fd, (struct sockaddr *) &client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }

        session = calloc(1, sizeof(*session));
        if (session == NULL) {
            close(client_fd);
            continue;
        }

        session->sockfd = client_fd;
        session->ctx = ctx;
        safe_copy(session->role, sizeof(session->role), "guest");

        if (pthread_create(&thread, NULL, client_thread, session) != 0) {
            close(client_fd);
            free(session);
            continue;
        }
        pthread_detach(thread);
    }

    close(ctx->listen_fd);
    return 0;
}

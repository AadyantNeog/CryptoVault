#ifndef SERVER_H
#define SERVER_H

#include "server/ipc.h"

#include <signal.h>

typedef struct {
    int listen_fd;
    volatile sig_atomic_t *stop_flag;
    char storage_root[MAX_PATH_LEN];
    ServerIpc ipc;
} ServerContext;

int server_run(ServerContext *ctx, int port);

#endif

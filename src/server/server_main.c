#include "server/server.h"

#include "common/common.h"
#include "server/storage.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signum) {
    (void) signum;
    g_stop = 1;
}

int main(int argc, char **argv) {
    ServerContext ctx;
    int port = 9090;

    memset(&ctx, 0, sizeof(ctx));
    safe_copy(ctx.storage_root, sizeof(ctx.storage_root), "storage");
    ctx.stop_flag = &g_stop;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (port <= 0) {
            fprintf(stderr, "Invalid port.\n");
            return 1;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (storage_init(ctx.storage_root) != 0) {
        fprintf(stderr, "Could not initialize storage.\n");
        return 1;
    }

    if (ipc_init(&ctx.ipc, ctx.storage_root) != 0) {
        fprintf(stderr, "Could not initialize IPC resources.\n");
        return 1;
    }

    if (server_run(&ctx, port) != 0) {
        ipc_cleanup(&ctx.ipc);
        return 1;
    }

    ipc_cleanup(&ctx.ipc);
    return 0;
}

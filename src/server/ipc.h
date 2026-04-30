#ifndef IPC_H
#define IPC_H

#include "common/common.h"

#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>

typedef struct {
    int log_pipe[2];
    pid_t logger_pid;
    int shm_fd;
    char shm_name[64];
    VaultStats *stats;
    pthread_mutex_t stats_mutex;
    sem_t transfer_slots;
    char audit_log_path[MAX_PATH_LEN];
} ServerIpc;

int ipc_init(ServerIpc *ipc, const char *storage_root);
void ipc_cleanup(ServerIpc *ipc);
void ipc_log(ServerIpc *ipc, const char *message);
void ipc_logf(ServerIpc *ipc, const char *fmt, ...);
void ipc_adjust_active_clients(ServerIpc *ipc, int delta);
void ipc_increment_total_clients(ServerIpc *ipc);
void ipc_increment_uploads(ServerIpc *ipc);
void ipc_increment_downloads(ServerIpc *ipc);
void ipc_increment_commands(ServerIpc *ipc);
void ipc_format_stats(ServerIpc *ipc, char *buffer, size_t size);

#endif

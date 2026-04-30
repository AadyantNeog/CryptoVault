#include "server/ipc.h"

#include "common/common.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void logger_process(int read_fd, const char *audit_log_path) {
    FILE *log_file = fopen(audit_log_path, "a");
    char buffer[512];
    ssize_t received;

    if (log_file == NULL) {
        _exit(1);
    }

    while ((received = read(read_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[received] = '\0';
        fputs(buffer, log_file);
        fflush(log_file);
    }

    fclose(log_file);
    close(read_fd);
    _exit(0);
}

int ipc_init(ServerIpc *ipc, const char *storage_root) {
    memset(ipc, 0, sizeof(*ipc));
    ipc->log_pipe[0] = -1;
    ipc->log_pipe[1] = -1;
    ipc->shm_fd = -1;

    snprintf(ipc->audit_log_path, sizeof(ipc->audit_log_path), "%s/audit.log", storage_root);
    snprintf(ipc->shm_name, sizeof(ipc->shm_name), "/cryptovault_stats_%d", getpid());

    if (pipe(ipc->log_pipe) != 0) {
        return -1;
    }

    ipc->logger_pid = fork();
    if (ipc->logger_pid < 0) {
        return -1;
    }
    if (ipc->logger_pid == 0) {
        close(ipc->log_pipe[1]);
        logger_process(ipc->log_pipe[0], ipc->audit_log_path);
    }

    close(ipc->log_pipe[0]);
    ipc->log_pipe[0] = -1;

    ipc->shm_fd = shm_open(ipc->shm_name, O_CREAT | O_RDWR, 0600);
    if (ipc->shm_fd < 0) {
        return -1;
    }

    if (ftruncate(ipc->shm_fd, sizeof(VaultStats)) != 0) {
        return -1;
    }

    ipc->stats = mmap(NULL, sizeof(VaultStats), PROT_READ | PROT_WRITE, MAP_SHARED, ipc->shm_fd, 0);
    if (ipc->stats == MAP_FAILED) {
        ipc->stats = NULL;
        return -1;
    }
    memset(ipc->stats, 0, sizeof(VaultStats));

    pthread_mutex_init(&ipc->stats_mutex, NULL);
    sem_init(&ipc->transfer_slots, 0, 4);

    ipc_logf(ipc, "Server logger started (pid=%d)\n", (int) getpid());
    return 0;
}

void ipc_cleanup(ServerIpc *ipc) {
    if (ipc == NULL) {
        return;
    }

    ipc_log(ipc, "Server shutting down\n");

    if (ipc->log_pipe[1] >= 0) {
        close(ipc->log_pipe[1]);
        ipc->log_pipe[1] = -1;
    }

    if (ipc->logger_pid > 0) {
        waitpid(ipc->logger_pid, NULL, 0);
    }

    if (ipc->stats != NULL) {
        munmap(ipc->stats, sizeof(VaultStats));
        ipc->stats = NULL;
    }

    if (ipc->shm_fd >= 0) {
        close(ipc->shm_fd);
        shm_unlink(ipc->shm_name);
    }

    pthread_mutex_destroy(&ipc->stats_mutex);
    sem_destroy(&ipc->transfer_slots);
}

void ipc_log(ServerIpc *ipc, const char *message) {
    if (ipc == NULL || ipc->log_pipe[1] < 0 || message == NULL) {
        return;
    }
    (void) write(ipc->log_pipe[1], message, strlen(message));
}

void ipc_logf(ServerIpc *ipc, const char *fmt, ...) {
    char line[768];
    char ts[32];
    va_list args;

    current_timestamp(ts, sizeof(ts));
    snprintf(line, sizeof(line), "[%s] ", ts);

    va_start(args, fmt);
    vsnprintf(line + strlen(line), sizeof(line) - strlen(line), fmt, args);
    va_end(args);

    ipc_log(ipc, line);
}

static void increment_field(ServerIpc *ipc, int *field, int delta) {
    if (ipc == NULL || ipc->stats == NULL) {
        return;
    }

    pthread_mutex_lock(&ipc->stats_mutex);
    *field += delta;
    pthread_mutex_unlock(&ipc->stats_mutex);
}

void ipc_adjust_active_clients(ServerIpc *ipc, int delta) {
    increment_field(ipc, &ipc->stats->active_clients, delta);
}

void ipc_increment_total_clients(ServerIpc *ipc) {
    increment_field(ipc, &ipc->stats->total_clients_served, 1);
}

void ipc_increment_uploads(ServerIpc *ipc) {
    increment_field(ipc, &ipc->stats->total_uploads, 1);
}

void ipc_increment_downloads(ServerIpc *ipc) {
    increment_field(ipc, &ipc->stats->total_downloads, 1);
}

void ipc_increment_commands(ServerIpc *ipc) {
    increment_field(ipc, &ipc->stats->total_commands, 1);
}

void ipc_format_stats(ServerIpc *ipc, char *buffer, size_t size) {
    VaultStats snapshot;

    if (ipc == NULL || ipc->stats == NULL || buffer == NULL || size == 0) {
        return;
    }

    pthread_mutex_lock(&ipc->stats_mutex);
    snapshot = *ipc->stats;
    pthread_mutex_unlock(&ipc->stats_mutex);

    snprintf(buffer, size,
             "Active clients: %d\nTotal clients served: %d\nTotal uploads: %d\nTotal downloads: %d\nTotal commands: %d\n",
             snapshot.active_clients,
             snapshot.total_clients_served,
             snapshot.total_uploads,
             snapshot.total_downloads,
             snapshot.total_commands);
}

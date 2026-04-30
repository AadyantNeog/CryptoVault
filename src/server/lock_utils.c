#include "server/lock_utils.h"

#include <fcntl.h>
#include <unistd.h>

int lock_fd(int fd, short lock_type) {
    struct flock lock;

    lock.l_type = lock_type;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_pid = getpid();

    return fcntl(fd, F_SETLKW, &lock);
}

int unlock_fd(int fd) {
    struct flock lock;

    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_pid = getpid();

    return fcntl(fd, F_SETLK, &lock);
}

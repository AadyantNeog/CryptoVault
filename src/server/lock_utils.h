#ifndef LOCK_UTILS_H
#define LOCK_UTILS_H

int lock_fd(int fd, short lock_type);
int unlock_fd(int fd);

#endif

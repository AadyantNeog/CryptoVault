#include "client/client.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *host = "127.0.0.1";
    int port = 9090;

    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }

    return client_run(host, port);
}

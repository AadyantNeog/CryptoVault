#include "client/client.h"

#include "common/common.h"
#include "common/crypto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int handle_upload_command(int sockfd, char *args) {
    char *saveptr = NULL;
    char *local_path = strtok_r(args, " ", &saveptr);
    char *remote_name = strtok_r(NULL, " ", &saveptr);
    FILE *fp;
    long size;
    char response[MAX_LINE];
    char key_hex[MAX_KEY_HEX];
    unsigned char buffer[4096];
    uint64_t state = 0;

    if (local_path == NULL || remote_name == NULL) {
        printf("Usage: upload <local_path> <remote_name>\n");
        return 0;
    }

    fp = fopen(local_path, "rb");
    if (fp == NULL) {
        perror("fopen");
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (crypto_generate_key(key_hex, sizeof(key_hex)) != 0) {
        fclose(fp);
        printf("Could not generate encryption key.\n");
        return 0;
    }

    send_linef(sockfd, "UPLOAD %s %ld %s", remote_name, size, key_hex);
    if (recv_line(sockfd, response, sizeof(response)) <= 0) {
        fclose(fp);
        return -1;
    }
    printf("%s\n", response);

    if (strncmp(response, "READY", 5) != 0) {
        fclose(fp);
        return 0;
    }

    while (!feof(fp)) {
        size_t bytes = fread(buffer, 1, sizeof(buffer), fp);
        if (bytes > 0) {
            crypto_xor_stream(buffer, bytes, key_hex, &state);
            if (send_all(sockfd, buffer, bytes) != 0) {
                fclose(fp);
                return -1;
            }
        }
    }

    fclose(fp);

    if (recv_line(sockfd, response, sizeof(response)) <= 0) {
        return -1;
    }
    printf("%s\n", response);
    return 0;
}

static int handle_download_command(int sockfd, char *args) {
    char *saveptr = NULL;
    char *file_id = strtok_r(args, " ", &saveptr);
    char *output_path = strtok_r(NULL, " ", &saveptr);
    char response[MAX_LINE];
    char remote_name[256];
    long size;
    char key_hex[MAX_KEY_HEX];
    FILE *fp;
    unsigned char buffer[4096];
    uint64_t state = 0;
    long remaining;

    if (file_id == NULL || output_path == NULL) {
        printf("Usage: download <file_id> <output_path>\n");
        return 0;
    }

    send_linef(sockfd, "DOWNLOAD %s", file_id);
    if (recv_line(sockfd, response, sizeof(response)) <= 0) {
        return -1;
    }
    if (sscanf(response, "FILE %255s %ld %64s", remote_name, &size, key_hex) != 3) {
        printf("%s\n", response);
        return 0;
    }

    fp = fopen(output_path, "wb");
    if (fp == NULL) {
        perror("fopen");
        return 0;
    }

    send_linef(sockfd, "READY");
    remaining = size;
    while (remaining > 0) {
        size_t chunk = remaining > (long) sizeof(buffer) ? sizeof(buffer) : (size_t) remaining;
        if (recv_all(sockfd, buffer, chunk) != 0) {
            fclose(fp);
            return -1;
        }
        crypto_xor_stream(buffer, chunk, key_hex, &state);
        if (fwrite(buffer, 1, chunk, fp) != chunk) {
            fclose(fp);
            return -1;
        }
        remaining -= (long) chunk;
    }

    fclose(fp);

    if (recv_line(sockfd, response, sizeof(response)) <= 0) {
        return -1;
    }
    printf("%s\n", response);
    printf("Saved decrypted file to %s\n", output_path);
    return 0;
}

static int print_block_response(int sockfd, const char *end_token) {
    char line[MAX_LINE];

    while (1) {
        if (recv_line(sockfd, line, sizeof(line)) <= 0) {
            return -1;
        }
        if (strcmp(line, end_token) == 0) {
            break;
        }
        printf("%s\n", line);
    }
    return 0;
}

int client_run(const char *host, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    char input[MAX_LINE];
    char response[MAX_LINE];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((uint16_t) port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server address.\n");
        close(sockfd);
        return 1;
    }

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
        perror("connect");
        close(sockfd);
        return 1;
    }

    if (recv_line(sockfd, response, sizeof(response)) > 0) {
        printf("%s\n", response);
    }

    printf("Type 'help' to see commands.\n");
    while (1) {
        char raw_copy[MAX_LINE];
        char *saveptr = NULL;
        char *command;

        printf("vault> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        trim_newline(input);
        if (input[0] == '\0') {
            continue;
        }

        safe_copy(raw_copy, sizeof(raw_copy), input);
        command = strtok_r(raw_copy, " ", &saveptr);
        if (command == NULL) {
            continue;
        }

        if (strcmp(command, "help") == 0) {
            printf("login <username> <password>\n");
            printf("create-user <username> <password> <role>\n");
            printf("list\n");
            printf("upload <local_path> <remote_name>\n");
            printf("download <file_id> <output_path>\n");
            printf("share <file_id> <username>\n");
            printf("delete <file_id>\n");
            printf("stats\n");
            printf("quit\n");
        } else if (strcmp(command, "upload") == 0) {
            if (handle_upload_command(sockfd, input + strlen("upload")) != 0) {
                break;
            }
        } else if (strcmp(command, "download") == 0) {
            if (handle_download_command(sockfd, input + strlen("download")) != 0) {
                break;
            }
        } else if (strcmp(command, "list") == 0) {
            send_linef(sockfd, "LIST");
            if (recv_line(sockfd, response, sizeof(response)) <= 0) {
                break;
            }
            if (strcmp(response, "LIST_BEGIN") == 0) {
                if (print_block_response(sockfd, "LIST_END") != 0) {
                    break;
                }
            } else {
                printf("%s\n", response);
            }
        } else if (strcmp(command, "stats") == 0) {
            send_linef(sockfd, "STATS");
            if (recv_line(sockfd, response, sizeof(response)) <= 0) {
                break;
            }
            if (strcmp(response, "STATS_BEGIN") == 0) {
                if (print_block_response(sockfd, "STATS_END") != 0) {
                    break;
                }
            } else {
                printf("%s\n", response);
            }
        } else if (strcmp(command, "create-user") == 0) {
            char *args = input + strlen("create-user");
            while (*args == ' ') {
                args++;
            }
            send_linef(sockfd, "CREATE_USER %s", args);
            if (recv_line(sockfd, response, sizeof(response)) <= 0) {
                break;
            }
            printf("%s\n", response);
        } else if (strcmp(command, "login") == 0) {
            char *args = input + strlen("login");
            while (*args == ' ') {
                args++;
            }
            send_linef(sockfd, "LOGIN %s", args);
            if (recv_line(sockfd, response, sizeof(response)) <= 0) {
                break;
            }
            printf("%s\n", response);
        } else if (strcmp(command, "share") == 0) {
            char *args = input + strlen("share");
            while (*args == ' ') {
                args++;
            }
            send_linef(sockfd, "SHARE %s", args);
            if (recv_line(sockfd, response, sizeof(response)) <= 0) {
                break;
            }
            printf("%s\n", response);
        } else if (strcmp(command, "delete") == 0) {
            char *args = input + strlen("delete");
            while (*args == ' ') {
                args++;
            }
            send_linef(sockfd, "DELETE %s", args);
            if (recv_line(sockfd, response, sizeof(response)) <= 0) {
                break;
            }
            printf("%s\n", response);
        } else if (strcmp(command, "quit") == 0) {
            send_linef(sockfd, "QUIT");
            if (recv_line(sockfd, response, sizeof(response)) > 0) {
                printf("%s\n", response);
            }
            break;
        } else {
            printf("Unknown client command.\n");
        }
    }

    close(sockfd);
    return 0;
}

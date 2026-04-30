CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -D_POSIX_C_SOURCE=200809L -pthread -I./src
LDFLAGS = -pthread

COMMON_SRCS = src/common/common.c src/common/crypto.c
SERVER_SRCS = src/server/server_main.c src/server/server.c src/server/auth.c src/server/storage.c src/server/lock_utils.c src/server/ipc.c
CLIENT_SRCS = src/client/client_main.c src/client/client.c

SERVER_BIN = build/vault_server
CLIENT_BIN = build/vault_client
BUILD_DIR = build

.PHONY: all clean

all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(COMMON_SRCS) $(SERVER_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(COMMON_SRCS) $(SERVER_SRCS) $(LDFLAGS)

$(CLIENT_BIN): $(COMMON_SRCS) $(CLIENT_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(COMMON_SRCS) $(CLIENT_SRCS) $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

# CryptoVault: Features, Design, and Usage

## Overview

CryptoVault is a Linux-based Operating Systems mini project written in C. It implements a multi-user encrypted vault using a TCP client-server architecture. The system is built to visibly demonstrate all mandatory OS lab requirements:

- role-based authorization
- file locking
- concurrency control
- data consistency
- socket programming
- inter-process communication


## Main Features

- Multi-client TCP server using POSIX sockets
- Role-based access control with `admin`, `user`, and `guest`
- File upload, download, listing, sharing, and deletion
- Encrypted file storage using a client-side stream cipher before upload
- Advisory file locking using `fcntl()` on metadata files
- Thread-per-client concurrency with `pthread`
- POSIX semaphore limiting simultaneous uploads/downloads
- Shared memory statistics using `shm_open()` + `mmap()`
- Pipe-based logger process for audit logging
- Signal-based graceful shutdown on `SIGINT` / `SIGTERM`
- Flat-file persistent storage.

## Important Note About Encryption

This project uses a self-contained educational stream cipher implemented in pure C so that the full project can compile in a standard Linux lab environment without external crypto libraries.

- The client encrypts file contents before upload.
- The server stores only encrypted blobs.
- The client decrypts files after download.

## Project Structure

```text
CryptoVault/
├── Makefile
├── docs/
│   └── FEATURES_AND_USAGE.md
├── src/
│   ├── client/
│   │   ├── client.c
│   │   ├── client.h
│   │   └── client_main.c
│   ├── common/
│   │   ├── common.c
│   │   ├── common.h
│   │   ├── crypto.c
│   │   └── crypto.h
│   └── server/
│       ├── auth.c
│       ├── auth.h
│       ├── ipc.c
│       ├── ipc.h
│       ├── lock_utils.c
│       ├── lock_utils.h
│       ├── server.c
│       ├── server.h
│       ├── server_main.c
│       ├── storage.c
│       └── storage.h
└── storage/
    └── blobs/
```

## Mapping to OS Lab Requirements

### 1. Role-Based Authorization

Implemented in:

- `src/server/auth.c`
- `src/server/server.c`

How it works:

- Users are stored in `storage/users.db`.
- Each user has a role: `admin`, `user`, or `guest`.
- Every sensitive server command checks the session role before proceeding.

Permissions:

- `admin`
  - create users
  - access all files
  - view server statistics
  - delete any file
- `user`
  - upload own files
  - download own/shared files
  - share owned files
  - delete own files
- `guest`
  - view/download only shared files
  - cannot upload or share

### 2. File Locking

Implemented in:

- `src/server/lock_utils.c`
- `src/server/storage.c`
- `src/server/auth.c`

How it works:

- `fcntl()` advisory locks are applied to metadata files.
- Read locks are used while listing or reading metadata.
- Write locks are used while appending or rewriting metadata files.

This prevents corruption when multiple clients access shared metadata concurrently.

### 3. Concurrency Control

Implemented in:

- `src/server/server.c`
- `src/server/ipc.c`

How it works:

- The server accepts multiple clients simultaneously.
- Each client is handled in its own thread using `pthread_create()`.
- Shared counters are protected with a mutex.
- A POSIX semaphore limits simultaneous transfer operations to avoid uncontrolled resource usage.

### 4. Data Consistency

Implemented in:

- `src/server/storage.c`

How it works:

- File metadata is updated under write locks.
- Complex updates like sharing/deletion rewrite `files.db` through a temporary file and atomic `rename()`.
- This reduces the chance of lost updates or corrupted metadata when multiple threads act together.

### 5. Socket Programming

Implemented in:

- `src/server/server.c`
- `src/client/client.c`

How it works:

- The server uses TCP sockets with `socket()`, `bind()`, `listen()`, and `accept()`.
- The client uses `socket()` and `connect()`.
- Commands and responses are sent over the network using a line-based protocol, while uploaded/downloaded file data is streamed as binary.

### 6. Inter-Process Communication

Implemented in:

- `src/server/ipc.c`
- `src/server/server_main.c`

IPC mechanisms used:

- `pipe()`
  - the main server sends audit messages to a logger child process
- shared memory using `shm_open()` and `mmap()`
  - stores runtime server statistics
- signals
  - `SIGINT` and `SIGTERM` trigger graceful shutdown

## Storage Files

Runtime data lives under `storage/`:

- `storage/users.db`
  - user records in the format `username|role|password_hash`
- `storage/files.db`
  - file metadata records
- `storage/blobs/`
  - encrypted file contents
- `storage/audit.log`
  - audit log written by the logger child process

## Default Accounts

These are created automatically on first run:

- `admin / admin123`
- `alice / alice123`
- `guest / guest123`
- `ben / ben123`

Change these in `src/server/auth.c` if you want different demo credentials.

## Build Instructions

From the project root:

```bash
make
```

This builds:

- `build/vault_server`
- `build/vault_client`

To clean:

```bash
make clean
```

## How To Run

### 1. Start the server

```bash
./build/vault_server
```

Or choose a custom port:

```bash
./build/vault_server 9091
```

### 2. Start one or more clients

In another terminal:

```bash
./build/vault_client
```

Or for a custom host/port:

```bash
./build/vault_client 127.0.0.1 9091
```

## Client Commands

Inside the client prompt:

```text
login <username> <password>
create-user <username> <password> <role>
list
upload <local_path> <remote_name>
download <file_id> <output_path>
share <file_id> <username>
delete <file_id>
stats
quit
```

## Known Simplifications

- The transport channel is plain TCP, not TLS.
- The encryption module is educational and self-contained.
- Logical remote file names should not contain spaces.
- Password hashing is simplified for lab use.

These choices keep the focus on Operating Systems concepts while still delivering a realistic secure storage workflow.

/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the Mixnet course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the Mixnet project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#ifndef HARNESS_NETWORKING_H
#define HARNESS_NETWORKING_H

#include "error.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Per-connection state.
 */
struct harness_accepted_state {
    int connection_fd;                      // FD of the new connection
    socklen_t addrlen;                      // Size of the address field
    struct sockaddr_in address;             // Address of the new client
};

struct harness_accept_args {
    int *rc;                                // Return code (0 on success)
    int listen_fd;                          // FD of socket to listen on
    bool use_timeout;                       // Use the timeout mechanism
    volatile bool done;                     // Accept routine terminated
    uint16_t max_clients;                   // Expected number of clients
    volatile bool started;                  // Accept routine initialized
    uint16_t *num_accepted;                 // Number of accepted clients
    unsigned int timeout_ms;                // Accept timeout (milliseconds)
    volatile bool keep_running;             // ITC synchronization variable
    struct harness_accepted_state *states;  // New clients' connection state
};

/**
 * Collection of networking-related helper functions.
 */
int harness_socket(const bool reuse_addr);

test_error_code_t harness_server_setup(int *socket_fd,
    struct sockaddr_in *addr, const int listen_queue,
    const bool reuse_addr);

void *harness_accept(void *args);
void harness_accept_with_timeout(
    const int listen_fd, const unsigned int timeout_ms,
    const uint16_t max_clients, uint16_t *num_accepted,
    struct harness_accepted_state *states, int *rc);

int harness_connect_with_timeout(
    const int socket_fd, const struct sockaddr_in *address,
    const socklen_t addrlen, const unsigned int timeout_ms);

test_error_code_t harness_send_with_timeout(
    const int socket_fd, const uint32_t timeout_ms,
    const void *buffer, const size_t buffer_length);

test_error_code_t harness_recv_with_timeout(
    const int socket_fd, const uint32_t timeout_ms,
    void *recv_buffer, const size_t buffer_length,
    const uint16_t session_nonce);

bool harness_equal_netaddrs(const struct sockaddr_in addr_a,
                            const struct sockaddr_in addr_b);

#ifdef __cplusplus
}
#endif

#endif // HARNESS_NETWORKING_H

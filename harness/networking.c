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
#include "networking.h"

#include "message.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/sctp.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * Initializes a non-blocking SCTP socket.
 */
int harness_socket(const bool reuse_addr) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (socket_fd == -1) { return -1; }
    bool success = true;

    // Configure the socket to be non-blocking
    const int flags = fcntl(socket_fd, F_GETFL, 0);
    success &= (flags >= 0); // Fetch the currently-set flags
    success &= (fcntl(socket_fd, F_SETFL, (flags | O_NONBLOCK)) >= 0);

    // Reuse address if required
    if (reuse_addr) {
        const int reuse = 1;
        success &= (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR,
                               &reuse, sizeof(int)) != -1);
    }
    // 1:1 single-stream SCTP
    struct sctp_initmsg initmsg;
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_max_attempts = 3;
    initmsg.sinit_num_ostreams = 1;
    initmsg.sinit_max_instreams = 1;
    success &= (setsockopt(socket_fd, SOL_SCTP, SCTP_INITMSG,
                           &initmsg, sizeof(initmsg)) != -1);

    // Use heartbeats
    struct sctp_paddrparams paddrparams;
    memset(&paddrparams, 0, sizeof(paddrparams));
    paddrparams.spp_flags = SPP_HB_ENABLE;
    paddrparams.spp_hbinterval = 5000;
    success &= (setsockopt(socket_fd, SOL_SCTP, SCTP_PEER_ADDR_PARAMS,
                           &paddrparams, sizeof(paddrparams)) != -1);

    // TODO(natre): Enable UDP encapsulation
    if (!success) { close(socket_fd); }
    return success ? socket_fd : -1;
}

/**
 * Performs standard server setup (socket, bind, listen).
 */
test_error_code_t harness_server_setup(int *socket_fd,
    struct sockaddr_in *addr, const int listen_queue,
    const bool reuse_addr) {
    bool success = true;

    // No clients, nothing to do
    if (listen_queue == 0) { return TEST_ERROR_NONE; }

    // First, set up a socket to listen for connections
    success &= (*socket_fd = harness_socket(reuse_addr)) > 0;
    if (!success) { return TEST_ERROR_SOCKET_CREATE_FAILED; }

    // Bind to port
    success &= (bind(*socket_fd, (struct sockaddr *)
                addr, sizeof(struct sockaddr)) != -1);
    if (!success) { return TEST_ERROR_SOCKET_BIND_FAILED; }

    // If binding to arbitrary port, also update addr
    if (addr->sin_port == 0) {
        socklen_t addrlen = sizeof(struct sockaddr);
        success &= (getsockname(*socket_fd,
                    (struct sockaddr *) addr, &addrlen) != -1);
    }
    // Prepare to listen for connection attempts
    success &= (listen(*socket_fd, listen_queue) != -1);
    if (!success) { return TEST_ERROR_SOCKET_LISTEN_FAILED; }

    return TEST_ERROR_NONE;
}

/**
 * Low-level, threadable server-side accept functionality. Attempts to accept
 * a certain number of client connections (max_clients) while a condition var
 * (keep_running) remains true. Returns (by reference) the accepted number of
 * clients, local socket fds, and their net addresses. Returns -1 on error
 * (check errno).
 */
void *harness_accept(void *harness_accept_args) {
    struct harness_accept_args *args = (
        (struct harness_accept_args*) harness_accept_args);

    *(args->rc) = 0;
    *(args->num_accepted) = 0;
    assert(!args->started && args->keep_running && !args->done);

    // Set up the timer
    struct timespec now;
    if (!args->use_timeout) { args->timeout_ms = 0; }
    else if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) { *(args->rc) = -1; }

    struct timespec deadline = {
        .tv_sec = now.tv_sec,
        .tv_nsec = now.tv_nsec + (args->timeout_ms * 1000000l)
    };

    args->started = true;
    while ((*(args->num_accepted) < args->max_clients) &&
           (*(args->rc) == 0) && args->keep_running) {
        if (args->use_timeout) {
            // Get time and compute time until the deadline
            if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
                *(args->rc) = -1;
            }
            int ms_until_deadline = (int) (
                (deadline.tv_sec - now.tv_sec) * 1000l +
                (deadline.tv_nsec - now.tv_nsec) / 1000000l);

            // Exhausted the timeout for connect
            if (ms_until_deadline < 0) { break; }
        }
        // Accept incoming requests
        struct harness_accepted_state *state = &(
            args->states[*(args->num_accepted)]);

        state->addrlen = sizeof(struct sockaddr_in);
        int retval = accept(args->listen_fd,
                            (struct sockaddr *) &(state->address),
                            &(state->addrlen));
        if (retval < 0) {
            // Accept encountered a real error
            if ((errno != EWOULDBLOCK) && (errno != EAGAIN)) {
                *(args->rc) = -1; }
        }
        else {
            // Update the conn_fds array and repeat
            state->connection_fd = retval;
            *(args->num_accepted) += 1;

            // Configure the socket to be non-blocking
            const int flags = fcntl(retval, F_GETFL, 0);
            bool success = (flags >= 0 && fcntl(retval, F_SETFL,
                                (flags | O_NONBLOCK)) >= 0);

            if (!success) { *(args->rc) = -1; }
        }
    }
    args->done = true;
    return NULL;
}

/**
 * Server-side accept with timeout.
 */
void harness_accept_with_timeout(
    const int listen_fd, const unsigned int timeout_ms,
    const uint16_t max_clients, uint16_t *num_accepted,
    struct harness_accepted_state *states, int *rc) {
    // Allocate and initialize arguments
    struct harness_accept_args args = {
        .rc = rc,
        .done = false,
        .states = states,
        .started = false,
        .use_timeout = true,
        .keep_running = true,
        .listen_fd = listen_fd,
        .timeout_ms = timeout_ms,
        .max_clients = max_clients,
        .num_accepted = num_accepted,
    };

    // Invoke the helper function
    harness_accept(&args);
}

/**
 * Client-side connect functionality with timeout and retry. Adapted from:
 * https://stackoverflow.com/questions/2597608/c-socket-connection-timeout.
 * Return 0 on success, -1 for errors.
 */
int harness_connect_with_timeout(
    const int socket_fd, const struct sockaddr_in *address,
    const socklen_t addrlen, const unsigned int timeout_ms) {
    int rc = -1; // Return value
    do {
        if ((rc = connect(socket_fd, (struct sockaddr *)
                          address, addrlen)) < 0) {
            // If connect encountered a real error, this try failed
            if ((errno != EWOULDBLOCK) && (errno != EINPROGRESS)) {
                rc = -1; break;
            }
            // Connection attempt is still in progress
            else {
                struct timespec now;
                if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
                    rc = -1; break;
                }
                struct timespec deadline = {
                    .tv_sec = now.tv_sec,
                    .tv_nsec = now.tv_nsec + (timeout_ms * 1000000l)
                };
                do {
                    // Calculate how long until the deadline
                    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
                        rc = -1; break;
                    }
                    int ms_until_deadline = (int) (
                        (deadline.tv_sec - now.tv_sec) * 1000l +
                        (deadline.tv_nsec - now.tv_nsec) / 1000000l);

                    // Exhausted the timeout for connect
                    if (ms_until_deadline < 0) { rc = 0; break; }

                    // Set up polling on this fd
                    struct pollfd pfds[] = {
                        { .fd = socket_fd, .events = POLLOUT } };
                    rc = poll(pfds, 1, ms_until_deadline);

                    // If poll 'succeeded', make sure it *really* succeeded
                    if(rc > 0) {
                        int error = 0; socklen_t len = sizeof(error);
                        int retval = getsockopt(socket_fd, SOL_SOCKET,
                                                SO_ERROR, &error, &len);

                        if (retval == 0) { errno = error; }
                        if (error != 0) { rc = -1; }
                    }
                }
                // Poll was interrupted, retry
                while((rc == -1) && (errno == EINTR));

                // Did poll timeout? If so, this try failed
                if(rc == 0) { errno = ETIMEDOUT; rc = -1; }
            }
        }
    } while (0);
    return (rc > 0) ? 0 : -1;
}

/**
 * Send an SCTP message with the given timeout.
 */
test_error_code_t harness_send_with_timeout(
    const int socket_fd, const uint32_t timeout_ms,
    const void *buffer, const size_t buffer_length) {
    int ms_until_deadline = timeout_ms;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return TEST_ERROR_FRAGMENT_EXCEPTION;
    }
    struct timespec deadline = {
        .tv_sec = now.tv_sec,
        .tv_nsec = now.tv_nsec + (timeout_ms * 1000000l)
    };
    do {
        // Attempt to send the message
        int rc = sctp_sendmsg(socket_fd,
                              buffer, buffer_length,
                              NULL, 0, 0, 0, 0, 0, 0);
        if (rc < 0) {
            if ((errno != EAGAIN) && (errno != ENOBUFS)) {
                return TEST_ERROR_CTRL_CONNECTION_BROKEN;
            }
        }
        else if (rc != (int) buffer_length) {
            // SCTP transmission is non-atomic
            return TEST_ERROR_SCTP_PARTIAL_DATA;
        }
        // Successful transmission
        else { return TEST_ERROR_NONE; }

        // Calculate time until the deadline
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
            return TEST_ERROR_FRAGMENT_EXCEPTION;
        }
        ms_until_deadline = (int) (
            (deadline.tv_sec - now.tv_sec) * 1000l +
            (deadline.tv_nsec - now.tv_nsec) / 1000000l);
    }
    while (ms_until_deadline > 0);
    return TEST_ERROR_SEND_REQS_TIMEOUT;
}

/**
 * Receive an SCTP message with the given timeout.
 */
test_error_code_t harness_recv_with_timeout(
    const int socket_fd, const uint32_t timeout_ms,
    void *recv_buffer, const size_t buffer_length,
    const uint16_t session_nonce) {
    int ms_until_deadline = timeout_ms;
    struct test_message_header *header = (
        (struct test_message_header*) recv_buffer);

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return TEST_ERROR_FRAGMENT_EXCEPTION;
    }
    struct timespec deadline = {
        .tv_sec = now.tv_sec,
        .tv_nsec = now.tv_nsec + (timeout_ms * 1000000l)
    };
    do {
        // Attempt to receive the message
        int flags = 0;
        int rc = sctp_recvmsg(socket_fd, recv_buffer,
                              buffer_length, NULL, 0,
                              NULL, &flags);
        if (rc < 0) {
            if ((errno != EAGAIN) && (errno != ENOBUFS)) {
                return TEST_ERROR_CTRL_CONNECTION_BROKEN;
            }
        }
        else if (rc == 0) {
            return TEST_ERROR_CTRL_CONNECTION_BROKEN;
        }
        else if (rc != (int) buffer_length) {
            // SCTP transmission is non-atomic
            return TEST_ERROR_SCTP_PARTIAL_DATA;
        }
        // If the nonce is correct, return the message buffer
        // Else, simply ignore the message (mismatched nonce).
        else if (header->session_nonce == session_nonce) {
            return TEST_ERROR_NONE;
        }

        // Calculate time until the deadline
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
            return TEST_ERROR_FRAGMENT_EXCEPTION;
        }
        ms_until_deadline = (int) (
            (deadline.tv_sec - now.tv_sec) * 1000l +
            (deadline.tv_nsec - now.tv_nsec) / 1000000l);
    }
    while (ms_until_deadline > 0);
    return TEST_ERROR_RECV_WAIT_TIMEOUT;
}

/**
 * Returns whether two network addresses are identical.
 */
bool harness_equal_netaddrs(const struct sockaddr_in addr_a,
                            const struct sockaddr_in addr_b) {
    return ((addr_a.sin_port == addr_b.sin_port) &&
            (addr_a.sin_family == addr_b.sin_family) &&
            (addr_a.sin_addr.s_addr == addr_b.sin_addr.s_addr));
}

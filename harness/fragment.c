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
#include "fragment.h"

#include "message.h"
#include "networking.h"
#include "mixnet/node.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/sctp.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Constant parameters
static const int FRAGMENT_MQ_PCAP_DEPTH = 128;
static const int FRAGMENT_MQ_APP_PACKETS_DEPTH = 128;
static const uint32_t DEFAULT_FRAGMENT_TIMEOUT_MS = 2000;

uint16_t fragment_next_port_idx(
    const uint16_t idx, const uint16_t num_neighbors) {
    const uint16_t max_port_id = num_neighbors;
    return (idx == max_port_id) ? 0 : idx + 1;
}

void initialize_fragment_thread_state(
    struct fragment_thread_state *state) {
    state->tid = 0;
    state->exited = false;
    state->started = false;
    state->keep_running = true;
    state->error_code = TEST_ERROR_NONE;
}

struct fragment_context
*fragment_context_create(const uint16_t nonce,
                         const int autotest_mode,
                         const uint16_t fragment_id,
                         const uint32_t connect_timeout,
                         const uint32_t communication_timeout,
                         const struct sockaddr_in orc_netaddr) {

    // Allocate a new fragment context
    struct fragment_context *ctx = (
        malloc(sizeof(struct fragment_context)));

    if (ctx == NULL) { return NULL; }
    struct mixnet_context *subctx = &(ctx->mixnet_ctx);
    struct mixnet_node_config *config = &(subctx->config);

    // Node configuration
    config->num_neighbors = 0;
    config->neighbor_addrs = NULL;

    // Mixnet subcontext
    subctx->tx_listen_fd = -1;
    subctx->link_states = NULL;
    subctx->port_mutexes = NULL;
    subctx->rx_socket_fds = NULL;
    subctx->tx_socket_fds = NULL;
    subctx->packet_buffer = NULL;
    subctx->neighbor_netaddrs = NULL;
    memset(&(subctx->tx_server_netaddr), 0,
           sizeof(subctx->tx_server_netaddr));

    // Network configuration
    ctx->nonce = nonce;
    ctx->fragment_id = fragment_id;
    ctx->orc_netaddr = orc_netaddr;
    ctx->autotest_mode = autotest_mode;
    ctx->connect_timeout = connect_timeout;
    ctx->communication_timeout = communication_timeout;

    // Default initialization
    ctx->local_fd_ctrl = -1;
    ctx->local_fd_pcap = -1;

    ctx->ctrl_message_buffer = malloc(MAX_TEST_MESSAGE_SIZE);
    if (ctx->ctrl_message_buffer == NULL) { free(ctx); return NULL; }

    ctx->pcap_message_buffer = malloc(MAX_TEST_MESSAGE_SIZE);
    if (ctx->pcap_message_buffer == NULL) {
        free(ctx->ctrl_message_buffer);
        free(ctx); return NULL;
    }

    // Initialize message queues
    if (message_queue_init(&(ctx->mq_pcap), sizeof(void*),
                           FRAGMENT_MQ_PCAP_DEPTH) != 0) {
        free(ctx->pcap_message_buffer);
        free(ctx->ctrl_message_buffer);
        free(ctx); return NULL;
    }
    if (message_queue_init(&(ctx->mq_app_packets),
                           MAX_MIXNET_PACKET_SIZE,
                           FRAGMENT_MQ_APP_PACKETS_DEPTH) != 0) {
        message_queue_destroy(&(ctx->mq_pcap));
        free(ctx->pcap_message_buffer);
        free(ctx->ctrl_message_buffer);
        free(ctx); return NULL;
    }

    // Initialize fragment thread states
    initialize_fragment_thread_state(&(ctx->ts_node));
    initialize_fragment_thread_state(&(ctx->ts_pcap));
    return ctx;
}

bool fragment_mixnet_init(struct fragment_context *ctx,
                          const struct mixnet_node_config c) {
    if (ctx == NULL) { return false; }
    bool success = true; // Return value
    struct mixnet_context *subctx = &(ctx->mixnet_ctx);
    struct mixnet_node_config *config = &(subctx->config);

    success &= ((subctx->packet_buffer =
        malloc(MAX_MIXNET_PACKET_SIZE)) != NULL);

    *config = c;
    subctx->next_port_idx = 0;
    subctx->is_pcap_subscribed = false;
    config->neighbor_addrs = NULL; // Stale pointer
    if (config->num_neighbors == 0) { return success; }

    if (success &= ((config->neighbor_addrs =
            malloc(sizeof(mixnet_address) * c.num_neighbors)) != NULL)) {
        for (uint16_t nid = 0; nid < c.num_neighbors; nid++) {
            config->neighbor_addrs[nid] = c.neighbor_addrs[nid];
        }
    }
    if (success &= ((subctx->port_mutexes =
            malloc(sizeof(pthread_mutex_t) * c.num_neighbors)) != NULL)) {
        for (uint16_t nid = 0; nid < c.num_neighbors; nid++) {
            pthread_mutex_init(&(subctx->port_mutexes[nid]), NULL);
        }
    }
    if (success &= ((subctx->tx_socket_fds =
            malloc(sizeof(int) * c.num_neighbors)) != NULL)) {
        for (uint16_t nid = 0; nid < c.num_neighbors; nid++) {
            subctx->tx_socket_fds[nid] = -1;
        }
    }
    if (success &= ((subctx->rx_socket_fds =
            malloc(sizeof(int) * c.num_neighbors)) != NULL)) {
        for (uint16_t nid = 0; nid < c.num_neighbors; nid++) {
            subctx->rx_socket_fds[nid] = -1;
        }
    }
    success &= (subctx->neighbor_netaddrs = calloc(
            c.num_neighbors, sizeof(struct sockaddr_in))) != NULL;

    if (success &= (subctx->link_states =
            malloc(sizeof(bool) * c.num_neighbors)) != NULL) {
        for (uint16_t nid = 0; nid < c.num_neighbors; nid++) {
            // By default, all Mixnet links are enabled
            subctx->link_states[nid] = true;
        }
    }
    return success;
}

void fragment_context_destroy(
    struct fragment_context *ctx) {
    if (ctx == NULL) { return; } // Safe handling

    free(ctx->ctrl_message_buffer);
    free(ctx->pcap_message_buffer);
    message_queue_destroy(&(ctx->mq_pcap));
    message_queue_destroy(&(ctx->mq_app_packets));
    struct mixnet_context *subctx = &(ctx->mixnet_ctx);
    struct mixnet_node_config *config = &(subctx->config);

    // Deallocate node configuration
    free(config->neighbor_addrs);

    // Close local TX sockets to neighbors
    uint16_t num_neighbors = config->num_neighbors;
    if (subctx->tx_socket_fds != NULL) {
        for (uint16_t nid = 0; nid < num_neighbors; nid++) {
            if (subctx->tx_socket_fds[nid] != -1) {
                close(subctx->tx_socket_fds[nid]);
            }
        }
        free(subctx->tx_socket_fds);
    }
    // Close listening socket
    if (subctx->tx_listen_fd != -1) {
        close(subctx->tx_listen_fd);
    }
    // Close local RX sockets to neighbors
    if (subctx->rx_socket_fds != NULL) {
        for (uint16_t nid = 0; nid < num_neighbors; nid++) {
            if (subctx->rx_socket_fds[nid] != -1) {
                close(subctx->rx_socket_fds[nid]);
            }
        }
        free(subctx->rx_socket_fds);
    }
    // Destroy and deallocate mutexes
    if (subctx->port_mutexes != NULL) {
        for (uint16_t nid = 0; nid < num_neighbors; nid++) {
            pthread_mutex_destroy(&(subctx->port_mutexes[nid]));
        }
        free(subctx->port_mutexes);
    }
    free(subctx->neighbor_netaddrs);
    free(subctx->packet_buffer);
    free(subctx->link_states);

    // Close local pcap, ctrl sockets
    if (ctx->local_fd_pcap != -1) {
        close(ctx->local_fd_pcap);
    }
    if (ctx->local_fd_ctrl != -1) {
        close(ctx->local_fd_ctrl);
    }
    free(ctx);
}

/**
 * Helper functions to send/recv data.
 */
 void fragment_prepare_message_header(
    struct fragment_context *ctx,
    void *buffer, const test_error_code_t error,
    const enum test_message_type_enum message_type) {
    // Populate the message header
    struct test_message_header *header = (
        (struct test_message_header*) buffer);

    header->error_code = error;
    header->session_nonce = ctx->nonce;
    header->fragment_id = ctx->fragment_id;
    header->message_code = message_code_create(false, message_type);
}

test_error_code_t fragment_check_message_header(
    struct fragment_context *ctx, void *buffer,
    const bool check_message_type, const enum
    test_message_type_enum message_type) {
    // Validate the fragment ID and message type
    struct test_message_header *header = (
        (struct test_message_header*) buffer);

    uint16_t recv_code = header->message_code;
    const test_message_type_t recv_type = (
        message_code_to_type(recv_code));

    // ID doesn't match the fragment
    if (header->fragment_id != ctx->fragment_id) {
        return TEST_ERROR_BAD_FRAGMENT_ID;
    }
    // Incorrect message direction
    if (!message_code_is_request(recv_code)) {
        return TEST_ERROR_BAD_MESSAGE_CODE;
    }
    // Received unexpected message code
    if (check_message_type && (message_type != recv_type)) {
        return ((recv_type == TEST_MESSAGE_SHUTDOWN) ?
                TEST_ERROR_FRAGMENT_SHUTDOWN_REQ :
                TEST_ERROR_BAD_MESSAGE_CODE);
    }
    // Orchestrator reported a test error
    if (header->error_code != TEST_ERROR_NONE) {
        return TEST_ERROR_FRAGMENT_EXCEPTION;
    }
    return TEST_ERROR_NONE;
}

/**
 * Fragment FSM functionality.
 */
test_error_code_t
fragment_run_state_setup_ctrl(struct fragment_context *ctx) {
    // First, set up a socket to communicate on the ctrl overlay
    if ((ctx->local_fd_ctrl = harness_socket(false)) < 0) {
        return TEST_ERROR_SOCKET_CREATE_FAILED;
    }
    // Attempt to connect to the orchestrator
    if (harness_connect_with_timeout(ctx->local_fd_ctrl,
        &(ctx->orc_netaddr), sizeof(ctx->orc_netaddr),
        ctx->connect_timeout) < 0) {
        return TEST_ERROR_SOCKET_CONNECT_FAILED;
    }
    // Connected, initiate handshake
    void *buffer = ctx->ctrl_message_buffer;
    memset(buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, buffer, TEST_ERROR_NONE,
                                    TEST_MESSAGE_SETUP_CTRL);
    // Prepare the message payload
    struct test_response_setup_overlay *payload = (
        (struct test_response_setup_overlay*) (
            ctx->ctrl_message_buffer +
            sizeof(struct test_message_header))
    );
    payload->fragment_id = ctx->fragment_id;

    test_error_code_t error_code = harness_send_with_timeout(
        ctx->local_fd_ctrl, ctx->connect_timeout,
        buffer, MAX_TEST_MESSAGE_SIZE);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    // Complete handshake
    error_code = harness_recv_with_timeout(
        ctx->local_fd_ctrl, ctx->connect_timeout,
        buffer, MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    return fragment_check_message_header(
        ctx, buffer, true, TEST_MESSAGE_SETUP_CTRL);
}

test_error_code_t
fragment_run_state_setup_pcap(struct fragment_context *ctx) {
    test_error_code_t error_code = TEST_ERROR_NONE;

    // Wait for a ctrl message to start setup
    error_code = harness_recv_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    error_code = fragment_check_message_header(ctx, ctx->ctrl_message_buffer,
                                               true, TEST_MESSAGE_SETUP_PCAP);
    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }

    // Parse the message payload
    struct sockaddr_in pcap_netaddr;
    {
    struct test_request_setup_pcap *payload = (
        (struct test_request_setup_pcap*) (
            ctx->ctrl_message_buffer +
            sizeof(struct test_message_header))
    );
    pcap_netaddr = payload->pcap_netaddr;
    pcap_netaddr.sin_addr.s_addr = ctx->orc_netaddr.sin_addr.s_addr;
    }
    // Acknowledge pcap overlay setup
    memset(ctx->ctrl_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, ctx->ctrl_message_buffer,
                                    TEST_ERROR_NONE, TEST_MESSAGE_SETUP_PCAP);

    error_code = harness_send_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE);
    if (error_code != TEST_ERROR_NONE) { return error_code; }

    // Next, set up a socket to communicate on the pcap overlay
    if ((ctx->local_fd_pcap = harness_socket(false)) < 0) {
        return TEST_ERROR_SOCKET_CREATE_FAILED;
    }
    // Attempt to connect to the orchestrator
    if (harness_connect_with_timeout(ctx->local_fd_pcap,
        &pcap_netaddr, sizeof(pcap_netaddr),
        ctx->communication_timeout) < 0) {
        return TEST_ERROR_SOCKET_CONNECT_FAILED;
    }
    // Connected, initiate handshake
    memset(ctx->pcap_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, ctx->pcap_message_buffer,
                                    TEST_ERROR_NONE, TEST_MESSAGE_SETUP_PCAP);
    // Prepare the message payload
    {
    struct test_response_setup_overlay *payload = (
        (struct test_response_setup_overlay*) (
            ctx->pcap_message_buffer +
            sizeof(struct test_message_header))
    );
    payload->fragment_id = ctx->fragment_id;
    }

    error_code = harness_send_with_timeout(
        ctx->local_fd_pcap, ctx->communication_timeout,
        ctx->pcap_message_buffer, MAX_TEST_MESSAGE_SIZE);
    if (error_code != TEST_ERROR_NONE) { return error_code; }

    // Complete handshake
    error_code = harness_recv_with_timeout(
        ctx->local_fd_pcap, ctx->communication_timeout,
        ctx->pcap_message_buffer, MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    return fragment_check_message_header(ctx, ctx->pcap_message_buffer,
                                         true, TEST_MESSAGE_SETUP_PCAP);
}

test_error_code_t
fragment_run_state_create_topology(struct fragment_context *ctx) {
    test_error_code_t error_code = TEST_ERROR_NONE;

    // Wait for the corresponding ctrl message
    error_code = harness_recv_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    error_code = fragment_check_message_header(ctx, ctx->ctrl_message_buffer,
                                               true, TEST_MESSAGE_TOPOLOGY);
    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }

    // Parse the message payload
    struct test_request_topology *payload = (
        (struct test_request_topology*) (
            ctx->ctrl_message_buffer +
            sizeof(struct test_message_header))
    );
    // Initialize node configuration
    struct mixnet_node_config c = {
        .node_addr = payload->mixaddr,
        .num_neighbors = payload->num_neighbors,
        .mixing_factor = payload->mixing_factor,
        .neighbor_addrs = payload->neighbor_mixaddrs,
        .use_random_routing = payload->use_random_routing,
        .root_hello_interval_ms = payload->root_hello_interval_ms,
        .reelection_interval_ms = payload->reelection_interval_ms,
    };
    if (!fragment_mixnet_init(ctx, c)) {
        return TEST_ERROR_FRAGMENT_EXCEPTION;
    };
    // Acknowledge topology setup
    memset(ctx->ctrl_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, ctx->ctrl_message_buffer,
                                    TEST_ERROR_NONE, TEST_MESSAGE_TOPOLOGY);

    return harness_send_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE);
}

// Helper macro
#define DIE_DURING_ACCEPT(error_code)           \
    if (error_code != TEST_ERROR_NONE) {        \
        args.keep_running = false;              \
        pthread_join(accept_thread, NULL);      \
                                                \
        free(states);                           \
        return error_code;                      \
    }

// TODO(natre): This function is a mess. Sadly there's too much
// shared state between the tasks (setting up the Mixnet server,
// clients, and resolving the connection addresses) to separate
// them out neatly. Figure out a way to do this eventually.
test_error_code_t
fragment_run_state_start_mixnet(struct fragment_context *ctx) {
    test_error_code_t error_code = TEST_ERROR_NONE;

    // Wait for the corresponding ctrl message
    error_code = harness_recv_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    error_code = fragment_check_message_header(
        ctx, ctx->ctrl_message_buffer, true,
        TEST_MESSAGE_START_MIXNET_SERVER);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    // Mixnet server address
    struct mixnet_context *subctx = &(ctx->mixnet_ctx);
    subctx->tx_server_netaddr.sin_family = AF_INET;
    subctx->tx_server_netaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    struct mixnet_node_config *config = &(subctx->config);
    error_code = harness_server_setup(&(subctx->tx_listen_fd),
                                      &(subctx->tx_server_netaddr),
                                      config->num_neighbors, false);
    if (error_code != TEST_ERROR_NONE) { return error_code; }

    // Next, launch a helper thread to accept new connections
    struct harness_accepted_state *states = malloc(
        sizeof(struct harness_accepted_state) * config->num_neighbors);

    int rc = 0;
    uint16_t num_accepted = 0;
    struct harness_accept_args args = {
        .rc = &rc,
        .done = false,
        .timeout_ms = 0,
        .states = states,
        .started = false,
        .use_timeout = false,
        .keep_running = true,
        .num_accepted = &num_accepted,
        .listen_fd = subctx->tx_listen_fd,
        .max_clients = config->num_neighbors,
    };
    pthread_t accept_thread;
    if (pthread_create(&accept_thread, NULL, &harness_accept, &args) != 0) {
        free(states); return TEST_ERROR_FRAGMENT_EXCEPTION;
    }
    // Wait until the thread is running
    while (!args.started) {}

    // Acknowledge Mixnet server startup
    memset(ctx->ctrl_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, ctx->ctrl_message_buffer,
                                    TEST_ERROR_NONE,
                                    TEST_MESSAGE_START_MIXNET_SERVER);
    // Prepare the message payload
    {
        struct test_response_start_mixnet_server *payload = (
            (struct test_response_start_mixnet_server*) (
                ctx->ctrl_message_buffer +
                sizeof(struct test_message_header))
        );
        payload->server_netaddr = subctx->tx_server_netaddr;
        payload->server_netaddr.sin_addr.s_addr = ((uint32_t) -1);
    }
    error_code = harness_send_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE);

    DIE_DURING_ACCEPT(error_code)

    // Wait for the next ctrl message
    error_code = harness_recv_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    DIE_DURING_ACCEPT(error_code)

    error_code = fragment_check_message_header(
        ctx, ctx->ctrl_message_buffer, true,
        TEST_MESSAGE_START_MIXNET_CLIENTS);

    DIE_DURING_ACCEPT(error_code)

    // Parse the message payload
    {
        struct test_request_start_mixnet_clients *payload = (
            (struct test_request_start_mixnet_clients*) (
                ctx->ctrl_message_buffer +
                sizeof(struct test_message_header))
        );
        if (payload->num_neighbors != config->num_neighbors) {
            DIE_DURING_ACCEPT(TEST_ERROR_FRAGMENT_BAD_NEIGHBOR_COUNT)
        }
        // Update the neighbors' network addresses
        for (uint16_t nid = 0; nid < payload->num_neighbors; nid++) {
            subctx->neighbor_netaddrs[nid] = (
                payload->neighbor_server_netaddrs[nid]);
        }
    }
    // Next, attempt to connect to each neighbor
    for (uint16_t nid = 0; nid < config->num_neighbors; nid++) {
        if ((subctx->rx_socket_fds[nid] = harness_socket(false)) < 0) {
            DIE_DURING_ACCEPT(TEST_ERROR_SOCKET_CREATE_FAILED)
        }
        // Attempt to connect to the neighbor's Mixnet server
        struct sockaddr_in netaddr = subctx->neighbor_netaddrs[nid];
        if (harness_connect_with_timeout(subctx->rx_socket_fds[nid],
            &(netaddr), sizeof(netaddr), ctx->communication_timeout) < 0)
            { DIE_DURING_ACCEPT(TEST_ERROR_SOCKET_CONNECT_FAILED) }
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return TEST_ERROR_FRAGMENT_EXCEPTION;
    }
    int ms_until_deadline = ctx->communication_timeout;
    struct timespec deadline = {
        .tv_sec = now.tv_sec,
        .tv_nsec = now.tv_nsec + (ms_until_deadline * 1000000l)
    };
    do {
        // Calculate time until the deadline
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
            return TEST_ERROR_FRAGMENT_EXCEPTION;
        }
        ms_until_deadline = (int) (
            (deadline.tv_sec - now.tv_sec) * 1000l +
            (deadline.tv_nsec - now.tv_nsec) / 1000000l);

    // Signal the accept thread
    } while (!args.done && (ms_until_deadline > 0));

    args.keep_running = false;
    pthread_join(accept_thread, NULL);

    // Ensure that neighbors connected successfully
    if (*(args.num_accepted) != config->num_neighbors) {
        free(states); return TEST_ERROR_SOCKET_ACCEPT_TIMEOUT;
    }
    // Acknowledge Mixnet client startup
    memset(ctx->ctrl_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, ctx->ctrl_message_buffer,
                                    TEST_ERROR_NONE,
                                    TEST_MESSAGE_START_MIXNET_CLIENTS);
    // Prepare the message payload
    {
        struct test_response_start_mixnet_clients *payload = (
            (struct test_response_start_mixnet_clients*) (
                ctx->ctrl_message_buffer +
                sizeof(struct test_message_header))
        );
        payload->num_neighbors = config->num_neighbors;
        for (uint16_t nid = 0; nid < config->num_neighbors; nid++) {
            socklen_t addrlen = sizeof(struct sockaddr);
            if (getsockname(subctx->rx_socket_fds[nid],
                            (struct sockaddr *) &(payload->
                                client_netaddrs[nid]), &addrlen) < 0) {
                free(states);
                return TEST_ERROR_FRAGMENT_EXCEPTION;
            }
        }
    }
    error_code = harness_send_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE);

    if (error_code != TEST_ERROR_NONE) {
        free(states); return error_code;
    }
    // Wait for the next ctrl message
    error_code = harness_recv_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    if (error_code != TEST_ERROR_NONE) {
        free(states); return error_code;
    }
    error_code = fragment_check_message_header(
        ctx, ctx->ctrl_message_buffer, true,
        TEST_MESSAGE_RESOLVE_MIXNET_CONNS);

    if (error_code != TEST_ERROR_NONE) {
        free(states); return error_code;
    }
    // Parse the message payload
    {
        struct test_request_resolve_mixnet_connections *payload = (
            (struct test_request_resolve_mixnet_connections*) (
                ctx->ctrl_message_buffer +
                sizeof(struct test_message_header))
        );
        if (payload->num_neighbors != config->num_neighbors) {
            free(states); return TEST_ERROR_FRAGMENT_BAD_NEIGHBOR_COUNT;
        }
        // Map NIDs to the appropriate local server FDs
        for (uint16_t nid = 0; nid < payload->num_neighbors; nid++) {
            bool success = false;
            for (uint16_t i = 0; i < config->num_neighbors; i++) {
                if (harness_equal_netaddrs(states[i].address,
                        payload->neighbor_client_netaddrs[nid])) {
                    subctx->tx_socket_fds[nid] = states[i].connection_fd;
                    success = true; break;
                }
            }
            // Sanity check: Ensure that each pair of nodes
            // has a consistent adjacency relationship.
            assert(success);
        }
        free(states);
    }
    // Finally, acknowledge Mixnet connection resolution
    memset(ctx->ctrl_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, ctx->ctrl_message_buffer,
                                    TEST_ERROR_NONE,
                                    TEST_MESSAGE_RESOLVE_MIXNET_CONNS);

    return harness_send_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE);
}
// Cleanup
#undef DIE_DURING_ACCEPT

test_error_code_t
fragment_run_state_start_testcase(struct fragment_context *ctx) {
    test_error_code_t error_code = TEST_ERROR_NONE;

    // Wait for the corresponding ctrl message
    error_code = harness_recv_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    error_code = fragment_check_message_header(
        ctx, ctx->ctrl_message_buffer, true,
        TEST_MESSAGE_START_TESTCASE);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    // Acknowledge testcase starting
    memset(ctx->ctrl_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(
        ctx, ctx->ctrl_message_buffer,
        TEST_ERROR_NONE, TEST_MESSAGE_START_TESTCASE);

    return harness_send_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE);
}

test_error_code_t
fragment_run_state_run_testcase(struct fragment_context *ctx) {
    test_error_code_t error_code = TEST_ERROR_NONE;
    bool end_testcase = false;

    // Launch the helper threads
    if (pthread_create(&(ctx->ts_node.tid), NULL,
                       &fragment_node, ctx) != 0) {
        return TEST_ERROR_FRAGMENT_EXCEPTION;
    }
    if (pthread_create(&(ctx->ts_pcap.tid), NULL,
                       &fragment_pcap, ctx) != 0) {
        return TEST_ERROR_FRAGMENT_EXCEPTION;
    }

    while ((error_code == TEST_ERROR_NONE) && !end_testcase) {
        bool send_response = false;
        enum test_message_type_enum type = TEST_MESSAGE_NOOP;

        error_code = harness_recv_with_timeout(
            ctx->local_fd_ctrl, 0,
            ctx->ctrl_message_buffer,
            MAX_TEST_MESSAGE_SIZE, ctx->nonce);

        // Received a valid message
        if (error_code == TEST_ERROR_NONE) {
            error_code = fragment_check_message_header(ctx,
                ctx->ctrl_message_buffer, false, TEST_MESSAGE_NOOP);

            if (error_code != TEST_ERROR_NONE) { break; }

            struct test_message_header *header = (
                (struct test_message_header*) ctx->ctrl_message_buffer);

            // Perform the requested action based on message type
            type = message_code_to_type(header->message_code);
            switch (type) {
            // Change a network link state
            case TEST_MESSAGE_CHANGE_LINK_STATE: {
                struct test_request_change_link_state *payload = (
                    (struct test_request_change_link_state*) (
                        ctx->ctrl_message_buffer +
                        sizeof(struct test_message_header))
                );
                error_code = (
                    fragment_testcase_task_update_link_state(
                        ctx, payload->neighbor_id, payload->state));

                send_response = true;
            } break;

            // Change the orchestrator's pcap subscription
            case TEST_MESSAGE_PCAP_SUBSCRIPTION: {
                struct test_request_pcap_subscription *payload = (
                    (struct test_request_pcap_subscription*) (
                        ctx->ctrl_message_buffer +
                        sizeof(struct test_message_header))
                );
                error_code = (
                    fragment_testcase_update_pcap_subscription(
                        ctx, payload->subscribe));

                send_response = true;
            } break;

            // Emulate packet injection
            case TEST_MESSAGE_SEND_PACKET: {
                struct test_request_send_packet *payload = (
                    (struct test_request_send_packet*) (
                        ctx->ctrl_message_buffer +
                        sizeof(struct test_message_header)
                    )
                );
                error_code = fragment_testcase_send_packet(ctx, payload);
                send_response = true;
            } break;

            // End this testcase
            case TEST_MESSAGE_END_TESTCASE: {
                end_testcase = true;
                error_code = fragment_run_state_end_testcase(ctx);

                // Only respond if we can clean up the threads
                if (error_code == TEST_ERROR_NONE) {
                    send_response = true;
                }
            } break;

            default: {
                // Received an unexpected message
                error_code = TEST_ERROR_BAD_MESSAGE_CODE;
            }
            } // switch

            if (send_response) {
                // Send response to the orchestrator
                memset(ctx->ctrl_message_buffer, 0,
                       MAX_TEST_MESSAGE_SIZE);

                fragment_prepare_message_header(
                    ctx, ctx->ctrl_message_buffer, error_code, type);

                error_code = harness_send_with_timeout(
                    ctx->local_fd_ctrl, ctx->communication_timeout,
                    ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE);
            }
        }
        // Didn't receive a message
        else if (error_code == TEST_ERROR_RECV_WAIT_TIMEOUT) {
            error_code = TEST_ERROR_NONE; // Reset error
        }
        // Irrecoverable error
        else { break; }

        // Check on the helper threads. If either of them exited prematurely,
        // log the relevant error, then wait for the orchestrator to timeout.
        if (!end_testcase && (ctx->ts_node.exited || ctx->ts_pcap.exited)) {
            if (ctx->ts_node.error_code != TEST_ERROR_NONE) {
                printf("[Node %d] node thread exited with error %d\n",
                       ctx->fragment_id, ctx->ts_node.error_code);
            }
            if (ctx->ts_pcap.error_code != TEST_ERROR_NONE) {
                printf("[Node %d] pcap thread exited with error %d\n",
                       ctx->fragment_id, ctx->ts_pcap.error_code);
            }
            error_code = TEST_ERROR_FRAGMENT_EXCEPTION;
        }
    }
    if (error_code != TEST_ERROR_NONE) { return error_code; }

    // If everything was OK thus far, we're just waiting on
    // a graceful shutdown request from the orchestrator at
    // this point. Use a liberal timeout to account for the
    // orchestrator's own recv timeout for stragglers.
    error_code = harness_recv_with_timeout(
            ctx->local_fd_ctrl,
            ctx->communication_timeout * 3,
            ctx->ctrl_message_buffer,
            MAX_TEST_MESSAGE_SIZE, ctx->nonce);

    return fragment_check_message_header(ctx,
        ctx->ctrl_message_buffer, false, TEST_MESSAGE_SHUTDOWN);
}

// Here, check if we can clean up gracefully. In particular,
// if we are sure that the helper threads can be terminated
// by signalling, then we can clean up ourselves. Otherwise
// it's better NOT to reply and wait for the orchestrator's
// timeout mechanism to kick in and clean up for us.
test_error_code_t
fragment_run_state_end_testcase(struct fragment_context *ctx) {
    ctx->ts_node.keep_running = false;
    ctx->ts_pcap.keep_running = false;

    void **ptr = (void **) message_queue_message_alloc(&(ctx->mq_pcap));
    if (ptr == NULL) { return TEST_ERROR_FRAGMENT_EXCEPTION; }
    *ptr = NULL;
    message_queue_write(&(ctx->mq_pcap), (void*) ptr);

    // Given threads some time, if required
    if (!ctx->ts_node.exited || !ctx->ts_pcap.exited) { sleep(1); }

    // Nope, still running
    if (!ctx->ts_pcap.exited || !ctx->ts_pcap.exited) {
        return TEST_ERROR_FRAGMENT_THREADS_NONRESPONSIVE;
    }
    pthread_join(ctx->ts_node.tid, NULL);
    pthread_join(ctx->ts_pcap.tid, NULL);
    return TEST_ERROR_NONE;
}

test_error_code_t
fragment_run_state_do_shutdown(struct fragment_context *ctx) {
    test_error_code_t error_code = TEST_ERROR_NONE;
    // Send response to the orchestrator
    memset(ctx->ctrl_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, ctx->ctrl_message_buffer,
                                    TEST_ERROR_NONE, TEST_MESSAGE_SHUTDOWN);

    error_code = harness_send_with_timeout(
        ctx->local_fd_ctrl, ctx->communication_timeout,
        ctx->ctrl_message_buffer, MAX_TEST_MESSAGE_SIZE);

    if (error_code == TEST_ERROR_NONE) {
        fragment_context_destroy(ctx);
    }
    return error_code;
}

void *fragment_node(void *args) {
    struct fragment_context *ctx = (struct fragment_context*) args;
    struct fragment_thread_state *ts = &(ctx->ts_node);
    ts->started = true;

    // Invoke the students' node implementation. Since this is
    // external code, assume that we have no control over what
    // happens (at least in this thread) this point forth. The
    // fragment will opportunistically try to exit gracefully,
    // but we'll otherwise rely on the orchestrator's timeout
    // mechanism to handle any catastrophic failures.
    run_node(ctx,
             &(ts->keep_running),
             ctx->mixnet_ctx.config);

    ctx->ts_node.exited = true;
    return NULL;
}

void *fragment_pcap(void *args) {
    struct fragment_context *ctx = (struct fragment_context*) args;
    struct fragment_thread_state *ts = &(ctx->ts_pcap);
    test_error_code_t error_code = TEST_ERROR_NONE;

    // Construct the common header
    memset(ctx->pcap_message_buffer, 0, MAX_TEST_MESSAGE_SIZE);
    fragment_prepare_message_header(ctx, ctx->pcap_message_buffer,
                                    TEST_ERROR_NONE, TEST_MESSAGE_PCAP_DATA);

    // Pointer to the payload
    void *payload = (ctx->pcap_message_buffer +
                     sizeof(struct test_message_header));

    // Continue running until signalled to stop
    ts->started = true;
    while (ts->keep_running &&
           error_code == TEST_ERROR_NONE) {
        // Consume packets from the pcap MQ. Since we want this
        // thread to yield when it is not doing anything useful,
        // we use blocking read operations. Finally, to prevent
        // deadlocks scenarios (possible if the producer thread
        // itself exits), we use the NULL pointer as a sentinel
        // value, signalling (in-band) that the queue is out of
        // operation and the thread should return.
        mixnet_packet **ptr = ((mixnet_packet **)
            message_queue_read(&(ctx->mq_pcap)));

        mixnet_packet *packet = *ptr;
        message_queue_message_free(&(ctx->mq_pcap), (void*) ptr);
        if (packet == NULL) { break; } // Sentinel value, all done

        const size_t total_size = (sizeof(struct mixnet_packet) +
                                   packet->payload_size);
        // Sanity check
        assert(total_size <= MAX_MIXNET_PACKET_SIZE);

        // Populate the PCAP message
        memcpy(payload, packet, total_size);
        free(packet); // Don't need the packet anymore

        // Attempt to send the message
        error_code = harness_send_with_timeout(
            ctx->local_fd_pcap, ctx->communication_timeout,
            ctx->pcap_message_buffer, MAX_TEST_MESSAGE_SIZE);

        ts->error_code = error_code;
    }
    ts->exited = true;
    return NULL;
}

static bool is_shutdown_req(test_error_code_t error_code) {
    return (error_code == TEST_ERROR_FRAGMENT_SHUTDOWN_REQ);
}

static enum fragment_state_t
next_state(const test_error_code_t error_code,
           const enum fragment_state_t ok_state) {
    return (
        is_shutdown_req(error_code) ? FRAGMENT_STATE_SHUTDOWN :
        (error_code != TEST_ERROR_NONE) ? FRAGMENT_STATE_DONE :
        ok_state
    );
}

void fragment_ctrl(struct fragment_context *ctx) {
    if (ctx == NULL) { return; }
    const bool autotest_mode = ctx->autotest_mode;
    test_error_code_t error_code = TEST_ERROR_NONE;
    const mixnet_address fragment_id = ctx->fragment_id;
    enum fragment_state_t state = FRAGMENT_STATE_SETUP_CTRL;

    while (state != FRAGMENT_STATE_DONE) {
        switch (state) {
        // Setup ctrl overlay
        case FRAGMENT_STATE_SETUP_CTRL: {
            error_code = fragment_run_state_setup_ctrl(ctx);
            state = next_state(error_code, FRAGMENT_STATE_SETUP_PCAP);
        } break;

        // Setup pcap overlay
        case FRAGMENT_STATE_SETUP_PCAP: {
            error_code = fragment_run_state_setup_pcap(ctx);
            state = next_state(error_code, FRAGMENT_STATE_CREATE_TOPOLOGY);
        } break;

        // Create Mixnet topology
        case FRAGMENT_STATE_CREATE_TOPOLOGY: {
            error_code = fragment_run_state_create_topology(ctx);
            state = next_state(error_code, FRAGMENT_STATE_START_MIXNET);
        } break;

        // Start Mixnet
        case FRAGMENT_STATE_START_MIXNET: {
            error_code = fragment_run_state_start_mixnet(ctx);
            state = next_state(error_code, FRAGMENT_STATE_START_TESTCASE);
        } break;

        // Start testcase
        case FRAGMENT_STATE_START_TESTCASE: {
            error_code = fragment_run_state_start_testcase(ctx);
            state = next_state(error_code, FRAGMENT_STATE_RUN_TESTCASE);
        } break;

        // Run the testcase
        case FRAGMENT_STATE_RUN_TESTCASE: {
            error_code = fragment_run_state_run_testcase(ctx);
            state = next_state(error_code, FRAGMENT_STATE_SHUTDOWN);
        } break;

        // Perform graceful shutdown
        case FRAGMENT_STATE_SHUTDOWN: {
            error_code = fragment_run_state_do_shutdown(ctx);
            state = FRAGMENT_STATE_DONE;
        } break;

        case FRAGMENT_STATE_DONE: break;
        } // switch
    }
    if (error_code == TEST_ERROR_NONE) {
        if (!autotest_mode) {
            printf("[Node %d] Exiting normally\n", fragment_id);
        }
    }
    else {
        if (!autotest_mode) {
            printf("[Node %d] Dying with error code %d\n",
                   fragment_id, error_code);
        }
        // Can't clean up properly, wait to be killed
        if (autotest_mode) { while (true) {} }
    }
}

/**
 * Testcase tasks.
 */
test_error_code_t fragment_testcase_task_update_link_state(
    struct fragment_context *ctx, const uint16_t nid,
    const bool link_state) {
    // Sanity check: Orchestrator should sanitize input
    struct mixnet_context *subctx = &(ctx->mixnet_ctx);
    assert(nid < subctx->config.num_neighbors);

    pthread_mutex_t *mutex = &(subctx->port_mutexes[nid]);
    // Acquire the mutex for the corresponding port and
    // update link state. If the link is being disabled,
    // we also need to drain the socket receive queue.
    pthread_mutex_lock(mutex);
    ctx->mixnet_ctx.link_states[nid] = link_state;

    if (!link_state) {
        int rc = 0;
        int flags = 0;
        do {
            // Drain the receive queue
            rc = sctp_recvmsg(subctx->rx_socket_fds[nid],
                              ctx->ctrl_message_buffer,
                              MAX_MIXNET_PACKET_SIZE,
                              NULL, 0, NULL, &flags);

            if (rc == 0) {
                pthread_mutex_unlock(mutex);
                return TEST_ERROR_MIXNET_CONNECTION_BROKEN;
            }
            if ((rc < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                pthread_mutex_unlock(mutex);
                return TEST_ERROR_MIXNET_CONNECTION_BROKEN;
            }
        } while (rc > 0);
    }
    pthread_mutex_unlock(mutex);
    return TEST_ERROR_NONE;
}

test_error_code_t fragment_testcase_update_pcap_subscription(
    struct fragment_context *ctx, const bool subscribe) {
    ctx->mixnet_ctx.is_pcap_subscribed = subscribe;
    return TEST_ERROR_NONE;
}

test_error_code_t fragment_testcase_send_packet(
    struct fragment_context *ctx,
    struct test_request_send_packet *metadata) {
    mixnet_packet *packet = ((mixnet_packet *)
        message_queue_message_alloc(&(ctx->mq_app_packets)));
    // If full, the node isn't consuming packets fast enough
    if (packet == NULL) { return TEST_ERROR_FRAGMENT_EXCEPTION; }

    // Update the header fields
    packet->payload_size = 0;
    packet->type = metadata->type;
    packet->src_address = metadata->src_mixaddr;
    packet->dst_address = metadata->dst_mixaddr;

    if (packet->type == PACKET_TYPE_DATA ||
        packet->type == PACKET_TYPE_PING) {
        mixnet_packet_routing_header *header = (
            (mixnet_packet_routing_header *) packet->payload);

        header->hop_index = 0;
        header->route_length = 0;
        if (packet->type == PACKET_TYPE_DATA) {
            packet->payload_size = metadata->data_size;
            memcpy(header->route, metadata->data, metadata->data_size);
        }
    }

    message_queue_write(&(ctx->mq_app_packets), (void*) packet);
    return TEST_ERROR_NONE;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        printf("[Node] Usage: ./node server_ip server_port node_id nonce\n");
        return 1;
    }
    // Server address
    struct sockaddr_in orc_netaddr;
    memset(&orc_netaddr, 0, sizeof(orc_netaddr));
    orc_netaddr.sin_family = AF_INET;

    in_addr_t s_addr = inet_addr(argv[1]);
    if (s_addr == (in_addr_t) -1) {
        printf("[Node] Invalid server address\n");
        return 1;
    }
    orc_netaddr.sin_addr.s_addr = s_addr;
    orc_netaddr.sin_port = htons((uint16_t) atoi(argv[2]));
    uint16_t fragment_id = (uint16_t) strtoul(argv[3], NULL, 10);
    uint16_t nonce = (uint16_t) strtoul(argv[4], NULL, 10); // Session nonce

    // Configuration
    int autotest_mode = 0;
    uint32_t connect_timeout = DEFAULT_FRAGMENT_TIMEOUT_MS;
    uint32_t communication_timeout = DEFAULT_FRAGMENT_TIMEOUT_MS;

    int c; optind = 4; // Parse command-line args
    while ((c = getopt(argc, argv, "a")) != -1) {
        switch (c) {
        case 'a': { autotest_mode = 1; } break;
        default: break;
        }
    }
    if (!autotest_mode) {
        // Use large timeouts in manual mode
        communication_timeout = 5000; // 5 seconds
        connect_timeout = 30 * 60 * 1000; // 30 minutes
        printf("[Node %d] Started Mixnet node with nonce %d\n",
               fragment_id, nonce);
    }

    struct fragment_context *ctx = fragment_context_create(
        nonce, autotest_mode, fragment_id, connect_timeout,
        communication_timeout, orc_netaddr);

    fragment_ctrl(ctx);
    return 0;
}

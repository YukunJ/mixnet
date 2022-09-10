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
#ifndef HARNESS_FRAGMENT_H
#define HARNESS_FRAGMENT_H

#include "error.h"
#include "message.h"
#include "mixnet/address.h"
#include "mixnet/config.h"
#include "external/itc/message_queue.h"

#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Represents each fragment's Mixnet subcontext.
 */
struct mixnet_context {
    // Mixnet node configuration
    struct mixnet_node_config config;       // This node's configuration
    // TX
    int tx_listen_fd;                       // Listen FD (this node as server)
    int *tx_socket_fds;                     // Socket FDs (this node as server)
    struct sockaddr_in tx_server_netaddr;   // This node's local server address
    // RX
    int *rx_socket_fds;                     // Socket FDs (this node as client)
    struct sockaddr_in *neighbor_netaddrs;  // Server addrs of neighboring nodes
    // Miscellaneous
    volatile bool is_pcap_subscribed;       // Orchestrator subscribed for pcap?
    pthread_mutex_t *port_mutexes;          // Mutexes guarding per-port state
    uint16_t next_port_idx;                 // Next port to serve (RR index)
    char *packet_buffer;                    // Scratch packet buffer (recv)
    bool *link_states;                      // NID -> Link state (up: true)
};

/**
 * Represents the fragment's per-thread state.
 */
struct fragment_thread_state {
    pthread_t tid;                          // Thread ID
    volatile bool exited;                   // Whether this thread has exited
    volatile bool started;                  // Whether the thread has started
    volatile bool keep_running;             // Continue running this thread?
    test_error_code_t error_code;           // Thread's return code
};
void initialize_fragment_thread_state(
    struct fragment_thread_state *state);

/**
 * Represents the overall fragment context.
 */
struct fragment_context {
    // Harness state
    uint16_t nonce;                         // Test session nonce
    int autotest_mode;                      // Run in autotest mode?
    int local_fd_ctrl;                      // Local FD for ctrl overlay
    int local_fd_pcap;                      // Local FD for pcap overlay
    uint16_t fragment_id;                   // This fragment's unique ID
    uint32_t connect_timeout;               // Initial connection timeout
    char *ctrl_message_buffer;              // Scratch buffer (ctrl overlay)
    char *pcap_message_buffer;              // Scratch buffer (pcap overlay)
    struct sockaddr_in orc_netaddr;         // Orchestrator's ctrl net address
    uint32_t communication_timeout;         // Send/recv communication timeout

    // Mixnet subcontext
    struct mixnet_context mixnet_ctx;

    // Housekeeping
    struct message_queue mq_pcap;           // MQ for pcap data
    struct message_queue mq_app_packets;    // MQ for injected packets
    struct fragment_thread_state ts_node;   // Thread managing the Mixnet node
    struct fragment_thread_state ts_pcap;   // Thread handling the pcap stream
};

/**
 * FSM states. These represent common tasks that need to be
 * run for every testcase (set up the Mixnet topology, etc).
 */
enum fragment_state_t {
    FRAGMENT_STATE_SETUP_CTRL = 0,
    FRAGMENT_STATE_SETUP_PCAP,
    FRAGMENT_STATE_CREATE_TOPOLOGY,
    FRAGMENT_STATE_START_MIXNET,
    FRAGMENT_STATE_START_TESTCASE,
    FRAGMENT_STATE_RUN_TESTCASE,
    FRAGMENT_STATE_SHUTDOWN,
    FRAGMENT_STATE_DONE,
};

/**
 * Allocates and returns a new fragment context.
 *
 * @param nonce Server-generated session nonce
 * @param autotest_mode Running in autotest mode?
 * @param fragment_id Unique ID for this fragment
 * @param connect_timeout Initial timeout to connect
 * @param communication_timeout Timeout for send/recv
 * @param orc_netaddr Network address of the orchestrator
 * @return Pointer to a heap-allocated fragment context (or NULL)
 */
struct fragment_context*
fragment_context_create(const uint16_t nonce,
                        const int autotest_mode,
                        const uint16_t fragment_id,
                        const uint32_t connect_timeout,
                        const uint32_t communication_timeout,
                        const struct sockaddr_in orc_netaddr);

/**
 * Given an ordered list of network addresses of Mixnet nodes
 * directly neighboring this one, initializes the fragment's
 * Mixnet subcontext.
 *
 * @param ctx The fragment context
 * @param c This node's mixnet configuration
 * @return True if initialization was successful, else false
 */
bool fragment_mixnet_init(struct fragment_context *ctx,
                          const struct mixnet_node_config c);

/**
 * Destroy the fragment context. Deallocates resources (memory,
 * sockets, etc.) and returns. The context should not be reused
 * beyond this point.
 *
 * @param ctx The fragment context to destroy
 */
void fragment_context_destroy(struct fragment_context *ctx);

/**
 * Fragment threads.
 */
void *fragment_node(void *args);
void *fragment_pcap(void *args);
void  fragment_ctrl(struct fragment_context *ctx);

/**
 * Helper functions to send/recv data.
 */
void fragment_prepare_message_header(
    struct fragment_context *ctx,
    void *buffer, const test_error_code_t error,
    const enum test_message_type_enum message_type);

test_error_code_t fragment_check_message_header(
    struct fragment_context *ctx, void *buffer,
    const bool check_message_type, const enum
    test_message_type_enum message_type);

/**
 * Miscellaneous helper functions.
 */
uint16_t fragment_next_port_idx(
    const uint16_t idx, const uint16_t max_num_ports);

/**
 * Fragment FSM functionality.
 */
#define DEFINE_FRAGMENT_STATE_FUNCTION(name)            \
    test_error_code_t                                   \
    fragment_run_state_##name(struct fragment_context*)

DEFINE_FRAGMENT_STATE_FUNCTION(setup_ctrl);
DEFINE_FRAGMENT_STATE_FUNCTION(setup_pcap);
DEFINE_FRAGMENT_STATE_FUNCTION(create_topology);
DEFINE_FRAGMENT_STATE_FUNCTION(start_mixnet);
DEFINE_FRAGMENT_STATE_FUNCTION(start_testcase);
DEFINE_FRAGMENT_STATE_FUNCTION(run_testcase);
DEFINE_FRAGMENT_STATE_FUNCTION(end_testcase);
DEFINE_FRAGMENT_STATE_FUNCTION(do_shutdown);

// Cleanup
#undef DEFINE_FRAGMENT_STATE_FUNCTION

/**
 * Fragment testcase tasks.
 */
test_error_code_t fragment_testcase_task_update_link_state(
    struct fragment_context *ctx, const uint16_t nid,
    const bool link_state);

test_error_code_t fragment_testcase_update_pcap_subscription(
    struct fragment_context *ctx, const bool subscribe);

test_error_code_t fragment_testcase_send_packet(
    struct fragment_context *ctx,
    struct test_request_send_packet *metadata);

#ifdef __cplusplus
}
#endif

#endif // HARNESS_FRAGMENT_H

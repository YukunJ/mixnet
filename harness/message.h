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
#ifndef HARNESS_MESSAGE_H
#define HARNESS_MESSAGE_H

#include "mixnet/address.h"
#include "mixnet/packet.h"

#include <assert.h>
#include <netinet/in.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constant parameters
#define MAX_NUM_NEIGHBORS       (64)
#define MAX_TEST_MESSAGE_DATA   (64)
#define MAX_TEST_MESSAGE_SIZE   (2048)

/**
 * Test harness message types.
 *
 * 16-bit value representing the type of message enclosed. The most
 * siginificant bit indicates the message direction (0 for requests
 * going from the orchestrator to fragments, 1 for responses in the
 * reverse direction).
 */
enum test_message_type_enum {
    // Sentinel value
    TEST_MESSAGE_NOOP = 0,

    // Message types
    TEST_MESSAGE_SETUP_CTRL,            // Setup ctrl overlay
    TEST_MESSAGE_SETUP_PCAP,            // Setup pcap overlay
    TEST_MESSAGE_TOPOLOGY,              // Create the topology
    TEST_MESSAGE_START_MIXNET_SERVER,   // Start Mixnet server
    TEST_MESSAGE_START_MIXNET_CLIENTS,  // Start Mixnet clients
    TEST_MESSAGE_RESOLVE_MIXNET_CONNS,  // Resolve Mixnet connections
    TEST_MESSAGE_CHANGE_LINK_STATE,     // Change network link states
    TEST_MESSAGE_PCAP_DATA,             // Fragment-captured pcap data
    TEST_MESSAGE_PCAP_SUBSCRIPTION,     // Change subscription to pcaps
    TEST_MESSAGE_SEND_PACKET,           // Send a packet on the network
    TEST_MESSAGE_START_TESTCASE,        // Indicate testcase commencing
    TEST_MESSAGE_END_TESTCASE,          // Indicate testcase completion
    TEST_MESSAGE_SHUTDOWN,              // Teardown fragment process
};
// Shorter type alias for the enum
typedef uint16_t test_message_type_t;

/**
 * Message header structure. This is a common header for
 * all messages exchanged on the ctrl and pcap overlays.
 */
struct test_message_header {
    uint16_t session_nonce;             // Nonce for test session
    uint16_t message_code;              // Message polarity and type
    uint16_t fragment_id;               // Unique ID of the target fragment
    uint16_t error_code;                // 0 on success, else error (error.h)
};
static_assert(sizeof(struct test_message_header) == 8, "Bad size");

// Helper functions
uint16_t message_code_create(
    bool is_request, enum test_message_type_enum type);

bool message_code_is_request(const uint16_t message_code);
void message_code_reverse_polarity(uint16_t *message_code);
test_message_type_t message_code_to_type(const uint16_t message_code);

// Helper macros
#define GET_MESSAGE_SIZE(typename)                                      \
    (sizeof(struct test_message_header) + sizeof(typename))

#define CHECK_ALIGNMENT_AND_SIZE(typename)                              \
    static_assert(alignof(typename) <= 8, "Bad alignment");             \
    static_assert(GET_MESSAGE_SIZE(typename) <= MAX_TEST_MESSAGE_SIZE,  \
                  "Bad size")

/**
 * Payload structure for REQUEST messages.
 */
// Setup pcap overlay
struct test_request_setup_pcap {
    struct sockaddr_in pcap_netaddr; // Network address on which the
                                     // pcap server is listening
};
CHECK_ALIGNMENT_AND_SIZE(struct test_request_setup_pcap);

// Topology
struct test_request_topology {
    mixnet_address mixaddr; // Node's mixnet address
    uint16_t num_neighbors; // Number of direct neighbors
    mixnet_address neighbor_mixaddrs[MAX_NUM_NEIGHBORS];
    // NID -> Mixnet address

    // Node configuration
    bool use_random_routing; // Perform random routing?
    uint16_t mixing_factor; // Mixing factor to use during routing
    uint32_t root_hello_interval_ms; // Time between 'hello' messages
    uint32_t reelection_interval_ms; // Time before starting reelection
};
CHECK_ALIGNMENT_AND_SIZE(struct test_request_topology);

// Start Mixnet client
struct test_request_start_mixnet_clients {
    uint16_t num_neighbors; // Number of direct neighbors
    struct sockaddr_in neighbor_server_netaddrs[MAX_NUM_NEIGHBORS];
    // NID -> Network address of the neighbor's corresponding server socket
};
CHECK_ALIGNMENT_AND_SIZE(struct test_request_start_mixnet_clients);

// Resolve Mixnet network connections
struct test_request_resolve_mixnet_connections {
    uint16_t num_neighbors; // Number of direct neighbors
    struct sockaddr_in neighbor_client_netaddrs[MAX_NUM_NEIGHBORS];
    // NID -> Network address of the neighbor's corresponding client socket
};
CHECK_ALIGNMENT_AND_SIZE(struct test_request_resolve_mixnet_connections);

// Change network link state
struct test_request_change_link_state {
    uint16_t neighbor_id; // NID corresponding to the link to update
    bool state; // New state of the link (enabled if true)
};
CHECK_ALIGNMENT_AND_SIZE(struct test_request_change_link_state);

// Change pcap subscription
struct test_request_pcap_subscription {
    bool subscribe; // Whether to subscribe/unsubscribe to/from pcap data
};
CHECK_ALIGNMENT_AND_SIZE(struct test_request_pcap_subscription);

// Send a packet out over the network
struct test_request_send_packet {
    mixnet_packet_type_t type; // Packet type
    mixnet_address src_mixaddr; // Source Mixnet address
    mixnet_address dst_mixaddr; // Destination Mixnet address

    uint16_t data_size; // Size of packet data field
    char data[MAX_TEST_MESSAGE_DATA]; // Packet data
};
CHECK_ALIGNMENT_AND_SIZE(struct test_request_send_packet);

/**
 * Payload structure for RESPONSE messages.
 */
// Ctrl and pcap overlay setup
struct test_response_setup_overlay {
    uint16_t fragment_id; // This node's fragment ID
};
CHECK_ALIGNMENT_AND_SIZE(struct test_response_setup_overlay);

// Start Mixnet server
struct test_response_start_mixnet_server {
    struct sockaddr_in server_netaddr; // Network address on which the
                                       // Mixnet server is listening.
};
CHECK_ALIGNMENT_AND_SIZE(struct test_response_start_mixnet_server);

// Start Mixnet clients
struct test_response_start_mixnet_clients {
    uint16_t num_neighbors; // Number of direct neighbors
    struct sockaddr_in client_netaddrs[MAX_NUM_NEIGHBORS];
    // NID -> Network address of the corresponding client socket
};
CHECK_ALIGNMENT_AND_SIZE(struct test_response_start_mixnet_clients);

// Cleanup
#undef CHECK_ALIGNMENT_AND_SIZE

#ifdef __cplusplus
}
#endif

#endif // HARNESS_MESSAGE_H

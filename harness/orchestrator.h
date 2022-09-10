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
#ifndef HARNESS_ORCHESTRATOR_H
#define HARNESS_ORCHESTRATOR_H

#include "error.h"
#include "message.h"
#include "mixnet/address.h"

#include <functional>
#include <stdint.h>
#include <thread>
#include <vector>

/**
 * Central controller orchestrating distributed fragments.
 */
class orchestrator {
public:
    // Orchestrator's ctrl port number
    static constexpr uint16_t PORT_LISTEN_CTRL = 9107;
    // Orchestrator's pcap port number
    static constexpr uint16_t PORT_LISTEN_PCAP = 9108;
    // Wait time to send/recv data to/from all fragments
    static constexpr uint32_t DEFAULT_WAIT_TIME_MS = 5000;

private:
    // FSM states. These represent common tasks that need to
    // be run for every testcase (set up the mixnet topology,
    // shut down fragments, etc.).
    enum class state_t {
        STATE_INIT = 0,
        STATE_SETUP_CTRL,
        STATE_SETUP_PCAP,
        STATE_CREATE_TOPOLOGY,
        STATE_START_MIXNET_SERVER,
        STATE_START_MIXNET_CLIENTS,
        STATE_RESOLVE_MIXNET_CONNECTIONS,
        STATE_START_TESTCASE,
        STATE_RUN_TESTCASE,
        STATE_END_TESTCASE,
        STATE_GRACEFUL_SHUTDOWN,
        STATE_FORCEFUL_SHUTDOWN,
        STATE_RESET,
    };

    // Fragment metadata
    typedef struct fragment_metadata {
        int pid = -1;                               // Fragment process ID
        int fd_ctrl = -1;                           // Local ctrl socket FD
        int fd_pcap = -1;                           // Local pcap socket FD
        struct sockaddr_in mixnet_server_netaddr{}; // Network address of this
                                                    // fragment's Mixnet server
    } fragment_metadata;

    // Maps Mixnet addresses to fragment metadata
    std::vector<fragment_metadata> fragments_;

    // Network topology represented using adjacency lists. For each
    // node, adjacency list indices correspond to the neighbor IDs.
    std::vector<std::vector<uint16_t>> topology_;
    std::vector<mixnet_address> mixaddrs_; // Fragment ID -> Mixnet address

    // Map of client network addresses on the Mixnet network
    std::vector<std::vector<struct sockaddr_in>> client_netaddrs_;

    // State for managing the pcap overlay
    std::thread pcap_thread_;
    std::vector<bool> pcap_subscriptions_;
    volatile bool pcap_thread_run_ = true;
    test_error_code_t pcap_thread_error_ = TEST_ERROR_NONE;

    // Mixnet node configurations
    uint32_t root_hello_interval_ms_ = 2000;        // Default: 2s
    uint32_t reelection_interval_ms_ = 20000;       // Default: 20s
    std::vector<uint16_t> mixing_factors_;          // Default: All 1
    std::vector<bool> use_random_routing_;          // Default: All false

    // Housekeeping
    state_t state_ = state_t::STATE_INIT;           // Current FSM state
    char *ctrl_message_buffer_ = nullptr;           // Scratch buffer (ctrl)
    char *pcap_message_buffer_ = nullptr;           // Scratch buffer (pcap)
    uint16_t session_nonce_ = 0;                    // Nonce for test session
    int listen_fd_ctrl_ = -1;                       // Server's ctrl socket FD
    int listen_fd_pcap_ = -1;                       // Server's pcap socket FD

    // Configuration
    int autotest_mode_ = 0;                         // Use autotester mode
    std::string fragment_dir_;                      // Fragment executable path
    uint32_t connect_timeout_ms_ = 0;               // Setup connection timeout
    uint32_t communication_timeout_ms_ = 0;         // Regular send/recv timeout

    /**
     * Registered callbacks.
     */
    // Mandatory
    std::function<void(orchestrator*)> cb_testcase_{};
    std::function<void(orchestrator*, struct test_message_header*,
                       struct mixnet_packet*)> cb_pcap_data_{};
    // Optional
    std::function<void(test_error_code_t)> cb_exit_code_{};

    /**
     * FSM functionality.
     */
    test_error_code_t run_state_init();
    test_error_code_t run_state_setup_ctrl();
    test_error_code_t run_state_setup_pcap();
    test_error_code_t run_state_end_testcase();
    test_error_code_t run_state_start_testcase();
    test_error_code_t run_state_create_topology();
    test_error_code_t run_state_graceful_shutdown();
    test_error_code_t run_state_start_mixnet_server();
    test_error_code_t run_state_start_mixnet_clients();
    test_error_code_t run_state_resolve_mixnet_connections();

    // Orchestrator methods
    void run_state_reset();
    void run_state_forceful_shutdown();

    /**
     * Miscellaneous helper methods.
     */
    void destroy_sockets();
    void pcap_thread_loop();
    void destroy_fragments(int signal);

    struct test_message_header *prepare_header(
        void *buffer, const uint16_t fragment_id,
        const enum test_message_type_enum message_type);

    test_error_code_t check_header(
        const void *buffer,
        const bool check_id, const uint16_t fragment_id,
        const enum test_message_type_enum message_type);

    test_error_code_t fragment_request_response(
        const uint16_t fragment_id,
        const std::function<void(void*)>& lambda,
        const enum test_message_type_enum message_type);

    test_error_code_t foreach_fragment_send_ctrl(
        const enum test_message_type_enum message_type,
        const std::function<void(size_t, void*)>& lambda);

    test_error_code_t foreach_fragment_send_generic(
        const std::vector<int>& fragment_fds,
        const enum test_message_type_enum message_type,
        const std::function<void(size_t, void*)>& lambda);

    test_error_code_t foreach_fragment_recv_ctrl(
        const enum test_message_type_enum message_type,
        const std::function<test_error_code_t(size_t, void*)>& lambda);

    test_error_code_t foreach_fragment_recv_generic(
        bool check_fragment_ids,
        const std::vector<int>& fragment_fds,
        const enum test_message_type_enum message_type,
        const std::function<test_error_code_t(size_t, void*)>& lambda);

public:
    explicit orchestrator();
    ~orchestrator();

    // Disallow copy/assignment
    orchestrator(const orchestrator&) = delete;
    void operator=(const orchestrator&) = delete;

    // Test API
    /**
     * The following methods allow you to change the STATIC configuration
     * of the network and mixnet nodes. This includes the topology, hello
     * and reelection intervals, nodes' mixing factors, etc. These should
     * be invoked before calling orchestrator::run().
     */
    void configure(int argc, char **argv);
    void set_topology(const std::vector<mixnet_address>& mixaddrs,
                      const std::vector<std::vector<uint16_t>>& topology);

    void register_cb_testcase(std::function<void(orchestrator*)> cb);

    void register_cb_pcap(std::function<void(orchestrator*,
        struct test_message_header*, struct mixnet_packet*)> cb);

    void register_cb_retcode(
        std::function<void(test_error_code_t)> cb);

    void set_mixing_factor(const uint16_t idx, const uint16_t factor);
    void set_use_random_routing(const uint16_t idx, const bool value);
    void set_root_hello_interval_ms(const uint32_t root_hello_interval_ms);
    void set_reelection_interval_ms(const uint32_t reelection_interval_ms);

    // Main orchestrator method. Once the virtual topology is set up and all
    // the nodes are running, passes control to the callback registered with
    // 'register_cb_testcase'. Packet traffic the orchestrator subscribes to
    // (see 'pcap_change_subscription' below) invokes the callback register-
    // ed via 'register_cb_pcap'; note that this runs in a separate thread,
    // so careful with shared state!
    void run();

    /**
     * The methods that appear after this point are run-time configuration
     * parameters. They must be invoked AFTER run() while the test-case is
     * still running.
     */
    // Allows the orchestrator to 'subscribe' to packet capture traffic.
    // Any packets that appear on the output (mixnet_send() to the user)
    // of a subscribed node will be sent back to the orchestrator and
    // will invoke the registered pcap callback.
    test_error_code_t pcap_change_subscription(
        const uint16_t idx, const bool subscribe);

    // Enable/disable the link between two nodes
    test_error_code_t change_link_state(const uint16_t idx_a,
                                        const uint16_t idx_b,
                                        const bool is_enabled);

    // Send a packet with source and destination addresses corresponding
    // to src_idx and dst_index, respectively. The optional data_string
    // parameter allows you to specify the data to send.
    test_error_code_t send_packet(const uint16_t src_idx,
                                  const uint16_t dst_idx,
                                  const mixnet_packet_type_t type,
                                  const std::string data_string="");
};

#endif // HARNESS_ORCHESTRATOR_H

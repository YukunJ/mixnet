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
#include "orchestrator.h"

#include "networking.h"

#include <assert.h>
#include <chrono>
#include <fcntl.h>
#include <filesystem>
#include <getopt.h>
#include <iostream>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <random>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

/**
 * Miscellaneous helper methods.
 */
void orchestrator::destroy_sockets() {
    for (size_t idx = 0; idx < fragments_.size(); idx++) {
        if (fragments_[idx].fd_ctrl != -1) {
            close(fragments_[idx].fd_ctrl);
        }
        if (fragments_[idx].fd_pcap != -1) {
            close(fragments_[idx].fd_pcap);
        }
    }
    if (listen_fd_pcap_ != -1) { close(listen_fd_pcap_); }
    if (listen_fd_ctrl_ != -1) { close(listen_fd_ctrl_); }
}

void orchestrator::destroy_fragments(int signal) {
    for (size_t idx = 0; idx < fragments_.size(); idx++) {
        if (fragments_[idx].pid != -1) {
            kill(fragments_[idx].pid, signal);
        }
    }
}

struct test_message_header*
orchestrator::prepare_header(void *buffer, const uint16_t fragment_id,
                             const enum test_message_type_enum type) {
    // Populate the message header
    auto *header = reinterpret_cast<
        struct test_message_header*>(buffer);

    header->fragment_id = fragment_id;
    header->error_code = TEST_ERROR_NONE;
    header->session_nonce = session_nonce_;
    header->message_code = message_code_create(true, type);

    return header;
}

test_error_code_t
orchestrator::check_header(const void *buffer,
    const bool check_id, const uint16_t fragment_id,
    const enum test_message_type_enum message_type) {
    // Compute header address
    auto header = reinterpret_cast<const
        struct test_message_header*>(buffer);
    uint16_t recv_code = header->message_code;

    if (check_id &&
        (header->fragment_id != fragment_id)) {
        // ID doesn't match the fragment
        return TEST_ERROR_BAD_FRAGMENT_ID;
    }
    else if (
        (message_code_to_type(recv_code) != message_type) ||
        message_code_is_request(recv_code)) {
        // Received unexpected message code
        return TEST_ERROR_BAD_MESSAGE_CODE;
    }
    else if (header->error_code != TEST_ERROR_NONE) {
        // The fragment reported a test error
        return TEST_ERROR_FRAGMENT_EXCEPTION;
    }
    return TEST_ERROR_NONE;
}

test_error_code_t
orchestrator::fragment_request_response(
    const uint16_t fragment_id,
    const std::function<void(void*)>& lambda,
    const enum test_message_type_enum message_type) {
    auto error_code = TEST_ERROR_NONE; // Return value

    // Prepare the request header
    memset(ctrl_message_buffer_, 0, MAX_TEST_MESSAGE_SIZE);
    prepare_header(ctrl_message_buffer_, fragment_id, message_type);

    // Populate the payload using lambda
    void *payload = (ctrl_message_buffer_ +
                     sizeof(struct test_message_header));
    lambda(payload);

    // Send the request
    error_code = harness_send_with_timeout(fragments_[fragment_id].fd_ctrl,
        communication_timeout_ms_, ctrl_message_buffer_, MAX_TEST_MESSAGE_SIZE);

    if (error_code != TEST_ERROR_NONE) { return error_code; }

    // Wait for acknowledgement
    error_code = harness_recv_with_timeout(
        fragments_[fragment_id].fd_ctrl, communication_timeout_ms_,
        ctrl_message_buffer_, MAX_TEST_MESSAGE_SIZE, session_nonce_);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    return check_header(ctrl_message_buffer_, true,
                        fragment_id, message_type);
}

test_error_code_t
orchestrator::foreach_fragment_send_ctrl(
    const enum test_message_type_enum message_type,
    const std::function<void(size_t, void*)>& lambda) {
    std::vector<int> fds; // Prepare fds to use with the helper
    for (const auto& v : fragments_) { fds.push_back(v.fd_ctrl); }
    return foreach_fragment_send_generic(fds, message_type, lambda);
}

test_error_code_t
orchestrator::foreach_fragment_send_generic(
    const std::vector<int>& fragment_fds,
    const enum test_message_type_enum message_type,
    const std::function<void(size_t, void*)>& lambda) {
    typedef std::chrono::system_clock clock; // Local typedef
    auto error_code = TEST_ERROR_NONE; // Return value

    // Prepare the common message header
    memset(ctrl_message_buffer_, 0, MAX_TEST_MESSAGE_SIZE);
    auto header = prepare_header(ctrl_message_buffer_, 0, message_type);

    void *payload = (ctrl_message_buffer_ +
                     sizeof(struct test_message_header));

    // Track pending requests
    size_t num_pending = fragment_fds.size();
    std::vector<bool> pending(fragment_fds.size(), true);
    auto time_start = clock::now(); // Start the wait timer

    while (num_pending != 0) {
        // Attempt to send a message to each fragment
        for (size_t idx = 0; idx < fragment_fds.size(); idx++) {
            auto current_ec = TEST_ERROR_NONE;
            if (!pending[idx]) { continue; }

            lambda(idx, payload); // Populate the payload
            header->fragment_id = idx; // Update fragment ID
            int rc = sctp_sendmsg(fragment_fds[idx],
                                  ctrl_message_buffer_,
                                  MAX_TEST_MESSAGE_SIZE,
                                  NULL, 0, 0, 0, 0, 0, 0);
            if (rc < 0) {
                if ((errno != EAGAIN) && (errno != ENOBUFS)) {
                    // Connection to fragment is broken, record error
                    current_ec = TEST_ERROR_CTRL_CONNECTION_BROKEN;
                    pending[idx] = false; num_pending--;
                }
            }
            else if (rc != (int) MAX_TEST_MESSAGE_SIZE) {
                // The SCTP transmission is non-atomic, record error
                current_ec = TEST_ERROR_SCTP_PARTIAL_DATA;
                pending[idx] = false; num_pending--;
            }
            else {
                // Success, update the state
                pending[idx] = false;
                num_pending--;
            }
            // Accumulate error across iterations
            if (error_code == TEST_ERROR_NONE) {
                error_code = current_ec;
            }
        }
        auto delta = clock::now() - time_start;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                delta).count() > communication_timeout_ms_) { break; }
    }
    return ((error_code != TEST_ERROR_NONE) ? error_code :
            (num_pending == 0) ? TEST_ERROR_NONE :
            TEST_ERROR_SEND_REQS_TIMEOUT);
}

test_error_code_t
orchestrator::foreach_fragment_recv_ctrl(
    const enum test_message_type_enum message_type,
    const std::function<test_error_code_t(size_t, void*)>& lambda) {
    std::vector<int> fds; // Prepare fds to use with the helper
    for (const auto& v : fragments_) { fds.push_back(v.fd_ctrl); }
    return foreach_fragment_recv_generic(true, fds, message_type, lambda);
}

test_error_code_t
orchestrator::foreach_fragment_recv_generic(
    bool check_ids, const std::vector<int>& fragment_fds,
    const enum test_message_type_enum expected_message_type,
    const std::function<test_error_code_t(size_t, void*)>& lambda) {
    typedef std::chrono::system_clock clock; // Local typedef
    auto error_code = TEST_ERROR_NONE; // Return value

    // Track pending responses
    size_t num_pending = fragment_fds.size();
    std::vector<bool> pending(fragment_fds.size(), true);
    auto time_start = clock::now(); // Start the wait timer

    // Compute header and payload address
    auto header = reinterpret_cast<struct
        test_message_header*>(ctrl_message_buffer_);

    void *payload = (ctrl_message_buffer_ +
                     sizeof(struct test_message_header));

    while (num_pending != 0) {
        // Attempt to recv on socket for each pending fragment
        for (size_t idx = 0; idx < fragment_fds.size(); idx++) {
            auto current_ec = TEST_ERROR_NONE;
            if (!pending[idx]) { continue; }

            int flags = 0;
            int rc = sctp_recvmsg(fragment_fds[idx],
                                  ctrl_message_buffer_,
                                  MAX_TEST_MESSAGE_SIZE,
                                  NULL, 0, NULL, &flags);
            if (rc < 0) {
                if ((errno != EAGAIN) && (errno != ENOBUFS)) {
                    // Connection to fragment is broken, record error
                    current_ec = TEST_ERROR_CTRL_CONNECTION_BROKEN;
                    pending[idx] = false; num_pending--;
                }
            }
            else if (rc == 0) {
                // Connection to fragment is broken, record error
                current_ec = TEST_ERROR_CTRL_CONNECTION_BROKEN;
                pending[idx] = false; num_pending--;
            }
            else if (rc != (int) MAX_TEST_MESSAGE_SIZE) {
                // The SCTP transmission is non-atomic, record error
                current_ec = TEST_ERROR_SCTP_PARTIAL_DATA;
                pending[idx] = false; num_pending--;
            }
            else {
                // Ignore any stale messages (mismatched nonce)
                if (header->session_nonce != session_nonce_) {
                    continue;
                }
                // Validate the message header
                current_ec = check_header(header, check_ids, idx,
                                          expected_message_type);
                // Process the message payload
                if (current_ec == TEST_ERROR_NONE) {
                    current_ec = lambda(idx, payload);
                }
                // Success, update the state
                pending[idx] = false;
                num_pending--;
            }
            // Accumulate error across iterations
            if (error_code == TEST_ERROR_NONE) {
                error_code = current_ec;
            }
        }
        auto delta = clock::now() - time_start;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                delta).count() > communication_timeout_ms_) { break; }
    }
    return ((error_code != TEST_ERROR_NONE) ? error_code :
            (num_pending == 0) ? TEST_ERROR_NONE :
            TEST_ERROR_RECV_WAIT_TIMEOUT);
}

/**
 * FSM functionality: SEND methods.
 */
test_error_code_t orchestrator::run_state_init() {
    assert(fragments_.empty()); // Sanity checks
    assert(state_ == state_t::STATE_INIT);

    // Pick a random nonce for this test session
    session_nonce_ = std::rand() % std::numeric_limits<uint16_t>::max();
    pcap_subscriptions_.resize(topology_.size(), false);
    client_netaddrs_.resize(topology_.size());

    if (!autotest_mode_) { // Info
        std::cout << "[Orchestrator] Started listening on port "
                  << PORT_LISTEN_CTRL << " with session nonce "
                  << session_nonce_ << std::endl;
    }
    return TEST_ERROR_NONE;
}

test_error_code_t
orchestrator::run_state_setup_ctrl() {
    assert(fragments_.empty()); // Sanity checks
    assert(state_ == state_t::STATE_SETUP_CTRL);

    // Ctrl server address
    struct sockaddr_in ctrl_netaddr;
    memset(&ctrl_netaddr, 0, sizeof(ctrl_netaddr));
    ctrl_netaddr.sin_family = AF_INET;
    ctrl_netaddr.sin_port = htons(PORT_LISTEN_CTRL);
    ctrl_netaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    auto error_code = harness_server_setup(&listen_fd_ctrl_, &ctrl_netaddr,
                                           topology_.size(), true);
    if (error_code != TEST_ERROR_NONE) { return error_code; }

    // Next, launch a helper thread to accept new connections
    int rc = 0;
    uint16_t num_accepted = 0;
    auto states = new struct harness_accepted_state[topology_.size()];
    std::thread accept_thread(harness_accept_with_timeout, listen_fd_ctrl_,
                              connect_timeout_ms_, topology_.size(),
                              &num_accepted, states, &rc);
    bool success = true;
    if (autotest_mode_ == 1) {
        // If we're in autotest mode, fork and exec the fragment processes
        for (size_t idx = 0; (idx < topology_.size()) && success; idx++) {
            pid_t pid = fork(); // Clone the current process
            if (pid < 0) {
                success = false;
            }
            else if (pid == 0) {
                // Child process
                auto listen_port = std::to_string(PORT_LISTEN_CTRL);
                auto session_nonce = std::to_string(session_nonce_);
                auto node_path = fragment_dir_ + "/node";
                auto fragment_id = std::to_string(idx);
                char *const argv_list[] = {
                    const_cast<char*>(node_path.c_str()), // 0: Executable path
                    const_cast<char*>("127.0.0.1"), // 1: Server IP (Loopback)
                    const_cast<char*>(listen_port.c_str()), // 2: Server port
                    const_cast<char*>(fragment_id.c_str()), // 3: Fragment ID
                    const_cast<char*>(session_nonce.c_str()), // 4: Nonce
                    const_cast<char*>("-a"), // 5: Use autotest mode
                    NULL
                };

                execv(node_path.c_str(), argv_list);
                exit(EXIT_FAILURE);
            }
            else {
                // Parent process
                fragments_.push_back(fragment_metadata());
                fragments_[idx].pid = pid;
            }
        }
    }
    else { fragments_.resize(topology_.size()); }
    accept_thread.join();

    // Exit on error
    if (!success) {
        delete [] states;
        return TEST_ERROR_FORK_FAILED;
    }
    else if (rc != 0) {
        delete [] states;
        return TEST_ERROR_SOCKET_ACCEPT_FAILED;
    }
    else if (num_accepted != topology_.size()) {
        delete [] states;
        return TEST_ERROR_SOCKET_ACCEPT_TIMEOUT;
    }
    // Wait a little for the child processes to get scheduled. If one or more
    // children die during this probationary period, something went wrong and
    // the orchestrator should force-quit; else, continue as usual (we assume
    // that if something had to go wrong, it already did).
    // sleep(1);
    // for (size_t idx = 0; idx < fragments_.size(); idx++) {
    //     if (waitpid(fragments_[idx].pid, NULL, WNOHANG) != 0) {
    //         delete [] states;
    //         return TEST_ERROR_EXEC_FAILED;
    //     }
    // }
    // Sanity check
    assert(topology_.size() == fragments_.size());

    // If everything is OK so far, wait for fragments to perform handshakes on
    // the ctrl overlay. We will use fragments' messages to map local ctrl fds
    // (returned by harness_accept_with_timeout) to fragment IDs.
    std::vector<int> fds;
    for (size_t idx = 0; idx < fragments_.size(); idx++) {
        fds.push_back(states[idx].connection_fd);
    }
    delete [] states;

    auto lambda = [this, fds] (size_t idx, void *p) {
        auto payload = reinterpret_cast<
            struct test_response_setup_overlay*>(p);

        // Ensure that the fragment ID is valid
        if (payload->fragment_id >= fragments_.size()) {
            return TEST_ERROR_BAD_FRAGMENT_ID;
        }
        // Ensure that no two fragments claim to have the same ID
        else if (fragments_[payload->fragment_id].fd_ctrl != -1) {
            return TEST_ERROR_BAD_FRAGMENT_ID;
        }
        fragments_[payload->fragment_id].fd_ctrl = fds[idx];
        return TEST_ERROR_NONE;
    };
    // Test connectivity on the ctrl overlay
    error_code = foreach_fragment_recv_generic(
        false, fds, TEST_MESSAGE_SETUP_CTRL, lambda);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    // Complete handshake
    return foreach_fragment_send_ctrl(TEST_MESSAGE_SETUP_CTRL,
                                      [this] (size_t, void *) {});
}

test_error_code_t
orchestrator::run_state_setup_pcap() {
    assert(state_ == state_t::STATE_SETUP_PCAP);
    assert(fragments_.size() == topology_.size());

    // Pcap server address
    struct sockaddr_in pcap_netaddr;
    memset(&pcap_netaddr, 0, sizeof(pcap_netaddr));
    pcap_netaddr.sin_family = AF_INET;
    pcap_netaddr.sin_port = htons(PORT_LISTEN_PCAP);
    pcap_netaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Setup the pcap socket
    auto error_code = harness_server_setup(&listen_fd_pcap_, &pcap_netaddr,
                                           topology_.size(), true);
    if (error_code != TEST_ERROR_NONE) { return error_code; }

    // Send a ctrl message to every fragment to setup the pcap overlay
    error_code = foreach_fragment_send_ctrl(TEST_MESSAGE_SETUP_PCAP,
        [this, pcap_netaddr] (size_t, void *p) {
        auto payload = reinterpret_cast<
            struct test_request_setup_pcap*>(p);

        // Populate the message payload
        payload->pcap_netaddr = pcap_netaddr;
    });
    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }

    // Wait for every fragment to acknowledge pcap overlay setup
    error_code = foreach_fragment_recv_ctrl(TEST_MESSAGE_SETUP_PCAP,
                                            [this] (size_t, void *) {
                                            return TEST_ERROR_NONE; });
    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }

    // Accept connections
    int rc = 0;
    uint16_t num_accepted = 0;
    auto states = new struct harness_accepted_state[topology_.size()];
    harness_accept_with_timeout(listen_fd_pcap_, communication_timeout_ms_,
                                topology_.size(), &num_accepted, states, &rc);
    // Exit on error
    if (rc != 0) {
        delete [] states;
        return TEST_ERROR_SOCKET_ACCEPT_FAILED;
    }
    else if (num_accepted != topology_.size()) {
        delete [] states;
        return TEST_ERROR_SOCKET_ACCEPT_TIMEOUT;
    }

    // If everything is OK so far, wait for fragments to perform handshakes on
    // the pcap overlay. We will use fragments' messages to map local pcap fds
    // (returned by harness_accept_with_timeout) to fragment IDs.
    std::vector<int> fds;
    for (size_t idx = 0; idx < fragments_.size(); idx++) {
        fds.push_back(states[idx].connection_fd);
    }
    delete [] states;

    auto lambda = [this, fds] (size_t idx, void *p) {
        auto payload = reinterpret_cast<
            struct test_response_setup_overlay*>(p);

        // Ensure that the packet's fragment ID is valid
        if (payload->fragment_id >= fragments_.size()) {
            return TEST_ERROR_BAD_FRAGMENT_ID;
        }
        // Ensure that no two fragments claim to have the same ID
        else if (fragments_[payload->fragment_id].fd_pcap != -1) {
            return TEST_ERROR_BAD_FRAGMENT_ID;
        }
        fragments_[payload->fragment_id].fd_pcap = fds[idx];
        return TEST_ERROR_NONE;
    };
    // Test connectivity on the pcap overlay
    error_code = foreach_fragment_recv_generic(
        false, fds, TEST_MESSAGE_SETUP_PCAP, lambda);

    if (error_code != TEST_ERROR_NONE) {
        return error_code;
    }
    // Complete handshake
    for (size_t idx = 0; idx < fragments_.size(); idx++) {
        fds[idx] = fragments_[idx].fd_pcap;
    }
    return foreach_fragment_send_generic(fds, TEST_MESSAGE_SETUP_PCAP,
                                         [this] (size_t, void *) {});
}

test_error_code_t
orchestrator::run_state_create_topology() {
    assert(state_ == state_t::STATE_CREATE_TOPOLOGY);
    auto error_code = TEST_ERROR_NONE; // Return value
    assert(fragments_.size() == topology_.size()); // Sanity check

    auto lambda = [this] (size_t idx, void *p) {
        auto payload = reinterpret_cast<struct test_request_topology*>(p);

        // Populate the message payload
        payload->mixaddr = mixaddrs_[idx];
        payload->num_neighbors = topology_[idx].size();
        for (size_t nid = 0; nid < topology_[idx].size(); nid++) {
            payload->neighbor_mixaddrs[nid] = mixaddrs_[topology_[idx][nid]];
        }
        // Mixnet node configuration
        payload->mixing_factor = mixing_factors_[idx];
        payload->use_random_routing = use_random_routing_[idx];
        payload->reelection_interval_ms = reelection_interval_ms_;
        payload->root_hello_interval_ms = root_hello_interval_ms_;
    };
    // Send the message to every fragment
    error_code = foreach_fragment_send_ctrl(TEST_MESSAGE_TOPOLOGY, lambda);

    // Wait for acknowledgement
    if (error_code == TEST_ERROR_NONE) {
        error_code = foreach_fragment_recv_ctrl(
            TEST_MESSAGE_TOPOLOGY,
            [this] (size_t, void*) { return TEST_ERROR_NONE; });
    }
    return error_code;
}

test_error_code_t
orchestrator::run_state_start_mixnet_server() {
    auto error_code = TEST_ERROR_NONE; // Return value
    assert(state_ == state_t::STATE_START_MIXNET_SERVER);

    // Send the message to every fragment
    error_code = foreach_fragment_send_ctrl(TEST_MESSAGE_START_MIXNET_SERVER,
                                            [this] (size_t, void*) {});

    auto lambda = [this] (size_t idx, void *p) {
        auto payload = reinterpret_cast<struct
            test_response_start_mixnet_server*>(p);

        // No neighbors, nothing to do
        if (topology_[idx].empty()) {
            return TEST_ERROR_NONE;
        }
        // Invalid server address
        else if ((payload->server_netaddr.sin_family != AF_INET) ||
                 (payload->server_netaddr.sin_addr.s_addr == 0) ||
                 (payload->server_netaddr.sin_port == 0)) {
            return TEST_ERROR_FRAGMENT_INVALID_SADDR;
        }
        fragments_[idx].mixnet_server_netaddr = payload->server_netaddr;
        return TEST_ERROR_NONE;
    };
    // Wait for acknowledgement
    if (error_code == TEST_ERROR_NONE) {
        error_code = foreach_fragment_recv_ctrl(
            TEST_MESSAGE_START_MIXNET_SERVER, lambda);
    }
    return error_code;
}

test_error_code_t
orchestrator::run_state_start_mixnet_clients() {
    auto error_code = TEST_ERROR_NONE; // Return value
    assert(state_ == state_t::STATE_START_MIXNET_CLIENTS);

    auto send_lambda = [this] (size_t idx, void *p) {
        auto payload = reinterpret_cast<struct
            test_request_start_mixnet_clients*>(p);

        // Populate the message payload
        payload->num_neighbors = topology_[idx].size();
        for (size_t nid = 0; nid < topology_[idx].size(); nid++) {
            payload->neighbor_server_netaddrs[nid] = fragments_[
                topology_[idx][nid]].mixnet_server_netaddr;
        }
    };
    // Send the message to every fragment
    error_code = foreach_fragment_send_ctrl(
        TEST_MESSAGE_START_MIXNET_CLIENTS, send_lambda);

    auto recv_lambda = [this] (size_t idx, void *p) {
        auto payload = reinterpret_cast<struct
            test_response_start_mixnet_clients*>(p);

        // Incorrect neighbor count
        if (payload->num_neighbors != topology_[idx].size()) {
            return TEST_ERROR_FRAGMENT_BAD_NEIGHBOR_COUNT;
        }
        else {
            for (size_t nid = 0; nid < topology_[idx].size(); nid++) {
                // Invalid client address
                if ((payload->client_netaddrs[nid].sin_family != AF_INET) ||
                    (payload->client_netaddrs[nid].sin_addr.s_addr == 0) ||
                    (payload->client_netaddrs[nid].sin_port == 0)) {
                    return TEST_ERROR_FRAGMENT_INVALID_SADDR;
                }
                client_netaddrs_[idx].push_back(payload->client_netaddrs[nid]);
            }
        }
        return TEST_ERROR_NONE;
    };
    // Wait for acknowledgement
    if (error_code == TEST_ERROR_NONE) {
        error_code = foreach_fragment_recv_ctrl(
            TEST_MESSAGE_START_MIXNET_CLIENTS, recv_lambda);
    }
    return error_code;
}

test_error_code_t
orchestrator::run_state_resolve_mixnet_connections() {
    auto error_code = TEST_ERROR_NONE; // Return value
    assert(state_ == state_t::STATE_RESOLVE_MIXNET_CONNECTIONS);

    auto lambda = [this] (size_t idx, void *p) {
        auto payload = reinterpret_cast<
            struct test_request_resolve_mixnet_connections*>(p);

        // For each neighbor, find the client netaddress
        // it uses to communicate with this Mixnet node.
        payload->num_neighbors = topology_[idx].size();
        for (size_t i = 0; i < topology_[idx].size(); i++) {

            bool success = false;
            uint16_t fragment_id = topology_[idx][i];
            for (size_t j = 0; j < topology_[fragment_id].size(); j++) {
                // This node is {fragment_id}'s j'th neighbor
                if (topology_[fragment_id][j] == idx) {
                    payload->neighbor_client_netaddrs[i] = (
                        client_netaddrs_[fragment_id][j]);

                    success = true; break;
                }
            }
            // Sanity check: Ensure that each pair of nodes
            // has a consistent adjacency relationship.
            assert(success);
        }
    };
    // Send the message to every fragment
    error_code = foreach_fragment_send_ctrl(
        TEST_MESSAGE_RESOLVE_MIXNET_CONNS, lambda);

    // Wait for acknowledgement
    if (error_code == TEST_ERROR_NONE) {
        error_code = foreach_fragment_recv_ctrl(
            TEST_MESSAGE_RESOLVE_MIXNET_CONNS,
            [this] (size_t, void*) { return TEST_ERROR_NONE; });
    }
    return error_code;
}

test_error_code_t
orchestrator::run_state_start_testcase() {
    assert(state_ == state_t::STATE_START_TESTCASE);
    auto error_code = TEST_ERROR_NONE; // Return value
    error_code = foreach_fragment_send_ctrl(TEST_MESSAGE_START_TESTCASE,
                                            [this] (size_t, void *) {});
    if (error_code == TEST_ERROR_NONE) {
        error_code = foreach_fragment_recv_ctrl(TEST_MESSAGE_START_TESTCASE,
                                                [this] (size_t, void*) {
                                                return TEST_ERROR_NONE; });
    }
    return error_code;
}

test_error_code_t
orchestrator::run_state_end_testcase() {
    assert(state_ == state_t::STATE_END_TESTCASE);
    auto error_code = TEST_ERROR_NONE; // Return value
    error_code = foreach_fragment_send_ctrl(TEST_MESSAGE_END_TESTCASE,
                                            [this] (size_t, void *) {});
    if (error_code == TEST_ERROR_NONE) {
        error_code = foreach_fragment_recv_ctrl(TEST_MESSAGE_END_TESTCASE,
                                                [this] (size_t, void*) {
                                                return TEST_ERROR_NONE; });
    }
    return error_code;
}

test_error_code_t
orchestrator::run_state_graceful_shutdown() {
    assert(state_ == state_t::STATE_GRACEFUL_SHUTDOWN);

    // Send the message to every fragment
    foreach_fragment_send_ctrl(TEST_MESSAGE_SHUTDOWN,
                               [this] (size_t, void*) {});

    auto lambda = [this] (size_t idx, void*) {
        fragments_[idx].pid = -1;
        return TEST_ERROR_NONE;
    };
    // Wait for acknowledgement
    return foreach_fragment_recv_ctrl(TEST_MESSAGE_SHUTDOWN, lambda);
}

/**
 * FSM functionality: ORCHESTRATOR methods.
 */
void orchestrator::run_state_forceful_shutdown() {
    assert(state_ == state_t::STATE_FORCEFUL_SHUTDOWN);

    // If graceful shutdown was unsuccessful, we don't know what
    // state the fragments are in. As such, we issue SIGKILL for
    // all fragment processes.
    destroy_fragments(SIGKILL);
}

void orchestrator::run_state_reset() {
    // Reset the orchestrator's internal state
    assert(state_ == state_t::STATE_RESET);
    destroy_sockets(); // Note: Sockets must be destroyed first
                       // before wiping other networking state!

    pcap_thread_error_ = TEST_ERROR_NONE;
    pcap_subscriptions_.clear();
    pcap_thread_run_ = true;

    use_random_routing_.clear();
    mixing_factors_.clear();
    mixaddrs_.clear();

    client_netaddrs_.clear();
    listen_fd_ctrl_ = -1;
    listen_fd_pcap_ = -1;
    fragments_.clear();
    topology_.clear();
}

/**
 * Pcap loop.
 */
void orchestrator::pcap_thread_loop() {
    auto error_code = TEST_ERROR_NONE;
    auto *header = reinterpret_cast<
        struct test_message_header*>(pcap_message_buffer_);

    auto *packet = reinterpret_cast<struct mixnet_packet*>(
        pcap_message_buffer_ + sizeof(struct test_message_header));

    while (pcap_thread_run_ && (error_code == TEST_ERROR_NONE)) {
        for (size_t idx = 0; idx < fragments_.size(); idx++) {
            // Ignore fragments to which we're not subscribed
            if (!pcap_subscriptions_[idx]) { continue; }

            // Attempt to receive a message (with zero timeout)
            error_code = harness_recv_with_timeout(fragments_[idx].fd_pcap,
                                                   0, pcap_message_buffer_,
                                                   MAX_TEST_MESSAGE_SIZE,
                                                   session_nonce_);
            // Received a message
            if (error_code == TEST_ERROR_NONE) {
                // Validate the message header
                error_code = check_header(pcap_message_buffer_, true,
                                          idx, TEST_MESSAGE_PCAP_DATA);

                if (error_code != TEST_ERROR_NONE) { break; }
                const size_t total_size = (sizeof(struct mixnet_packet) +
                                            packet->payload_size);

                if (total_size > MAX_MIXNET_PACKET_SIZE) {
                    // We perform several layers of filtering for malformed
                    // packets before this, so really shouldn't reach here.
                    error_code = TEST_ERROR_MIXNET_INVALID_PACKET_SIZE;
                    break;
                }
                // Valid packet, invoke callback
                cb_pcap_data_(this, header, packet);
            }
            // Receive timed-out, clear error
            else if (error_code == TEST_ERROR_RECV_WAIT_TIMEOUT) {
                error_code = TEST_ERROR_NONE;
            }
            // Irrecoverable error
            else { break; }
        }
        // Update the thread's error status
        pcap_thread_error_ = error_code;
    }
}

/**
 * Main loop.
 */
void orchestrator::run() {
    // TODO(natre): Check topology
    if (!cb_testcase_ || !cb_pcap_data_) {
        std::cout << "[Orchestrator] Testcase error: Testcase and packet "
                  << "capture callbacks must both be set." << std::endl;
        return;
    }
    if (topology_.size() != mixaddrs_.size()) {
        std::cout << "[Orchestrator] Testcase error: Topology and "
                  << "mixaddrs size do not match." << std::endl;
    }

    bool done = false;
    bool show_errors = true;
    state_ = state_t::STATE_INIT;
    test_error_code_t error_code = TEST_ERROR_NONE;

    while (!done) {
        switch (state_) {
        // Init
        case state_t::STATE_INIT: {
            error_code = run_state_init();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_SETUP_CTRL :
                      state_t::STATE_FORCEFUL_SHUTDOWN;
        } break;

        // Setup ctrl overlay
        case state_t::STATE_SETUP_CTRL: {
            error_code = run_state_setup_ctrl();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_SETUP_PCAP :
                      state_t::STATE_FORCEFUL_SHUTDOWN;
        } break;

        // Setup pcap overlay
        case state_t::STATE_SETUP_PCAP: {
            error_code = run_state_setup_pcap();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_CREATE_TOPOLOGY :
                      state_t::STATE_GRACEFUL_SHUTDOWN;
        } break;

        // Create test topology
        case state_t::STATE_CREATE_TOPOLOGY: {
            error_code = run_state_create_topology();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_START_MIXNET_SERVER :
                      state_t::STATE_GRACEFUL_SHUTDOWN;
        } break;

        // Start server loops
        case state_t::STATE_START_MIXNET_SERVER: {
            error_code = run_state_start_mixnet_server();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_START_MIXNET_CLIENTS :
                      state_t::STATE_GRACEFUL_SHUTDOWN;
        } break;

        // Start client loops
        case state_t::STATE_START_MIXNET_CLIENTS: {
            error_code = run_state_start_mixnet_clients();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_RESOLVE_MIXNET_CONNECTIONS :
                      state_t::STATE_GRACEFUL_SHUTDOWN;
        } break;

        // Start Mixnet connection resolution
        case state_t::STATE_RESOLVE_MIXNET_CONNECTIONS: {
            error_code = run_state_resolve_mixnet_connections();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_START_TESTCASE :
                      state_t::STATE_GRACEFUL_SHUTDOWN;
        } break;

        // Start test-case
        case state_t::STATE_START_TESTCASE: {
            error_code = run_state_start_testcase();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_RUN_TESTCASE :
                      state_t::STATE_END_TESTCASE;
        } break;

        // Run test-case
        case state_t::STATE_RUN_TESTCASE: {
            pcap_thread_ = std::thread(
                &orchestrator::pcap_thread_loop, this);

            cb_testcase_(this); // Callback
            pcap_thread_run_ = false;
            pcap_thread_.join();

            state_ = state_t::STATE_END_TESTCASE;
        } break;

        // End test-case
        case state_t::STATE_END_TESTCASE: {
            error_code = run_state_end_testcase();
            state_ = state_t::STATE_GRACEFUL_SHUTDOWN;
        } break;

        // Perform graceful shutdown
        case state_t::STATE_GRACEFUL_SHUTDOWN: {
            error_code = run_state_graceful_shutdown();
            state_ = (error_code == TEST_ERROR_NONE) ?
                      state_t::STATE_RESET :
                      state_t::STATE_FORCEFUL_SHUTDOWN;

            if (cb_exit_code_) { cb_exit_code_(error_code); }
        } break;

        // Butcher everything
        case state_t::STATE_FORCEFUL_SHUTDOWN: {
            error_code = TEST_ERROR_NONE;
            run_state_forceful_shutdown();
            state_ = state_t::STATE_RESET;
        } break;

        // Set up for the next test-case
        case state_t::STATE_RESET: {
            run_state_reset();
            done = true; // Finished run
            error_code = TEST_ERROR_NONE;
        } break;
        } // switch

        // Debug
        if (show_errors && (error_code != TEST_ERROR_NONE)) {
            std::cout << "[Orchestrator] Error code "
                      << error_code << std::endl;
            show_errors = false;
        }
    }
    // Debug
    std::cout << "[Orchestrator] Exiting normally" << std::endl;
}

/**
 * Public API.
 */
void orchestrator::configure(int argc, char **argv) {
    fragment_dir_ = std::filesystem::path(argv[0]).parent_path();
    communication_timeout_ms_ = DEFAULT_WAIT_TIME_MS;
    connect_timeout_ms_ = DEFAULT_WAIT_TIME_MS;

    int c; autotest_mode_ = 0; // Parse command-line args
    while ((c = getopt(argc, argv, "a")) != -1) {
        switch (c) {
        case 'a': { autotest_mode_ = 1; } break;
        default: break;
        }
    }
    // Use large timeouts in manual mode
    if (!autotest_mode_) {
        communication_timeout_ms_ = 5000; // 5 seconds
        connect_timeout_ms_ = 30 * 60 * 1000; // 30 minutes
    }
}

void orchestrator::set_topology(
    const std::vector<mixnet_address>& mixaddrs,
    const std::vector<std::vector<uint16_t>>& topology) {
    topology_ = topology;
    mixaddrs_ = mixaddrs;
    mixing_factors_.resize(topology.size(), 1);
    use_random_routing_.resize(topology.size(), false);
}

void orchestrator::register_cb_testcase(
    std::function<void(orchestrator*)> cb) {
    cb_testcase_ = cb;
}

void orchestrator::register_cb_pcap(std::function<void(orchestrator*,
    struct test_message_header*, struct mixnet_packet*)> cb) {
    cb_pcap_data_ = cb;
}

void orchestrator::register_cb_retcode(
    std::function<void(test_error_code_t)> cb) {
    cb_exit_code_ = cb;
}

void orchestrator::set_mixing_factor(
    const uint16_t idx, const uint16_t factor) {
    assert(idx < mixing_factors_.size());
    mixing_factors_[idx] = factor;
}
void orchestrator::set_use_random_routing(
    const uint16_t idx, const bool value) {
    assert(idx < use_random_routing_.size());
    use_random_routing_[idx] = value;
}
void orchestrator::set_root_hello_interval_ms(
    const uint32_t root_hello_interval_ms) {
    root_hello_interval_ms_ = root_hello_interval_ms;
}
void orchestrator::set_reelection_interval_ms(
    const uint32_t reelection_interval_ms) {
    reelection_interval_ms_ = reelection_interval_ms;
}

test_error_code_t orchestrator::pcap_change_subscription(
    const uint16_t idx, const bool subscribe) {
    assert(state_ == state_t::STATE_RUN_TESTCASE);

    if (pcap_subscriptions_[idx] == subscribe) {
        // No change in subscription, return
        return TEST_ERROR_NONE;
    }
    pcap_subscriptions_[idx] = subscribe;
    // Lambda to populate the message payload
    auto lambda = [this, subscribe] (void *p) {
        auto payload = reinterpret_cast<struct
            test_request_pcap_subscription*>(p);

        payload->subscribe = subscribe;
    };
    return fragment_request_response(
        idx, lambda, TEST_MESSAGE_PCAP_SUBSCRIPTION);
}

test_error_code_t
orchestrator::change_link_state(const uint16_t idx_a,
                                const uint16_t idx_b,
                                const bool is_enabled) {
    assert(state_ == state_t::STATE_RUN_TESTCASE);
    size_t b_nid_in_a = 0, a_nid_in_b = 0;
    bool success[2] {false, false};

    assert((idx_a < topology_.size()) && (idx_b < topology_.size()));
    for (size_t nid = 0; nid < topology_[idx_a].size(); nid++) {
        if (topology_[idx_a][nid] == idx_b) {
            b_nid_in_a = nid; success[0] = true;
            break;
        }
    }
    for (size_t nid = 0; nid < topology_[idx_b].size(); nid++) {
        if (topology_[idx_b][nid] == idx_a) {
            a_nid_in_b = nid; success[1] = true;
            break;
        }
    }
    if (!success[0] || !success[1]) {
        std::cout << "[Orchestrator] Improper adjacency relationship "
                  << "between nodes " << idx_a << " and " << idx_b
                  << ", please check topology" << std::endl;

        return TEST_ERROR_BAD_TESTCASE;
    }
    // Lambdas to populate the payloads
    auto lambda_a = [this, b_nid_in_a, is_enabled] (void *p) {
        auto payload = reinterpret_cast<struct
            test_request_change_link_state*>(p);

        payload->neighbor_id = b_nid_in_a;
        payload->state = is_enabled;
    };
    auto lambda_b = [this, a_nid_in_b, is_enabled] (void *p) {
        auto payload = reinterpret_cast<struct
            test_request_change_link_state*>(p);

        payload->neighbor_id = a_nid_in_b;
        payload->state = is_enabled;
    };
    auto error_code = TEST_ERROR_NONE;
    error_code = fragment_request_response(
        idx_a, lambda_a, TEST_MESSAGE_CHANGE_LINK_STATE);

    if (error_code == TEST_ERROR_NONE) {
        error_code = fragment_request_response(
            idx_b, lambda_b, TEST_MESSAGE_CHANGE_LINK_STATE);
    }
    return error_code;
}

test_error_code_t
orchestrator::send_packet(const uint16_t src_idx,
                          const uint16_t dst_idx,
                          const mixnet_packet_type_t type,
                          const std::string data_string) {
    assert(state_ == state_t::STATE_RUN_TESTCASE);
    if (data_string.size() >= MAX_TEST_MESSAGE_DATA) {
        std::cout << "[Orchestrator] Payload data should be "
                  << "smaller than " << MAX_TEST_MESSAGE_DATA
                  << " bytes" << std::endl;

        return TEST_ERROR_BAD_TESTCASE;
    }

    // Lambda to populate the message payload
    auto lambda = [this, src_idx, dst_idx,
        type, data_string] (void *p) {
        auto payload = reinterpret_cast<
            struct test_request_send_packet*>(p);

        payload->type = type;
        payload->src_mixaddr = mixaddrs_[src_idx];
        payload->dst_mixaddr = mixaddrs_[dst_idx];
        memcpy(payload->data, data_string.c_str(),
               data_string.size());

        payload->data_size = data_string.size();
    };
    return fragment_request_response(
        src_idx, lambda, TEST_MESSAGE_SEND_PACKET);
}

/**
 * Constructor/Destructor.
 */
orchestrator::orchestrator() {
    // Register signal handler
    signal(SIGPIPE, SIG_IGN);

    // Randomness
    srand(time(NULL));

    // Allocate the scratchpad message buffers
    ctrl_message_buffer_ = new char[MAX_TEST_MESSAGE_SIZE];
    assert(reinterpret_cast<size_t>(ctrl_message_buffer_) % 8 == 0);

    pcap_message_buffer_ = new char[MAX_TEST_MESSAGE_SIZE];
    assert(reinterpret_cast<size_t>(pcap_message_buffer_) % 8 == 0);
}

orchestrator::~orchestrator() {
    delete [] pcap_message_buffer_;
    delete [] ctrl_message_buffer_;
}

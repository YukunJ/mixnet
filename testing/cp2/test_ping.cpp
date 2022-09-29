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
#include "test_common.h"
#include "harness/orchestrator.h"

#include <iostream>
#include <stdlib.h>
#include <unistd.h>

static int pcap_count = 0;
static bool pcap_check_success = true;
static std::vector<size_t> received(8, 0);
static test_error_code_t retcode = TEST_ERROR_NONE;
static std::vector<mixnet_address> mixaddrs{15, 13, 11, 9, 72, 84, 2, 42};

static std::vector<mixnet_address> expected_route_req{13, 11, 9, 72, 84, 2};
static std::vector<mixnet_address> expected_route_rsp{2, 84, 72, 9, 11, 13};

void pcap(orchestrator* orchestrator,
          struct test_message_header* header,
          struct mixnet_packet* packet) {
    (void) orchestrator;

    if (packet->type == PACKET_TYPE_PING) {
        auto rh = reinterpret_cast<struct
            mixnet_packet_routing_header*>(packet + 1);

        int src_idx = get_index(packet->src_address, mixaddrs);
        if (header->fragment_id == 7) {
            pcap_check_success &= (src_idx == 0);
            pcap_check_success &= check_route(
                rh, expected_route_req.data(), 6);
        }
        else if (header->fragment_id == 0) {
            pcap_check_success &= (src_idx == 7);
            pcap_check_success &= check_route(
                rh, expected_route_rsp.data(), 6);
        }
        else { pcap_check_success = false; }
        pcap_check_success &= (packet->dst_address ==
                               mixaddrs[header->fragment_id]);

        pcap_check_success &= (received[src_idx] == 0);
        if (pcap_check_success) { received[src_idx]++; }

        pcap_count++;
    }
}

/**
 * This test-case exercises shortest-path routing (with no mixing)
 * in a line topology with 8 Mixnet nodes. We subscribe to packet
 * updates from every node, then send a PING packet using a single
 * node as source.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP and link-state convergence
    auto error_code = TEST_ERROR_NONE;

    // Get packets from all nodes
    for (uint16_t i = 0; i < 8; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Send a PING packet
    DIE_ON_ERROR(orchestrator->send_packet(0, 7, PACKET_TYPE_PING));
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<std::vector<mixnet_address>> topology;
    create_line_topology(8, topology);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);

    std::cout << "[Test] Starting test_ping..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    bool success = ((pcap_count == 2) && pcap_check_success);
    std::cout << (success ? "PASS" : "FAIL") << std::endl;
}

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
static std::vector<size_t> received(7, 0);
static test_error_code_t retcode = TEST_ERROR_NONE;
static std::vector<mixnet_address> mixaddrs{15, 31, 12, 0, 81, 21, 42};
static std::vector<std::string> data{"Never", "gonna", "give", "you", "up",
                                     "Never", "gonna", "let", "you", "down"};

static std::vector<mixnet_address> expected_route_0{42, 21};
static std::vector<mixnet_address> expected_route_1{12, 0};

void pcap(orchestrator* orchestrator,
          struct test_message_header* header,
          struct mixnet_packet* packet) {
    (void) orchestrator;

    if (packet->type == PACKET_TYPE_DATA) {
        auto rh = reinterpret_cast<struct
            mixnet_packet_routing_header*>(packet + 1);

        pcap_check_success &= (header->fragment_id == 4);
        int src_idx = get_index(packet->src_address, mixaddrs);
        pcap_check_success &= ((src_idx == 0) || (src_idx == 1));
        pcap_check_success &= (packet->dst_address == mixaddrs[4]);

        pcap_check_success &= (received[src_idx] == 0);
        if (pcap_check_success) { received[src_idx]++; }

        pcap_check_success &= (
            (src_idx == 0) ? check_route(rh, expected_route_0.data(), 2) :
            (src_idx == 1) ? check_route(rh, expected_route_1.data(), 2) :
            false
        );
        pcap_check_success &= check_data(packet, data[src_idx]);
        pcap_count++;
    }
}

/**
 * This test-case exercises shortest-path routing (with no mixing)
 * in a ring topology with 7 Mixnet nodes. We subscribe to packet
 * updates from every node, then send DATA packets using a subset
 * of nodes as source.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP and link-state convergence
    auto error_code = TEST_ERROR_NONE;

    // Get packets from all nodes
    for (uint16_t i = 0; i < 7; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Try 2 nodes as source
    DIE_ON_ERROR(orchestrator->send_packet(0, 4, PACKET_TYPE_DATA, data[0]));
    DIE_ON_ERROR(orchestrator->send_packet(1, 4, PACKET_TYPE_DATA, data[1]));
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<std::vector<mixnet_address>> topology;
    create_ring_topology(7, topology);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);

    std::cout << "[Test] Starting test_sp_data_ring..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    bool success = ((pcap_count == 2) && pcap_check_success);
    std::cout << (success ? "PASS" : "FAIL") << std::endl;
}

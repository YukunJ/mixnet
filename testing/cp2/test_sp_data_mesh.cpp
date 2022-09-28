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
static test_error_code_t retcode = TEST_ERROR_NONE;
static std::vector<mixnet_address> mixaddrs {13, 14, 15, 42, 4, 23, 98};
static std::vector<std::string> data{"Never", "gonna", "give", "you", "up",
                                     "Never", "gonna", "let", "you", "down"};

static std::vector<mixnet_address> expected_route{15, 14};

void pcap(orchestrator* orchestrator,
          struct test_message_header* header,
          struct mixnet_packet* packet) {
    (void) orchestrator;

    if (packet->type == PACKET_TYPE_DATA) {
        auto rh = reinterpret_cast<struct
            mixnet_packet_routing_header*>(packet + 1);

        pcap_check_success &= (header->fragment_id == 6);
        pcap_check_success &= (packet->dst_address == mixaddrs[6]);

        int src_idx = get_index(packet->src_address, mixaddrs);
        pcap_check_success &= (src_idx == 0);

        pcap_check_success &= check_route(rh, expected_route.data(), 2);
        pcap_check_success &= check_data(packet, data[src_idx]);
        pcap_count++;
    }
}

/**
 * This test-case exercises shortest-path routing (with no mixing)
 * in a mesh topology with 7 Mixnet nodes. We subscribe to packet
 * updates from every node, then send DATA packets using a single
 * node as source. Checks if ties are broken based on hop address.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP and link-state convergence
    auto error_code = TEST_ERROR_NONE;

    // Get packets from all nodes
    for (uint16_t i = 0; i < 7; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Send a few packets
    for (size_t idx = 0; idx < 10; idx++) {
        DIE_ON_ERROR(orchestrator->send_packet(
            0, 6, PACKET_TYPE_DATA, data[0]));
    }
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<std::vector<mixnet_address>> topology;
    create_star_topology(5, topology);

    // Create 2 additional nodes
    for (size_t idx = 0; idx < 2; idx++) {
        topology.push_back(std::vector<uint16_t>());
    }
    // Create a secondary star centered at 5
    topology[5].push_back(2);
    topology[2].push_back(5);
    topology[5].push_back(3);
    topology[3].push_back(5);
    topology[5].push_back(4);
    topology[4].push_back(5);
    topology[5].push_back(6);
    topology[6].push_back(5);
    // Form a few more loops
    topology[1].push_back(6);
    topology[6].push_back(1);
    topology[3].push_back(6);
    topology[6].push_back(3);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);

    std::cout << "[Test] Starting test_sp_data_mesh..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    bool success = ((pcap_count == 10) && pcap_check_success);
    std::cout << (success ? "PASS" : "FAIL") << std::endl;
}

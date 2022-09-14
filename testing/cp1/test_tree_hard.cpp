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
static test_error_code_t retcode = TEST_ERROR_NONE;

void pcap(orchestrator* orchestrator,
          struct test_message_header* header,
          struct mixnet_packet* packet) {
    (void) orchestrator;
    (void) header;

    if (packet->type == PACKET_TYPE_FLOOD) {
        pcap_count++;
    }
}

/**
 * This test-case exercises a binary tree topology with 7 Mixnet nodes.
 * We subscribe to packet updates from all the nodes, then send a fixed
 * number of FLOOD packets using every node as src.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP convergence
    auto error_code = TEST_ERROR_NONE;

    // Get packets from all nodes
    for (uint16_t i = 0; i < 7; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Try every node as source
    for (size_t t = 0; t < 5; t++) {
        for (uint16_t idx = 0; idx < 7; idx++) {
            DIE_ON_ERROR(orchestrator->send_packet(
                idx, idx % 3, PACKET_TYPE_FLOOD));
        }
    }
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<mixnet_address> mixaddrs {52, 31, 108, 77, 23, 41, 62};
    std::vector<std::vector<mixnet_address>> topology;
    for (uint16_t i = 0; i < 7; i++) {
        topology.push_back(std::vector<mixnet_address>());
    }
    // Level 1
    topology[0].push_back(1);
    topology[1].push_back(0);
    topology[0].push_back(2);
    topology[2].push_back(0);

    // Level 2
    topology[1].push_back(3);
    topology[3].push_back(1);
    topology[1].push_back(4);
    topology[4].push_back(1);
    topology[2].push_back(5);
    topology[5].push_back(2);
    topology[2].push_back(6);
    topology[6].push_back(2);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);

    std::cout << "[Test] Starting test_tree_hard..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    std::cout << ((pcap_count == (5 * 7 * 6)) ? "PASS" : "FAIL") << std::endl;
}

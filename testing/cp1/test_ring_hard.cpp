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
 * This test-case exercises a ring topology with 8 Mixnet nodes. We
 * subscribe to packet updates from every node, then send one FLOOD
 * packet using a subset of nodes as src.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP convergence
    auto error_code = TEST_ERROR_NONE;

    // Get packets from all nodes
    for (uint16_t i = 0; i < 8; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Try every other node as source
    for (uint16_t i = 0; i < 8; i++) {
        if ((i % 2) == 1) { continue; }
        DIE_ON_ERROR(orchestrator->send_packet(
            i, (i % 4), PACKET_TYPE_FLOOD));
    }
    sleep(5); // Wait for packets to propagate

    // Send a PING packet
    DIE_ON_ERROR(orchestrator->send_packet(0, 4, PACKET_TYPE_PING));
    sleep(5);
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<std::vector<mixnet_address>> topology;
    create_ring_topology(8, topology);

    std::vector<mixnet_address> mixaddrs {0, 1, 2, 3,
                                          4, 5, 6, 7};
    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);

    std::cout << "[Test] Starting test_ring_hard..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    std::cout << ((pcap_count == (4 * 7)) ? "PASS" : "FAIL") << std::endl;
}

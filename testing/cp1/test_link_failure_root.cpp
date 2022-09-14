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
 * This test-case checks whether nodes can recover when
 * the previous root gets disconnected from the network.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP convergence
    auto error_code = TEST_ERROR_NONE;

    // Get packets from all nodes
    for (uint16_t i = 0; i < 7; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Inject a FLOOD packet using the root node as src
    DIE_ON_ERROR(orchestrator->send_packet(3, 0, PACKET_TYPE_FLOOD));
    sleep(5); // Wait for packets to propagate

    // Disconnect the root from the topology
    DIE_ON_ERROR(orchestrator->change_link_state(2, 3, false));
    DIE_ON_ERROR(orchestrator->change_link_state(3, 4, false));
    sleep(5); // Wait for STP re-convergence

    // Inject FLOOD packets into both ends
    DIE_ON_ERROR(orchestrator->send_packet(0, 0, PACKET_TYPE_FLOOD));
    DIE_ON_ERROR(orchestrator->send_packet(6, 0, PACKET_TYPE_FLOOD));
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<mixnet_address> mixaddrs {13, 14, 15, 4, 21, 22, 23};
    std::vector<std::vector<mixnet_address>> topology;
    create_line_topology(7, topology);
    topology[2].push_back(4);
    topology[4].push_back(2);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);
    orchestrator.set_root_hello_interval_ms(100); // 100 ms
    orchestrator.set_reelection_interval_ms(2000); // 1 second

    std::cout << "[Test] Starting test_link_failure_root..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    std::cout << (pcap_count == (6 + (2 * 5)) ? "PASS" : "FAIL") << std::endl;
}

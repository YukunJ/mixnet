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
 * This test-case checks whether nodes can recover
 * when a random link goes down in a ring network.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP convergence
    auto error_code = TEST_ERROR_NONE;

    // Get packets from all nodes
    for (uint16_t i = 0; i < 5; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Inject a few FLOOD packet using the root node as src
    for (size_t t = 0; t < 7; t++) {
        DIE_ON_ERROR(orchestrator->send_packet(3, 0, PACKET_TYPE_FLOOD));
    }
    sleep(5); // Wait for packets to propagate

    // Disconnect a link in the network, creating a line topology
    DIE_ON_ERROR(orchestrator->change_link_state(2, 3, false));
    sleep(5); // Wait for STP re-convergence

    // Inject a few more FLOOD packet using the root node as src
    for (size_t t = 0; t < 7; t++) {
        DIE_ON_ERROR(orchestrator->send_packet(3, 0, PACKET_TYPE_FLOOD));
    }
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<mixnet_address> mixaddrs {13, 14, 15, 4, 21};
    std::vector<std::vector<mixnet_address>> topology;
    create_ring_topology(5, topology);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);
    orchestrator.set_root_hello_interval_ms(100); // 100 ms
    orchestrator.set_reelection_interval_ms(1000); // 1 second

    std::cout << "[Test] Starting test_link_failure_ring..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    std::cout << ((pcap_count == (2 * 7 * 4)) ? "PASS" : "FAIL") << std::endl;
}

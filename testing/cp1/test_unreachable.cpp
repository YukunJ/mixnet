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

void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP convergence
    auto error_code = TEST_ERROR_NONE;
    for (size_t i = 0; i < 3; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Unreachable node as source
    DIE_ON_ERROR(orchestrator->send_packet(3, 0, PACKET_TYPE_FLOOD));
    sleep(5); // Wait for packets to propagate

    for (size_t i = 0; i < 3; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, false));
    }
    DIE_ON_ERROR(orchestrator->pcap_change_subscription(3, true));

    // Unreachable node as sink
    for (size_t i = 0; i < 3; i++) {
        DIE_ON_ERROR(orchestrator->send_packet(i, 0, PACKET_TYPE_FLOOD));
    }
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<std::vector<mixnet_address>> topology;
    std::vector<mixnet_address> mixaddrs {1, 8, 9, 0};
    create_unreachable_topology(4, topology);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);

    std::cout << "[Test] Starting test_unreachable..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    bool success = (pcap_count == 0) && (retcode == TEST_ERROR_NONE);
    std::cout << (success ? "PASS" : "FAIL") << std::endl;
}

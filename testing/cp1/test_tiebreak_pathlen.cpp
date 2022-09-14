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
 * This test-case checks whether nodes perform tie-breaking correctly
 * based on the path length to the root. Since our pcap harness isn't
 * guaranteed to deliver packets in-order, we can't use that to check
 * how the spanning-tree is traversed; instead, we simply disable low-
 * priority links after STP convergence and see if FLOOD packets still
 * propagate through the network OK.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP convergence
    auto error_code = TEST_ERROR_NONE;

    // Disable the low-priority link (should be blocked active anyway)
    DIE_ON_ERROR(orchestrator->change_link_state(0, 4, false));

    // Get packets from all nodes
    for (uint16_t i = 0; i < 5; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Try one end of the ring as source
    DIE_ON_ERROR(orchestrator->send_packet(0, 0, PACKET_TYPE_FLOOD));
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<mixnet_address> mixaddrs {18, 22, 12, 23, 15};
    std::vector<std::vector<mixnet_address>> topology;
    create_ring_topology(5, topology);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);
    // Set a high reelection interval so it never kicks in
    orchestrator.set_reelection_interval_ms(1000000); // 1000s

    std::cout << "[Test] Starting test_tiebreak_pathlen..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    std::cout << ((pcap_count == 4) ? "PASS" : "FAIL") << std::endl;
}

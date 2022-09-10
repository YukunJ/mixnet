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
#include "harness/orchestrator.h"

#include <iostream>
#include <stdlib.h>
#include <unistd.h>

static int pcap_count = 0;
void pcap(orchestrator* orchestrator,
          struct test_message_header* header,
          struct mixnet_packet* packet) {
    (void) orchestrator;
    (void) header;
    (void) packet;

    pcap_count++;
}

#define DIE_ON_ERROR                        \
    if (error_code != TEST_ERROR_NONE) {    \
        std::cout << "FAIL" << std::endl;   \
        return;                             \
    }

void testcase(orchestrator* orchestrator) {
    auto error_code = TEST_ERROR_NONE;

    error_code = orchestrator->pcap_change_subscription(0, true);
    DIE_ON_ERROR

    error_code = orchestrator->pcap_change_subscription(1, true);
    DIE_ON_ERROR

    error_code = orchestrator->pcap_change_subscription(2, true);
    DIE_ON_ERROR

    error_code = orchestrator->pcap_change_subscription(3, true);
    DIE_ON_ERROR

    error_code = orchestrator->send_packet(1, 0, PACKET_TYPE_DATA);
    DIE_ON_ERROR

    error_code = orchestrator->send_packet(2, 0, PACKET_TYPE_DATA);
    DIE_ON_ERROR

    error_code = orchestrator->send_packet(3, 0, PACKET_TYPE_DATA);
    DIE_ON_ERROR

    error_code = orchestrator->send_packet(0, 1, PACKET_TYPE_DATA);
    DIE_ON_ERROR

    error_code = orchestrator->send_packet(0, 2, PACKET_TYPE_DATA);
    DIE_ON_ERROR

    error_code = orchestrator->send_packet(0, 3, PACKET_TYPE_DATA);
    DIE_ON_ERROR
    sleep(1);
}

int main(int argc, char **argv) {
    // Initialize the topology
    std::vector<std::vector<mixnet_address>> topology;
    topology.push_back(std::vector<mixnet_address>());
    topology[0].push_back(1);
    topology[0].push_back(2);
    topology.push_back(std::vector<mixnet_address>());
    topology[1].push_back(0);
    topology.push_back(std::vector<mixnet_address>());
    topology[2].push_back(0);
    topology.push_back(std::vector<mixnet_address>());

    std::vector<mixnet_address> mixaddrs {45, 29, 13, 12};
    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.set_topology(mixaddrs, topology);

    orchestrator.run();
    std::cout << "Number of packets received: "
              << pcap_count << std::endl;
}

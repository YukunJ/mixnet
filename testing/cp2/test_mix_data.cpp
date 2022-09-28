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
static volatile bool expect_packets = false;
static test_error_code_t retcode = TEST_ERROR_NONE;
static std::vector<mixnet_address> mixaddrs{15, 31, 13, 64, 71, 21, 42};
static std::vector<std::string> data{"Never", "gonna", "give", "you", "up",
                                     "Never", "gonna", "let", "you", "down"};

void pcap(orchestrator* orchestrator,
          struct test_message_header* header,
          struct mixnet_packet* packet) {
    (void) orchestrator;

    if (packet->type == PACKET_TYPE_DATA) {
        pcap_check_success &= expect_packets;
        pcap_check_success &= (header->fragment_id >= 4);
        int src_idx = get_index(packet->src_address, mixaddrs);
        pcap_check_success &= ((src_idx != -1) && (src_idx <= 3));
        pcap_check_success &= (mixaddrs[header->fragment_id] ==
                               packet->dst_address);

        pcap_check_success &= (received[header->fragment_id] < 4);
        if (pcap_check_success) { received[header->fragment_id]++; }

        pcap_check_success &= check_data(packet, data[src_idx]);
        pcap_count++;
    }
}

/**
 * This test-case exercises mixing in a star topology with 7 Mixnet nodes.
 * We subscribe to packet updates from every node, then send DATA packets
 * using a subset of nodes as source. Checks whether the hub (with mixing
 * factor 6) and sources buffer packets properly.
 */
void testcase(orchestrator* orchestrator) {
    sleep(5); // Wait for STP and link-state convergence
    auto error_code = TEST_ERROR_NONE;
    expect_packets = false;

    // Get packets from all nodes
    for (uint16_t i = 0; i < 7; i++) {
        DIE_ON_ERROR(orchestrator->pcap_change_subscription(i, true));
    }
    // Inject 3 packets at the hub
    for (uint16_t i = 0; i < 3; i++) {
        DIE_ON_ERROR(orchestrator->send_packet(
            3, (4 + i), PACKET_TYPE_DATA, data[3]));
    }
    sleep(5); // Wait for packets to propagate

    // Inject 6 packets at the sources
    for (size_t idx = 0; idx < 2; idx++) {
        for (uint16_t i = 0; i < 3; i++) {
            DIE_ON_ERROR(orchestrator->send_packet(
                i, (4 + i), PACKET_TYPE_DATA, data[i]));
        }
    }
    sleep(5); // Wait for packets to propagate

    expect_packets = true;
    for (uint16_t i = 0; i < 3; i++) {
        DIE_ON_ERROR(orchestrator->send_packet(
            i, (4 + i), PACKET_TYPE_DATA, data[i]));
    }
    sleep(5); // Wait for packets to propagate
}

void return_code(test_error_code_t value) {
    retcode = value;
}

int main(int argc, char **argv) {
    std::vector<std::vector<mixnet_address>> topology;
    create_star_topology(7, topology);

    orchestrator orchestrator;
    orchestrator.configure(argc, argv);
    orchestrator.register_cb_pcap(pcap);
    orchestrator.register_cb_testcase(testcase);
    orchestrator.register_cb_retcode(return_code);
    orchestrator.set_topology(mixaddrs, topology);

    // Set mixing factors
    orchestrator.set_mixing_factor(3, 6);
    for (uint16_t i = 0; i < 3; i++) {
        orchestrator.set_mixing_factor(i, 3);
    }

    std::cout << "[Test] Starting test_mix_data..." << std::endl;
    orchestrator.run();
    std::cout << ((retcode == TEST_ERROR_NONE) ?
        "Nodes returned OK" : "Nodes returned error") << std::endl;

    bool success = ((pcap_count == 12) && pcap_check_success);
    std::cout << (success ? "PASS" : "FAIL") << std::endl;
}

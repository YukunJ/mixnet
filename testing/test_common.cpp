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

#include <cstring>
#include <string>

void create_line_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology) {

    for (uint16_t i = 0; i < num_nodes; i++) {
        topology.push_back(std::vector<uint16_t>());
        if (i > 0) {
            topology[i].push_back(i - 1);
            topology[i - 1].push_back(i);
        }
    }
}

void create_ring_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology) {

    create_line_topology(num_nodes, topology);
    topology[0].push_back(num_nodes - 1);
    topology[num_nodes - 1].push_back(0);
}

void create_unreachable_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology) {

    create_line_topology(num_nodes - 1, topology);
    topology.push_back(std::vector<uint16_t>());
}

void create_fully_connected_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology) {

    for (uint16_t i = 0; i < num_nodes; i++) {
        topology.push_back(std::vector<uint16_t>());
        for (uint16_t j = 0; j < num_nodes; j++) {
            if (i != j) {
                topology[i].push_back(j);
            }
        }
    }
}

void create_star_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology) {

    for (uint16_t i = 0; i < num_nodes; i++) {
        topology.push_back(std::vector<uint16_t>());
    }
    uint16_t hub_idx = num_nodes / 2;
    for (uint16_t i = 0; i < num_nodes; i++) {
        if (i != hub_idx) {
            topology[hub_idx].push_back(i);
            topology[i].push_back(hub_idx);
        }
    }
}

bool is_valid_route(
    const mixnet_address src_address,
    const mixnet_address dst_address,
    const std::vector<mixnet_address>& route,
    const std::vector<mixnet_address>& mixaddrs,
    const std::vector<std::vector<uint16_t>>& topology) {

    size_t route_idx = 0;
    int current = get_index(src_address, mixaddrs);
    int next = !route.empty() ? get_index(route[0], mixaddrs):
                                get_index(dst_address, mixaddrs);
    do {
        if ((current == -1) || (next == -1)) { return false; }
        if (get_index((uint16_t) next, topology[current]) == -1) {
            return false; // Invalid neighbor relationship
        }
        current = next;
        next = (++route_idx < route.size()) ?
                get_index(route[route_idx], mixaddrs) :
                get_index(dst_address, mixaddrs);
    }
    while (route_idx <= route.size());
    return true;
}

bool check_route(
    struct mixnet_packet_routing_header *header,
    const mixnet_address *expected, const size_t n) {
    if (header->route_length != n) { return false; }
    auto route = reinterpret_cast<mixnet_address*>(header + 1);

    for (size_t idx = 0; idx < n; idx++) {
        if (route[idx] != expected[idx]) {
            return false;
        }
    }
    return true;
}

bool check_data(struct mixnet_packet *packet,
                const std::string& expected) {
    auto rh = reinterpret_cast<struct
        mixnet_packet_routing_header*>(packet + 1);

    const uint16_t rh_size = 4 + (2 * rh->route_length);
    const uint16_t expected_size = (rh_size + expected.size());
    if (packet->payload_size != expected_size) { return false; }

    void *data = (reinterpret_cast<char*>(rh) + rh_size);
    return (memcmp(data, expected.c_str(), expected.size()) == 0);
}

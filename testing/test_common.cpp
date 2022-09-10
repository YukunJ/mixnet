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

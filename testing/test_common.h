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
#ifndef TESTING_TEST_COMMON_H
#define TESTING_TEST_COMMON_H

#include <stdint.h>
#include <vector>

// Helper macros
#define DIE_ON_ERROR(x)                         \
    error_code = x;                             \
    if (error_code != TEST_ERROR_NONE) {        \
        std::cout << "FAIL with error code "    \
                  << error_code << std::endl;   \
        return;                                 \
    }

// Helper functions
void create_line_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology);

void create_ring_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology);

void create_unreachable_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology);

void create_fully_connected_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology);

void create_star_topology(
    const uint16_t num_nodes,
    std::vector<std::vector<uint16_t>>& topology);

#endif // TESTING_TEST_COMMON_H

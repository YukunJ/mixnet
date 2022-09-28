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

#include "mixnet/address.h"
#include "mixnet/packet.h"

#include <algorithm>
#include <stdint.h>
#include <string>
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

bool is_valid_route(
    const mixnet_address src_address,
    const mixnet_address dst_address,
    const std::vector<mixnet_address>& route,
    const std::vector<mixnet_address>& mixaddrs,
    const std::vector<std::vector<uint16_t>>& topology);

bool check_route(
    struct mixnet_packet_routing_header* header,
    const mixnet_address *expected, const size_t n);

bool check_data(struct mixnet_packet *packet,
                const std::string& expected);

template<typename T>
int get_index(const T value, const std::vector<T>& values) {
    auto iter = std::find(values.begin(), values.end(), value);
    return (iter != values.end()) ? (iter - values.begin()) : -1;
}

#endif // TESTING_TEST_COMMON_H

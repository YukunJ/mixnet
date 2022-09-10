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
#ifndef MIXNET_CONFIG_H
#define MIXNET_CONFIG_H

#include "address.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Default parameters
#define DEFAULT_ROOT_HELLO_INTERVAL_MS  (2000)
#define DEFAULT_REELECTION_INTERVAL_MS  (10000)

// Node configuration
struct mixnet_node_config {
    mixnet_address node_addr; // Mixnet address of this node
    uint16_t num_neighbors; // This node's total neighbor count
    mixnet_address *neighbor_addrs; // Mixnet addresses of neighbors

    // STP parameters
    uint32_t root_hello_interval_ms; // Time (in ms) between 'hello' messages
    uint32_t reelection_interval_ms; // Time (in ms) before starting reelection

    // Routing parameters
    bool use_random_routing; // Whether this node should perform random routing
    uint16_t mixing_factor; // The exact number of (non-control) packets to mix
};

#ifdef __cplusplus
}
#endif

#endif // MIXNET_CONFIG_H

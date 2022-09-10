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
#include "node.h"

#include "connection.h"

#include <stdlib.h>
#include <stdio.h>

void run_node(void *handle,
              volatile bool *keep_running,
              const struct mixnet_node_config config) {

    // A dumb dataplane. Forwards DATA packets if they're destined
    // for an immediate neighbor, otherwise drops them. Also drops
    // all other kinds of packets (STP, FLOOD, LSA, PING).
    const uint16_t num_neighbors = config.num_neighbors;
    while (*keep_running) {
        uint8_t port = 0;
        bool success = false;
        mixnet_packet* packet = NULL;

        int value = mixnet_recv(handle, &port, &packet);
        if (value != 0) {
            // Data packet, check if it's for a neighbor
            if (packet->type == PACKET_TYPE_DATA) {
                for (size_t nid = 0; nid < num_neighbors && !success; nid++) {
                    if (config.neighbor_addrs[nid] == packet->dst_address) {
                        mixnet_send(handle, nid, packet);
                        // Ought to check if send() returns -1!
                        success = true;
                    }
                }
            }
            if (!success) { free(packet); }
        }
    }
}

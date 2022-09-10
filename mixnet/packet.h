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
#ifndef MIXNET_PACKET_H
#define MIXNET_PACKET_H

#include "address.h"

#include <assert.h>
#include <stdalign.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constant parameters
static const uint16_t MAX_MIXNET_PACKET_SIZE = 1024;

/**
 * Mixnet packet type.
 */
enum mixnet_packet_type_enum {
    PACKET_TYPE_STP = 0,
    PACKET_TYPE_FLOOD,
    PACKET_TYPE_LSA,
    PACKET_TYPE_DATA,
    PACKET_TYPE_PING,
};
// Shorter type alias for the enum
typedef uint16_t mixnet_packet_type_t;

// Helper macros
#define CHECK_ALIGNMENT_AND_SIZE(typename, size, align)         \
    static_assert(sizeof(typename) == size, "Bad size");        \
    static_assert(alignof(typename) <= align, "Bad alignment")

/**
 * Represents a generic Mixnet packet header.
 */
typedef struct mixnet_packet {
    mixnet_address src_address;     // Mixnet source address
    mixnet_address dst_address;     // Mixnet destination address
    mixnet_packet_type_t type;      // The type of Mixnet packet
    uint16_t payload_size;          // Payload size (in bytes)

#ifndef __cplusplus
    char payload[];                 // Variable-size payload
#endif
}__attribute__((__packed__)) mixnet_packet;
CHECK_ALIGNMENT_AND_SIZE(mixnet_packet, 8, 2);

/**
 * Represents the payload for an STP packet.
 */
typedef struct mixnet_packet_stp {
    mixnet_address root_address;    // Root of the spanning tree
    uint16_t path_length;           // Length of path to the root
    mixnet_address node_address;    // Current node's mixnet address

}__attribute__((packed)) mixnet_packet_stp;
CHECK_ALIGNMENT_AND_SIZE(mixnet_packet_stp, 6, 2);

/**
 * Represents the payload for an LSA packet.
 */
typedef struct mixnet_packet_lsa {
    mixnet_address node_address;    // Advertising node's mixnet address
    uint16_t neighbor_count;        // Length of path to the root

}__attribute__((packed)) mixnet_packet_lsa;
CHECK_ALIGNMENT_AND_SIZE(mixnet_packet_lsa, 4, 2);

/**
 * Represents a Routing Header (RH).
 */
typedef struct mixnet_packet_routing_header {
    uint16_t route_length;          // Route length (excluding src, dst)
    uint16_t hop_index;             // Index of current hop in the route

#ifndef __cplusplus
    char route[];                   // Var-size route (size is zero if no hops)
#endif
}__attribute__((packed)) mixnet_packet_routing_header;
CHECK_ALIGNMENT_AND_SIZE(mixnet_packet_routing_header, 4, 2);

/**
 * Represents the payload for a PING packet (minus RH).
 */
typedef struct mixnet_packet_ping {
    uint16_t ping_direction;        // 0 for request, 1 for response
    uint64_t send_time;             // Sender-populated request time

}__attribute__((packed)) mixnet_packet_ping;
CHECK_ALIGNMENT_AND_SIZE(mixnet_packet_ping, 10, 2);

// Cleanup
#undef CHECK_ALIGNMENT_AND_SIZE

#ifdef __cplusplus
}
#endif

#endif // MIXNET_PACKET_H

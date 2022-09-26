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
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "connection.h"

/** the scale factor from second to millisecond */
#define SECOND_TO_MILL 1000

/** the scale factor from millisecond to microsecond */
#define MILL_TO_MICRO 1000

/** the payload size of STP packet*/
#define STP_PACKET_SIZE 6

/**
 * The struct to store Minimal Spanning Tree Protocol information
 * which is of the triple form:
 * (who is the root, how far for me to reach root, what's the next hop to root)
 */
typedef struct stp_info {
  mixnet_address root;
  uint16_t root_distance;
  mixnet_address next_hop;
} stp_info_t;

/**
 * Generate the unix timestamp in millisecond
 * @return timestamp in unsigned long long
 */
uint64_t get_curr_time_ms() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)(tv.tv_sec) * SECOND_TO_MILL +
         (uint64_t)(tv.tv_usec) / MILL_TO_MICRO;
}

/**
 * Initialize the STP information to believe that self is the root of the
 * topology
 * @param stp_info_ptr pointer to stp_info_t struct
 * @param root_address the node's self address
 */
void init_stp_info(stp_info_t *stp_info_ptr, mixnet_address root_address) {
  stp_info_ptr->root = root_address;
  stp_info_ptr->root_distance = 0;
  stp_info_ptr->next_hop = root_address;
}

/**
 * Reset the is_active_link array so that every link becomes active
 * @param is_children pointer to is_active_link array
 * @param num_neighbors size of neighbors
 */
void init_is_active_link(bool *is_active_link, uint16_t num_neighbors) {
  for (uint16_t i = 0; i < num_neighbors; ++i) {
    is_active_link[i] = true;
  }
}

/**
 * Generate pointer to STP packet given root, path_length, and node_address
 * @param root_address the mixnet_address of the root node
 * @param path_length the path length from the current node to the root node
 * @param self_address the mixnet_address of the current node
 * @return the pointer to mixnet packet of STP type
 */
mixnet_packet *generate_stp_packet(mixnet_address root_address,
                                   uint16_t path_length,
                                   mixnet_address self_address) {
  mixnet_packet *m_packet = malloc(sizeof(mixnet_packet) + STP_PACKET_SIZE);
  mixnet_packet_stp stp_packet;
  // connect the mixnet packet's payload point to stp_packet
  m_packet->type = PACKET_TYPE_STP;
  m_packet->payload_size = STP_PACKET_SIZE;
  m_packet->src_address = 0;  // can be set to arbitrary
  m_packet->dst_address = 0;  // can be set to arbitrary
  stp_packet.root_address = root_address;
  stp_packet.path_length = path_length;
  stp_packet.node_address = self_address;
  // char[] is not assignable
  memcpy(m_packet->payload, (const char *)&stp_packet, STP_PACKET_SIZE);
  return m_packet;
}

/**
 * Generate flood packet for testing purpose
 * @return the pointer to a flood packet
 */
mixnet_packet *generate_flood_packet() {
  mixnet_packet *m_packet = malloc(sizeof(mixnet_packet));
  m_packet->src_address = 0;  // can be set to arbitrary
  m_packet->dst_address = 0;  // can be set to arbitrary
  m_packet->type = PACKET_TYPE_FLOOD;
  m_packet->payload_size = 0;
  return m_packet;
}

/**
 * @brief wrapper function for mixnet_send
 *        will keep retry if buffer queue is full and return 0
 *        but error code -1 will be returned and not re-tried
 * @param handle handle
 * @param port the port to send out
 * @param packet pointer to a mixnet_packet
 * @return mixnet_send status code
 */
int send(void *handle, const uint8_t port, mixnet_packet *packet) {
    int signal = 0;
    do {
        signal = mixnet_send(handle, port, packet);
    } while (signal == 0);
    return signal;
}

/**
 * Broadcast the STP triple to every neighbor
 * @param handle void * handler for control
 * @param config_ptr pointer to node config
 * @param root_address the self-believed root's address
 * @param path_length the length to root
 * @param self_address the node itself address
 */
void broadcast_stp(void *handle, const struct mixnet_node_config *config_ptr,
                   mixnet_address root_address, uint16_t path_length,
                   mixnet_address self_address) {
  // every time mixnet_send will free the packet after successful transmission
  // we need the allocated new packet for each port
  const uint16_t num_neighbors = config_ptr->num_neighbors;
  for (uint16_t i = 0; i < num_neighbors; i++) {
    mixnet_packet *packet =
        generate_stp_packet(root_address, path_length, self_address);
    if (send(handle, i, packet) == -1) {
      free(packet);
    }
  }
}

/**
 * Broadcast the flood message to all active links
 * @param handle void * handler for control
 * @param config_ptr pointer to node config
 * @param is_active_link the ptr to is_active_link array
 * @param num_neighbors the length to root
 * @param source_port the port where this flood message come from
 */
void broadcast_flood(void *handle, const struct mixnet_node_config *config_ptr,
                     bool *is_active_link, uint16_t num_neighbors,
                     uint16_t source_port) {
  for (uint16_t i = 0; i < num_neighbors; i++) {
    if (!is_active_link[i] || i == source_port) {
      continue;
    }
    mixnet_packet *packet = generate_flood_packet();
    if (send(handle, i, packet) == -1) {
      free(packet);
    }
  }
  if (source_port != num_neighbors) {
    // not a user-init flood packet, send back to user
    mixnet_packet *packet = generate_flood_packet();
    if (send(handle, num_neighbors, packet) == -1) {
      free(packet);
    }
  }
}

/**
 * Check if we have found a better root or a better path to path,
 * if we have, we would update stp_info, representing our knowledge
 * to root
 * @param stp_packet pointer to a stp packet
 * @param stp_info pointer to a stp_info
 * @return whether we have found a better root or path to root.
 */
bool is_better_root(mixnet_packet_stp *stp_packet, stp_info_t *stp_info) {
  bool found_better_root = false;
  if (stp_packet->root_address < stp_info->root) {
    found_better_root = true;
  } else if (stp_packet->root_address == stp_info->root) {
    if (stp_packet->path_length < stp_info->root_distance - 1) {
      found_better_root = true;
    } else if (stp_packet->path_length == stp_info->root_distance - 1 &&
               stp_packet->node_address < stp_info->next_hop) {
      found_better_root = true;
    }
  }
  if (found_better_root) {
    stp_info->root = stp_packet->root_address;
    stp_info->root_distance = stp_packet->path_length + 1;
    stp_info->next_hop = stp_packet->node_address;
  }
  return found_better_root;
}

/**
 * Test against a particular packet to see if it align with
 * @param stp_packet pointer to a stp packet
 * @param stp_info pointer to a stp_info
 * @return whether we have received root's hello message from my next hop
 */
bool received_hello_from_parent(mixnet_packet_stp *stp_packet,
                                stp_info_t *stp_info) {
  return stp_packet->root_address == stp_info->root &&
         stp_packet->node_address == stp_info->next_hop &&
         stp_packet->path_length == stp_info->root_distance - 1;
}

/**
 * test if we can infer from this packet, if the incoming port is child
 * @param stp_packet pointer to a stp_info
 * @return result of test
 */
bool is_potential_child(mixnet_packet_stp *stp_packet, stp_info_t *stp_info) {
  return stp_packet->root_address == stp_info->root &&
         stp_packet->path_length > stp_info->root_distance;
}

void run_node(void *handle, volatile bool *keep_running,
              const struct mixnet_node_config config) {
  // A dumb dataplane. Forwards DATA packets if they're destined
  // for an immediate neighbor, otherwise drops them. Also drops
  // all other kinds of packets (STP, FLOOD, LSA, PING).

  // We would initialize everything necessary here. Including our
  // belief about the root (on stack), time since last time hearing
  // hello from the root (on stack),  time since last time sending
  // hello as a root (on stack), and our belief about potential
  // children node, represented as a bool array (on heap)
  const uint16_t num_neighbors = config.num_neighbors;
  const uint64_t root_hello_interval_ms =
      (uint64_t)config.root_hello_interval_ms;
  const uint64_t reelection_interval_ms =
      (uint64_t)config.reelection_interval_ms;

  // initially, each node believes it is the root in the STP topology
  stp_info_t stp_info;
  init_stp_info(&stp_info, config.node_addr);

  // dynamically allocate an array of bool to indicate if a link is active
  // initially when this node think it's the root, every link is active
  bool *is_active_link = malloc(num_neighbors * sizeof(bool));
  init_is_active_link(is_active_link, num_neighbors);

  // broadcast to everyone: I am the root.
  broadcast_stp(handle, &config, stp_info.root, stp_info.root_distance,
                config.node_addr);
  uint64_t curr_time = get_curr_time_ms();
  uint64_t last_time_sending_hello = curr_time;
  uint64_t last_time_receiving_hello = curr_time;

  while (*keep_running) {
    uint8_t port = 0;
    bool success = false;
    mixnet_packet *packet = NULL;

    // Whether we have received hello from the root node in this epoch
    bool received_hello_from_root = false;

    int value = mixnet_recv(handle, &port, &packet);
    curr_time = get_curr_time_ms();
    if (value != 0) {
      // Data packet, check if it's for a neighbor
      if (packet->type == PACKET_TYPE_DATA) {
        for (size_t nid = 0; nid < num_neighbors && !success; nid++) {
          if (config.neighbor_addrs[nid] == packet->dst_address) {
            // mixnet_send(handle, nid, packet);
            // Ought to check if send() returns -1!
            success = send(handle, nid, packet) != -1;
          }
        }
        // STP packet
      } else if (packet->type == PACKET_TYPE_STP) {
        mixnet_packet_stp *stp_packet = (mixnet_packet_stp *)packet->payload;
        // if we have a better root, update the stp_info, set
        // received_hello_from_root indicating we want to broadcast our
        // potential children about root information update my knowledge about
        // active links
        if (is_better_root(stp_packet, &stp_info)) {
          received_hello_from_root = true;
          is_active_link[port] = true;
          // else if we have received root info from my parent, and this piece
          // of info agrees with my knowledge, set received_hello_from_root
          // indicating we want to broadcast our potential children about root
          // information update my knowledge about active links
        } else if (received_hello_from_parent(stp_packet, &stp_info)) {
          received_hello_from_root = true;
          is_active_link[port] = true;
          // else if the stp packet is from a potential child, we update our
          // knowledge about active links
        } else if (is_potential_child(stp_packet, &stp_info)) {
          is_active_link[port] = true;
        } else {
          is_active_link[port] = false;
        }
        // After processing the packet, check if we need to do
        // anything according to STP protocol
        // if I have received root's hello from root, I need to broadcast it to
        // everyone
        if (received_hello_from_root) {
          broadcast_stp(handle, &config, stp_info.root, stp_info.root_distance,
                        config.node_addr);
          last_time_receiving_hello = curr_time;
        }
      } else if (packet->type == PACKET_TYPE_FLOOD) {
        // if the FLOOD package is generated by users, broadcast to all active
        // link if the FlOOD package is from an active link, broadcast to all
        // other active links
        if (port == num_neighbors ||
            (port < num_neighbors && is_active_link[port])) {
          broadcast_flood(handle, &config, is_active_link, num_neighbors, port);
        }
      }

      if (!success) {
        free(packet);
      }
    }

    // the below is globally executed, each node will try execute by the end of
    // while

    // if I am the root, and we have waited for root hello interval ms
    // I would broadcast my heartbeat, and reset last time sending hello
    if (stp_info.root == config.node_addr &&
        curr_time - last_time_sending_hello >= root_hello_interval_ms) {
      broadcast_stp(handle, &config, stp_info.root, stp_info.root_distance,
                    config.node_addr);
      last_time_sending_hello = curr_time;
      // else I am not the root
    } else if (stp_info.root != config.node_addr) {
      // if I have waited for reelection_interval_ms, I think there is an error,
      // I would assume that I am the root again. I would initialize myself as
      // root update is_active_link, and broadcast, reset last time sending
      // hello
      if (curr_time - last_time_receiving_hello >= reelection_interval_ms) {
        init_stp_info(&stp_info, config.node_addr);
        init_is_active_link(is_active_link, num_neighbors);
        broadcast_stp(handle, &config, stp_info.root, stp_info.root_distance,
                      config.node_addr);
        last_time_sending_hello = curr_time;
      }
    }
  }

  // gracefully exit and release dynamic allocated memory
  free(is_active_link);
}

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "connection.h"
#include "utils.h"

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
 * Generate lsa packet to build topology
 * @return the pointer to a flood packet
 */
mixnet_packet *generate_lsa_packet(mixnet_address root_address,
                                   uint16_t num_neighbors,
                                   const mixnet_address *neighbors) {
  // The payload contains num_neighbors + 2 uint16_t, additional 2
  // represents sender's address and num_neighbors
  uint16_t payload_size = sizeof(uint16_t) * (num_neighbors + 2);
  mixnet_packet *m_packet = malloc(sizeof(mixnet_packet) + payload_size);
  m_packet->src_address = 0;  // can be set to arbitrary
  m_packet->dst_address = 0;  // can be set to arbitrary
  m_packet->type = PACKET_TYPE_LSA;
  m_packet->payload_size = payload_size;
  // set the payload for LSA packet
  uint16_t *payload = malloc(payload_size);
  payload[0] = root_address;
  payload[1] = num_neighbors;
  for (uint16_t i = 0; i < num_neighbors; i++) {
    payload[i + 2] = neighbors[i];
  }
  memcpy(m_packet->payload, (const char *)payload, payload_size);
  // free the payload
  free(payload);
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
  int signal;
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
                     const bool *is_active_link, uint16_t num_neighbors,
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
 * Broadcast the STP triple to every neighbor
 * @param handle void * handler for control
 * @param config_ptr pointer to node config
 * @param host_address the address of host sending LSA packet
 * @param num_neighbors_host number of neighbors of host
 * @param self_address the node itself address
 */
void broadcast_lsa(void *handle, const struct mixnet_node_config *config_ptr,
                   mixnet_address host_address, uint16_t num_neighbors_host,
                   mixnet_address *host_neighbors) {
  const uint16_t num_neighbors = config_ptr->num_neighbors;
  for (uint16_t i = 0; i < num_neighbors; i++) {
    mixnet_packet *packet =
        generate_lsa_packet(host_address, num_neighbors_host, host_neighbors);
    if (send(handle, i, packet) == -1) {
      free(packet);
    }
  }
}

/**
 * Generate a common routing header for both Data and Ping packet
 * @param route_length how many hops to take, excluding source and destination
 * @param shortest_path the Dijkstra shortest path result
 * @param is_random bool flag to indicate if randomness is involved in routing
 * @return a pointer to the routing header
 */
uint16_t *routing_header_generator(uint16_t *route_length,
                                   vector_t *shortest_path, bool is_random) {
  uint16_t *routing_header;
  if (is_random && get_curr_time_ms() % 2) {
    // generate "random" path
    *route_length = *route_length + 2;
    uint16_t routing_header_size = (*route_length + 2) * sizeof(uint16_t);
    routing_header = malloc(routing_header_size);
    routing_header[0] = *route_length;
    routing_header[1] = 0;  // the first "transporter"'s hop index
    routing_header[2] = *((mixnet_address *)vec_get(shortest_path, 1));
    routing_header[3] = *((mixnet_address *)vec_get(shortest_path, 0));
    for (uint16_t i = 0; i < vec_size(shortest_path) - 2; i++) {
      routing_header[i + 4] =
          *((mixnet_address *)vec_get(shortest_path, i + 1));
    }
  } else {
    // best path
    uint16_t routing_header_size = (*route_length + 2) * sizeof(uint16_t);
    routing_header = malloc(routing_header_size);
    routing_header[0] = *route_length;
    routing_header[1] = 0;  // the first "transporter"'s hop index
    for (uint16_t i = 0; i < vec_size(shortest_path) - 2; i++) {
      routing_header[i + 2] =
          *((mixnet_address *)vec_get(shortest_path, i + 1));
    }
  }
  return routing_header;
}

mixnet_packet *generate_data_packet(const struct mixnet_node_config *config_ptr,
                                    vector_t *shortest_path,
                                    mixnet_packet *data_packet) {
  mixnet_address source_address = config_ptr->node_addr;
  mixnet_address destination_address =
      *((mixnet_address *)vec_get(shortest_path, vec_size(shortest_path) - 1));
  assert(vec_size(shortest_path) >= 2);  // at least source -> destination
  uint16_t route_length = (uint16_t)vec_size(shortest_path) - 2;
  uint16_t data_size = data_packet->payload_size;
  // get the routing header, also modify route_length if random
  uint16_t *routing_header = routing_header_generator(
      &route_length, shortest_path, config_ptr->use_random_routing);
  uint16_t routing_header_size = (route_length + 2) * sizeof(uint16_t);
  mixnet_packet *m_packet =
      malloc(sizeof(mixnet_packet) + routing_header_size + data_size);
  // fill in the field of m_packet
  m_packet->src_address = source_address;
  m_packet->dst_address = destination_address;
  m_packet->payload_size = routing_header_size + data_size;
  m_packet->type = PACKET_TYPE_DATA;
  // set the routing header of the packet
  memcpy(m_packet->payload, (const char *)routing_header, routing_header_size);
  // copy in the true data part, +4 since data_packet from user has nonsense
  // route length and hop index
  memcpy(m_packet->payload + routing_header_size, data_packet->payload + 4,
         data_size);
  // free the routing header
  free(routing_header);
  return m_packet;
}

mixnet_packet *generate_ping_packet(const struct mixnet_node_config *config_ptr,
                                    vector_t *shortest_path) {
  mixnet_address source_address = config_ptr->node_addr;
  mixnet_address destination_address =
      *((mixnet_address *)vec_get(shortest_path, vec_size(shortest_path) - 1));
  assert(vec_size(shortest_path) >= 2);  // at least source -> destination
  uint16_t route_length = (uint16_t)vec_size(shortest_path) - 2;
  uint16_t data_size = 10;
  // get the routing header
  uint16_t *routing_header =
      routing_header_generator(&route_length, shortest_path, false);
  uint16_t routing_header_size = (route_length + 2) * sizeof(uint16_t);
  mixnet_packet *m_packet =
      malloc(sizeof(mixnet_packet) + routing_header_size + data_size);
  // fill in the field of m_packet
  m_packet->src_address = source_address;
  m_packet->dst_address = destination_address;
  m_packet->payload_size = routing_header_size + data_size;
  m_packet->type = PACKET_TYPE_PING;
  // set the routing header of the packet
  memcpy(m_packet->payload, (const char *)routing_header, routing_header_size);
  // set the ping direction of the packet
  uint16_t *ping_direction =
      (uint16_t *)(m_packet->payload + routing_header_size);
  ping_direction[0] = 0;
  // set the sending time of the packet;
  uint64_t *send_time =
      (uint64_t *)(m_packet->payload + routing_header_size + sizeof(uint16_t));
  *send_time = get_curr_time_ms();
  // free the routing header
  free(routing_header);
  return m_packet;
}

/**
 * When accumulate enough packets, send them all at once
 * @param mix_buffer a pointer to the mix buffer
 * @param config_ptr pointer to config struct
 * @param handle the system handler
 */
void send_buffer(vector_t *mix_buffer,
                 const struct mixnet_node_config *config_ptr, void *handle) {
  for (int64_t i = 0; i < vec_size(mix_buffer); i++) {
    mixnet_packet *packet = (mixnet_packet *)vec_get(mix_buffer, i);
    uint16_t *routing_header = (uint16_t *)packet->payload;
    mixnet_address next_hop;
    if (routing_header[0] == routing_header[1]) {
      // we are the last hop, send directly to destination
      next_hop = packet->dst_address;
    } else {
      next_hop = routing_header[2 + routing_header[1]];
    }
    for (uint16_t i = 0; i < config_ptr->num_neighbors; i++) {
      if (config_ptr->neighbor_addrs[i] == next_hop) {
        send(handle, i, packet);
      }
    }
  }
  mix_buffer->size = 0;
}

/**
 * Add a new generated packet into mix buffer
 * when reach mix factor, send them all out
 * @param mix_buffer the pointer to the mix buffer
 * @param new_packet pointer to a mixnet_packet
 * @param config_ptr pointer to the config
 * @param handle the system handler
 */
void add_buffer(vector_t *mix_buffer, mixnet_packet *new_packet,
                const struct mixnet_node_config *config_ptr, void *handle) {
  uint16_t mix_factor = config_ptr->mixing_factor;
  vec_push_back(mix_buffer, new_packet);
  if (vec_size(mix_buffer) == mix_factor) {
    send_buffer(mix_buffer, config_ptr, handle);
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
  // and the node topology graph and Dijkstra's result vector
  const uint16_t num_neighbors = config.num_neighbors;
  const uint64_t root_hello_interval_ms =
      (uint64_t)config.root_hello_interval_ms;
  const uint64_t reelection_interval_ms =
      (uint64_t)config.reelection_interval_ms;
  vector_t *mix_buffer = create_vector();
  graph_t *const graph = create_graph(mixnet_address_equal);
  vector_t *dijkstra_result = NULL;  // the shortest path calculation triples
  bool dijkstra_run = false;

  // add self and neighbors into the graph
  for (uint16_t i = 0; i < num_neighbors; i++) {
    mixnet_add_neighbor(graph, config.node_addr, config.neighbor_addrs[i]);
  }

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

  // broadcast LSA neighbor information out to neighbors
  for (uint16_t i = 0; i < num_neighbors; i++) {
    mixnet_packet *lsa_packet = generate_lsa_packet(
        config.node_addr, config.num_neighbors, config.neighbor_addrs);
    if (send(handle, i, lsa_packet) == -1) {
      free(lsa_packet);
      printf("send lsa packet leads to -1 signal\nAbort!\n");
      exit(1);
    }
  }

  while (*keep_running) {
    uint8_t port = 0;
    bool should_not_free = false;
    mixnet_packet *packet = NULL;

    // Whether we have received hello from the root node in this epoch
    bool received_hello_from_root = false;

    int value = mixnet_recv(handle, &port, &packet);
    curr_time = get_curr_time_ms();
    if (value != 0) {
      if (!dijkstra_run && (packet->type == PACKET_TYPE_DATA ||
                            packet->type == PACKET_TYPE_PING)) {
        dijkstra_result = dijkstra_shortest_path(graph, config.node_addr);
        dijkstra_run = true;
      }
      // Data packet, check if it's for a neighbor
      if (packet->type == PACKET_TYPE_DATA) {
        // first check if the packet is generated by the user
        if (port == num_neighbors) {
          // we need to generate the path and send it to the correct user
          // shortest_path is of form [source, X1, X2, ..., Xn, destination]
          vector_t *shortest_path = construct_path(
              dijkstra_result, config.node_addr, packet->dst_address);
          mixnet_packet *new_data_packet =
              generate_data_packet(&config, shortest_path, packet);
          free_vector(shortest_path);
          // add the new_data_packet into mix buffer
          add_buffer(mix_buffer, new_data_packet, &config, handle);
        } else {
          uint16_t *routing_header = (uint16_t *)packet->payload;
          uint16_t route_length = routing_header[0];
          uint16_t curr_hop = routing_header[1];
          if (route_length == curr_hop) {
            // replay this packet to my user
            send(handle, config.num_neighbors, packet);
            should_not_free = true;
          } else {
            routing_header[1] += 1;
            add_buffer(mix_buffer, packet, &config, handle);
            should_not_free = true;
          }
        }
      } else if (packet->type == PACKET_TYPE_PING) {
        // first check if the ping packet is generated by the user
        if (port == num_neighbors) {
          // we need to generate the path and send it to the correct user
          // shortest_path is of form [source, X1, X2, ..., Xn, destination]
          vector_t *shortest_path = construct_path(
              dijkstra_result, config.node_addr, packet->dst_address);
          mixnet_packet *new_ping_packet =
              generate_ping_packet(&config, shortest_path);
          free_vector(shortest_path);
          // add the new_data_packet into mix buffer
          add_buffer(mix_buffer, new_ping_packet, &config, handle);
        } else {
          uint16_t *routing_header = (uint16_t *)packet->payload;
          uint16_t route_length = routing_header[0];
          uint16_t curr_hop = routing_header[1];
          uint16_t direction = routing_header[route_length + 2];
          if (route_length == curr_hop) {
            // if direction is 0, we need to send back the ping packet
            if (direction == 0) {
              // first copy a packet and send back to user
              uint16_t copy_size = sizeof(mixnet_packet) + packet->payload_size;
              mixnet_packet *copy_packet = (mixnet_packet *)malloc(copy_size);
              memcpy(copy_packet, (const char *)packet, copy_size);
              send(handle, num_neighbors, copy_packet);

              // More, since I am the end of the request ping path, reverse the
              // route path and send it back
              vector_t *reverse_route = create_vector();
              for (uint16_t i = 0; i < route_length; i++) {
                mixnet_address hop = routing_header[i + 2];
                mixnet_address *hop_cpy =
                    (mixnet_address *)malloc(sizeof(mixnet_address));
                *hop_cpy = hop;
                vec_push_back(reverse_route, hop_cpy);
              }
              vec_reverse(reverse_route);
              for (uint16_t i = 0; i < route_length; i++) {
                // overwrite the reverse path
                routing_header[i + 2] =
                    *((mixnet_address *)vec_get(reverse_route, i));
              }
              free_vector(reverse_route);
              routing_header[1] = 0;  // reset the next-hop index to be 0
              routing_header[route_length + 2] =
                  1;  // reverse the ping direction
              // reverse the source and destination field of the packet head
              mixnet_address temp = packet->dst_address;
              packet->dst_address = packet->src_address;
              packet->src_address = temp;
              // add to mix buffer for temporary storage
              add_buffer(mix_buffer, packet, &config, handle);
              // reuse this packet, do not free it
              should_not_free = true;
            } else {
              // if direction is 1, compute RTT and send it back to user
              uint64_t *send_time =
                  (uint64_t *)(routing_header + 2 + route_length + 1);
              *send_time = get_curr_time_ms() - *send_time;
              send(handle, config.num_neighbors, packet);
              should_not_free = true;
            }
          } else {
            routing_header[1] += 1;
            add_buffer(mix_buffer, packet, &config, handle);
            should_not_free = true;
          }
        }
      } else if (packet->type == PACKET_TYPE_STP) {
        // STP packet
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
      } else if (packet->type == PACKET_TYPE_LSA) {
        // first check if we have processed LSA packet from the node sending LSA
        // packet
        uint16_t *payload = (uint16_t *)packet->payload;
        if (graph_find_vertex(graph, &payload[0]) == NULL) {
          // not receive this node's neighbor LSA information so far
          // first add the adjacency information into the graph
          mixnet_address host = payload[0];
          uint16_t num_neighbors_host = payload[1];
          for (uint16_t i = 0; i < num_neighbors_host; i++) {
            mixnet_add_neighbor(graph, host, payload[i + 2]);
          }
          // and propagate this packet to every neighbors
          broadcast_lsa(handle, &config, host, num_neighbors_host, &payload[2]);
        }
      }

      if (!should_not_free) {
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
  free_vector(mix_buffer);
  free_graph(graph);
  if (dijkstra_result != NULL) {
    free_vector(dijkstra_result);
  }
  free(is_active_link);
}

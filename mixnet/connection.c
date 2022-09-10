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
#include "connection.h"

#include "config.h"
#include "harness/fragment.h"
#include "packet.h"

#include <errno.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <stdlib.h>
#include <string.h>

int mixnet_recv(void *handle, uint8_t *port, mixnet_packet **packet) {
    // Fetch the fragment context
    struct fragment_context *ctx = (
        (struct fragment_context*) handle);

    struct mixnet_context *subctx = &(ctx->mixnet_ctx);
    struct mixnet_node_config *config = &(subctx->config);

    // Attempt to receive on the input ports in a round-robin fashion
    const uint16_t max_port_id = config->num_neighbors;
    const uint16_t stop_idx = subctx->next_port_idx;
    int num_recvd = 0;
    do {
        // This is the application-level data port
        if (subctx->next_port_idx == max_port_id) {
            // Consume a packet from the MQ
            mixnet_packet *mq_packet = ((mixnet_packet *)
                message_queue_tryread(&(ctx->mq_app_packets)));

            // Valid packet
            if (mq_packet != NULL) {
                num_recvd++;
                *port = subctx->next_port_idx;
                *packet = malloc(MAX_MIXNET_PACKET_SIZE);
                memcpy(*packet, mq_packet, MAX_MIXNET_PACKET_SIZE);

                message_queue_message_free(&(ctx->mq_app_packets),
                                           (void*) mq_packet);
            }
        }
        // This is a regular port
        else {
            pthread_mutex_t *mutex = &(subctx->
                port_mutexes[subctx->next_port_idx]);

            // SCTP socket operations are supposed to be thread-safe,
            // so guarding the recv call with a mutex isn't strictly
            // necessary. But leaving this here in case we switch to
            // standard UNIX sockets, etc.
            pthread_mutex_lock(mutex); // Acquire mutex
            bool is_link_enabled = subctx->link_states[
                subctx->next_port_idx];

            int rc = 0;
            int flags = 0;
            if (is_link_enabled) {
                rc = sctp_recvmsg(
                    subctx->rx_socket_fds[subctx->next_port_idx],
                    subctx->packet_buffer, MAX_MIXNET_PACKET_SIZE,
                    NULL, 0, NULL, &flags);
            }
            pthread_mutex_unlock(mutex); // Release mutex

            if (rc < 0) {
                if ((errno != EAGAIN) && (errno != ENOBUFS)) {
                    ctx->ts_node.error_code = (
                        TEST_ERROR_MIXNET_CONNECTION_BROKEN);

                    ctx->ts_node.exited = true;
                    pthread_exit(NULL);
                }
            }
            else if (rc == 0) {
                ctx->ts_node.error_code = (
                    TEST_ERROR_MIXNET_CONNECTION_BROKEN);

                ctx->ts_node.exited = true;
                pthread_exit(NULL);
            }
            else {
                // Validate the packet header
                mixnet_packet *header = (
                    (mixnet_packet *) subctx->packet_buffer);

                const size_t total_size = (sizeof(mixnet_packet) +
                                           header->payload_size);

                // We discard packets with size larger than MTU
                // on the TX side, so this case shouldn't arise
                // unless something went seriously wrong.
                if (total_size > MAX_MIXNET_PACKET_SIZE) {
                    ctx->ts_node.error_code = (
                        TEST_ERROR_MIXNET_INVALID_PACKET_SIZE);

                    ctx->ts_node.exited = true;
                    pthread_exit(NULL);
                }
                // SCTP transmission is non-atomic
                else if (rc != (int) total_size) {
                    ctx->ts_node.error_code = TEST_ERROR_SCTP_PARTIAL_DATA;
                    ctx->ts_node.exited = true;
                    pthread_exit(NULL);
                }
                else {
                    // Valid packet
                    num_recvd++;
                    *packet = malloc(total_size);
                    *port = subctx->next_port_idx;
                    memcpy(*packet, subctx->packet_buffer, total_size);
                }
            }
        }
        subctx->next_port_idx = fragment_next_port_idx(
            subctx->next_port_idx, config->num_neighbors);

    } while ((num_recvd == 0) &&
             (subctx->next_port_idx != stop_idx));

    return num_recvd;
}

int mixnet_send(void *handle, const uint8_t port, mixnet_packet *packet) {
    // Fetch the fragment context
    struct fragment_context *ctx = (
        (struct fragment_context*) handle);

    struct mixnet_context *subctx = &(ctx->mixnet_ctx);
    struct mixnet_node_config *config = &(subctx->config);

    const uint16_t max_port_id = config->num_neighbors;
    if (port > max_port_id) { return -1; } // Invalid port ID

    mixnet_packet *header = (mixnet_packet *) packet;
    const size_t total_size = sizeof(*header) + header->payload_size;

    // Incorrect packet size
    if (total_size > MAX_MIXNET_PACKET_SIZE) { return -1; }

    // Check type specifications
    switch (packet->type) {
    case PACKET_TYPE_STP: {
        // Incorrect payload size
        if (packet->payload_size != 6) { return -1; }
    } break;

    case PACKET_TYPE_FLOOD: {
        // Incorrect payload size
        if (packet->payload_size != 0) { return -1; }
    } break;

    case PACKET_TYPE_LSA: {
        // Incorrect payload size
        mixnet_packet_lsa *header = (
            (mixnet_packet_lsa *) packet->payload);

        if ((4 + (2 * header->neighbor_count)) !=
            packet->payload_size) { return -1; }
    } break;

    case PACKET_TYPE_DATA: break;

    case PACKET_TYPE_PING: {
        // Incorrect payload size
        mixnet_packet_routing_header *header = (
            (mixnet_packet_routing_header *) packet->payload);

        if (((4 + (2 * header->route_length)) + 10) !=
            packet->payload_size) { return -1; }
    } break;

    // Unknown packet type
    default: { return -1; } break;
    }

    // This is the application-level data port
    if (port == max_port_id) {
        if ((header->type != PACKET_TYPE_FLOOD) &&
            (header->type != PACKET_TYPE_DATA) &&
            (header->type != PACKET_TYPE_PING)) {
            return -1;
        }
        // If the orchestrator is subscribed to pcap updates
        // from this node, then mirror this packet to the MQ.
        if (subctx->is_pcap_subscribed) {
            void **ptr = ((void **)
                message_queue_message_alloc(&(ctx->mq_pcap)));

            // If the MQ failed to allocate memory, it means the
            // pcap thread isn't consuming fast enough, an issue
            // that would never arise during normal operation.
            // Indicate failure and return.
            if (ptr == NULL) {
                ctx->ts_node.error_code = (
                    TEST_ERROR_FRAGMENT_PCAP_MQ_FULL);

                ctx->ts_node.exited = true;
                free(packet); pthread_exit(NULL);
            }
            *ptr = packet; // Enque the packet
            message_queue_write(&(ctx->mq_pcap), ptr);
        }
        // Else, simply free the packet
        else { free(packet); }
        return 1;
    }
    // Regular port
    else {
        // Attempt to send the message
        int rc = sctp_sendmsg(subctx->tx_socket_fds[port],
                              packet, total_size,
                              NULL, 0, 0, 0, 0, 0, 0);
        if (rc < 0) {
            if ((errno != EAGAIN) && (errno != ENOBUFS)) {
                ctx->ts_node.error_code = TEST_ERROR_MIXNET_CONNECTION_BROKEN;
                ctx->ts_node.exited = true;
                free(packet);

                pthread_exit(NULL);
            }
        }
        // SCTP transmission is non-atomic
        else if (rc != (int) total_size) {
            ctx->ts_node.error_code = TEST_ERROR_SCTP_PARTIAL_DATA;
            ctx->ts_node.exited = true;
            free(packet);

            pthread_exit(NULL);
        }
        // Successful transmission
        else { free(packet); return 1; }
    }
    return 0;
}

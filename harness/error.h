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
#ifndef HARNESS_ERROR_H
#define HARNESS_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

// Internal error codes
typedef enum test_error_code_t {
    // OK (DO NOT TOUCH)
    TEST_ERROR_NONE = 0,
    // Possible errors
    TEST_ERROR_FORK_FAILED,
    TEST_ERROR_EXEC_FAILED,
    TEST_ERROR_BAD_TESTCASE,
    TEST_ERROR_BAD_FRAGMENT_ID,
    TEST_ERROR_BAD_MESSAGE_CODE,
    TEST_ERROR_RECV_WAIT_TIMEOUT,
    TEST_ERROR_SCTP_PARTIAL_DATA,
    TEST_ERROR_SEND_REQS_TIMEOUT,
    TEST_ERROR_FRAGMENT_EXCEPTION,
    TEST_ERROR_SOCKET_BIND_FAILED,
    TEST_ERROR_SOCKET_ACCEPT_FAILED,
    TEST_ERROR_SOCKET_CREATE_FAILED,
    TEST_ERROR_SOCKET_LISTEN_FAILED,
    TEST_ERROR_SOCKET_CONNECT_FAILED,
    TEST_ERROR_SOCKET_ACCEPT_TIMEOUT,
    TEST_ERROR_FRAGMENT_PCAP_MQ_FULL,
    TEST_ERROR_FRAGMENT_SHUTDOWN_REQ,
    TEST_ERROR_CTRL_CONNECTION_BROKEN,
    TEST_ERROR_FRAGMENT_INVALID_SADDR,
    TEST_ERROR_FRAGMENT_INVALID_CADDR,
    TEST_ERROR_MIXNET_CONNECTION_BROKEN,
    TEST_ERROR_MIXNET_INVALID_PACKET_SIZE,
    TEST_ERROR_FRAGMENT_BAD_NEIGHBOR_COUNT,
    TEST_ERROR_FRAGMENT_THREADS_NONRESPONSIVE,
    TEST_ERROR_FRAGMENT_DUPLICATE_LOCAL_ADDRS,
}
test_error_code_t;

#ifdef __cplusplus
}
#endif

#endif // HARNESS_ERROR_H

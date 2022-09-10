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
#ifndef MIXNET_ADDRESS_H
#define MIXNET_ADDRESS_H

#include <stdint.h>

/**
 * Represents the address of a node on the Mixnet network. Each node is
 * identified by a unique, 16-bit address (somewhat like a MAC address).
 */
typedef uint16_t mixnet_address;

#endif // MIXNET_ADDRESS_H

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
#ifndef MIXNET_NODE_H
#define MIXNET_NODE_H

#include <stdbool.h>

#include "address.h"
#include "config.h"

void run_node(void *handle, volatile bool *keep_running,
              const struct mixnet_node_config config);

#endif  // MIXNET_NODE_H

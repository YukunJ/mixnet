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
#include "message.h"

uint16_t message_code_create(
    bool is_request, enum test_message_type_enum type) {
    return (uint16_t) ((!is_request) << 15) | (((uint16_t) type) & 0x7FFF);
}
bool message_code_is_request(const uint16_t message_code) {
    return ((message_code & 0x8000) == 0);
}
void message_code_reverse_polarity(uint16_t *message_code) {
    *message_code = (uint16_t) ((*message_code) ^ 0x8000);
}
test_message_type_t message_code_to_type(const uint16_t message_code) {
    return (test_message_type_t) (message_code & 0x7FFF);
}

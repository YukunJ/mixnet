#include "utils.h"
#include <assert.h>

bool int_equal(ELEMENT_TYPE lhs, ELEMENT_TYPE rhs) {
    return *((int *)lhs) == *((int *)rhs);
}

bool int_max(ELEMENT_TYPE lhs, ELEMENT_TYPE rhs) {
    return *((int *)lhs) > *((int *)rhs);
}

void int_printer(ELEMENT_TYPE e) {
    printf("%d ", *(int *)e);
}

bool mixnet_address_equal(ELEMENT_TYPE lhs, ELEMENT_TYPE rhs) {
    return *((mixnet_address *)lhs) == *((mixnet_address *)rhs);
}

void mixnet_address_printer(ELEMENT_TYPE e) {
    printf("%hu ", *(mixnet_address *)e);
}

int main() {
    printf("[A]. Start testing the implementation of dynamically-expanding vector\n");
    vector_t *vec = create_vector();
    printf("1. Inserting 0 to 99 into the vector...\n");
    for (int i = 0; i < 100; i++) {
        int *i_ptr = (int *)malloc(sizeof(int));
        *i_ptr = i;
        vec_push_back(vec, i_ptr);
    }
    assert(vec_size(vec) == 100 && vec->capacity == 128);
    printf("vector's size and capacity are correct\n============================\n");

    printf("2. Find i = 50 to 99 in the vector using int_equal functor\n");
    for (int i = 50; i < 100; i++) {
        int *i_ptr = (int *)malloc(sizeof(int));
        *i_ptr = i;
        assert(vec_find(vec, i_ptr, int_equal) == i);
        free(i_ptr);
    }
    printf("vector's find func returns correct index\n============================\n");

    printf("3. Find the max element in the vector using int_max functor\n");
    int64_t max_id = vec_find_best(vec, int_max);
    assert(max_id == 99 && *(int *)(vec_get(vec, max_id)) == 99);
    printf("vector's find_best func returns best index\n============================\n");

    printf("4. Remove vector by index 0~9 and then 10 ~ 89\n");
    for (int64_t i = 0; i < 10; i++) {
        assert(vec_remove_by_index(vec, 0) == true);
    }
    for (int64_t i = 10; i < 90; i++) {
        assert(vec_remove_by_index(vec, 10) == true);
    }
    assert(vec_size(vec) == 10);
    vec_print(vec, int_printer);
    printf("vector's remove func works correctly\n============================\n");

    printf("5. vector's clear method should clear out the data and set capacity back to default value\n");
    vec_clear(vec);
    assert(vec_size(vec) == 0 && vec->capacity == INITIAL_CAPACITY);
    printf("vector's clear method works correctly\n");

    free_vector(vec);
    printf("All dynamically-expanding vector tests passed. Vector freed\n");
    printf("===========================================================\n\n\n");

    printf("[B]. Start testing the implementation of graph node relying on vector\n");
    mixnet_address *host_id = (mixnet_address *)malloc(sizeof(mixnet_address));
    *host_id = 0;
    graph_node_t *node = create_graph_node(host_id);
    assert(graph_node_size(node) == 0);

    printf("1. Add 1 to 5 as host 0's neighbors, should all be successful addition\n");
    for (mixnet_address i = 1; i <= 5; i++) {
        mixnet_address *i_ptr = (mixnet_address *)malloc(sizeof(mixnet_address));
        *i_ptr = i;
        assert(graph_node_add_neighbor(node, i_ptr, mixnet_address_equal) == true);
    }
    assert(graph_node_size(node) == 5);
    printf("graph node's new addition of neighbor works correctly\n");

    printf("2. Add again 1 to 5 as host 0's neighbors, since they already exists, size should not change\n");
    for (mixnet_address i = 1; i <= 5; i++) {
        mixnet_address *i_ptr = (mixnet_address *)malloc(sizeof(mixnet_address));
        *i_ptr = i;
        assert(graph_node_add_neighbor(node, i_ptr, mixnet_address_equal) == false);
        free(i_ptr);
    }
    assert(graph_node_size(node) == 5);
    printf("graph node's addition of neighbor can handle duplicates correctly\n");

    printf("3. print out the current content of this graph node\n");
    graph_node_print(node, mixnet_address_printer);

    printf("4. graph node's clear method should clear out the neighbor and set back to default\n");
    graph_node_clear(node);
    assert(graph_node_size(node) == 0 && node->neighbors->capacity == INITIAL_CAPACITY);
    printf("graph node's clear method works correctly\n");

    free_graph_node(node);
    printf("All graph_node tests passed. graph node freed\n");
    printf("===========================================================\n");
    return 0;
}
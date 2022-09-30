/**
 * utils.h
 * This is the utility file for CP2 to support Linked-State-Routing-Protocol
 * It contains a dynamically-expanding vector which supports basic vector operation
 * and a graph_node which is essentially a linked list node containing a vector of neighbors
 * and a graph data structure for storing the neighbors of each node in the graph
 * and a simplified version of Dijkstra's algorithm for source routing
 * @author Yukun Jiang & Leo Guo
 * @date Sep 25 2022
 */
#include "address.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#ifndef MIXNET_UTILS_H
#define MIXNET_UTILS_H

/** the initial capacity of vector */
#define INITIAL_CAPACITY 4

/** the multiplicative factor when resizing the vector */
#define MUL_FACTOR 2

/** the default element type for vector is void *, so it could generically handle any data type */
#define ELEMENT_TYPE void *


// ======================== vector ========================= //
/*
 * the dynamic expanding vector
 * NOT thread-safe be careful
 * use generic pointer "void *" as its element type, so it can hold any type
 * if you need to find an element in the vector,
 * it needs to be provided with a comparator function pointer
*/
typedef struct vector {
    ELEMENT_TYPE *data;
    int64_t size;
    int64_t capacity;
} vector_t;

/**
 * Create a new vector with the default initial capacity
 * @return pointer to dynamically allocated vector
 */
vector_t *create_vector() {
    vector_t *new_vector = (vector_t *)malloc(sizeof(vector_t));
    new_vector->data = (void **)calloc(INITIAL_CAPACITY, sizeof(ELEMENT_TYPE));
    new_vector->size = 0;
    new_vector->capacity = INITIAL_CAPACITY;
    return new_vector;
}

/**
 * Release the dynamically-allocated memory for vector and its data
 * @param vec pointer to a vector
 */
void free_vector(vector_t *vec) {
    if (vec) {
        for (int64_t i = 0; i < vec->size; i++) {
            free(vec->data[i]);
        }
        free(vec);
    }
}

/**
 * Expand the vector by twice the size and copy over the data
 * local-only visible func
 * @param vec pointer to a vector
 */
static void vec_expand(vector_t *vec) {
    ELEMENT_TYPE *old_data = vec->data;
    ELEMENT_TYPE *new_data = (void **)calloc(MUL_FACTOR * vec->capacity, sizeof(ELEMENT_TYPE));
    memcpy(new_data, vec->data, sizeof(ELEMENT_TYPE) * vec->capacity);
    vec->capacity *= MUL_FACTOR;
    vec->data = new_data;
    free(old_data);
}

/**
 * Get the current size of the vector
 * @param vec pointer to a vector
 * @return size of the vector
 */
int64_t vec_size(vector_t *vec) {
    return vec->size;
}

/**
 * Get the idx-th element in the vector
 * @param vec pointer to a vector
 * @param idx the index to be retrieved
 * @return the element (a pointer type), or NULL if the index is inappropriate
 */
ELEMENT_TYPE vec_get(vector_t *vec, int64_t idx) {
    if (idx < 0 || idx >= vec->size) {
        return NULL;
    }
    return vec->data[idx];
}

/**
 * Insert an element at the back of the vector
 * if the size reaches capacity, do dynamic expanding on the fly
 * @attention once the element enters this vector, vector will control its lifecycle
 * including free its dynamically allocated memory in the end
 * @param vec pointer to a vector
 * @param e the element to be inserted
 */
void vec_push_back(vector_t *vec, ELEMENT_TYPE e) {
    if (vec->size == vec->capacity) {
        vec_expand(vec);
    }
    vec->data[vec->size] = e;
    vec->size++;
}

/**
 * Reverse the order of elements in the vector
 * @param vec pointer to a vector
 */
void vec_reverse(vector_t *vec) {
    int64_t left = 0, right = vec->size-1;
    ELEMENT_TYPE temp;
    while (left < right) {
        temp = vec->data[left];
        vec->data[left] = vec->data[right];
        vec->data[right] = temp;
        left++;
        right--;
    }
}

/**
 * Find the best element in the vector
 * according to the specific comparator function
 * this comparator should return True when the left hand side is better than rhs
 * @param vec pointer to a vector
 * @param comp a function pointer that return True if left hand side is better than rhs
 * @return the index of best element in this vector, or -1 indicates problem
 */
int64_t vec_find_best(vector_t *vec, bool (*comp)(ELEMENT_TYPE, ELEMENT_TYPE)) {
    if (!vec->size) {
        return -1;
    }
    int64_t best_index = 0;
    for (int64_t i = 1; i < vec->size; i++) {
        if ((*comp)(vec->data[i], vec->data[best_index])) {
            best_index = i;
        }
    }
    return best_index;
}

/**
 * To Locate a specific element in the vector
 * require the input of a comparator
 * can be used together with the vec_remove_by_index function below
 * @param vec pointer to a vector
 * @param element_to_find the element to be find
 * @param comp a function pointer act as the equal comparator, return True if two input is considered equal
 * @return index of that element if found, or -1
 */
int64_t vec_find(vector_t *vec, ELEMENT_TYPE element_to_find, bool (*comp)(ELEMENT_TYPE, ELEMENT_TYPE)) {
    for (int64_t i = 0; i < vec->size; i++) {
        if ((*comp)(vec->data[i], element_to_find)) {
            return i;
        }
    }
    return -1;
}

/**
 * Remove the element specified at the index
 * @param vec pointer to a vector
 * @param idx the index of the element to be removed
 * @return true if such deletion is successfully
 */
bool vec_remove_by_index(vector_t *vec, int64_t idx) {
    if (idx < 0 || idx >= vec->size) {
        // the index is not within correct range
        return false;
    }
    free(vec->data[idx]);
    for (int64_t i = idx; i < vec->size-1; i++) {
        // shift right hand by one index to the left
        vec->data[i] = vec->data[i+1];
    }
    vec->size--;
    return true;
}

/**
 * Replace the vector's element at a specific index by a new one
 * @param vec pointer to a vector
 * @param idx the index of the element to be replaced
 * @param new_element pointer to a new element
 * @return true if such replacement is successfully
 */
bool vec_replace_by_index(vector_t *vec, int64_t idx, ELEMENT_TYPE new_element) {
    if (idx < 0 || idx >= vec->size) {
        // the index is not within correct range
        return false;
    }
    free(vec->data[idx]);
    vec->data[idx] = new_element;
    return true;
}

/**
 * Clear out the data in vec and reset to default state
 * @param vec pointer to a vector
 */
void vec_clear(vector_t *vec) {
    if (vec) {
        for (int64_t i = 0; i < vec->size; i++) {
            free(vec->data[i]);
        }
        free(vec->data);
        vec->data = (void **)calloc(INITIAL_CAPACITY, sizeof(ELEMENT_TYPE));
        vec->size = 0;
        vec->capacity = INITIAL_CAPACITY;
    }
}

/**
 * Helper function to print a vector with the provided printer function for each element
 * @param vec pointer to a vector
 * @param element_printer function printer that prints out an individual element
 */
void vec_print(vector_t *vec, void (element_printer)(ELEMENT_TYPE)) {
    printf("Printer: Vector of size %lld and capacity %lld, contents as follow:\n", (long long)vec->size, (long long)vec->capacity);
    for (int64_t i = 0; i < vec->size; i++) {
        (*element_printer)(vec->data[i]);
    }
    printf("\n");
}

// ======================= graph node ======================= //
/*
 * the graph node holds an entry in the graph
 * with one host and a vector of its neighbors
 * you can think of it as a pair of <host_id, vector of neighbor id>
 *
 * the graph node itself forms a structure of singly linked list
 * that will be manipulated by outside graph structure
 *
 * For our specific usage, we expect the host and element in the vector
 * to be of same type implicitly
 */
typedef struct graph_node {
    ELEMENT_TYPE host;
    vector_t *neighbors;
    struct graph_node *next;
} graph_node_t;

/**
 * Create a graph node with the host identifier
 * @param host a pointer to the host identifier
 * @return pointer to the newly created graph node
 */
graph_node_t *create_graph_node(ELEMENT_TYPE host) {
    graph_node_t* node = (graph_node_t *)malloc(sizeof(graph_node_t));
    node->host = host;
    node->neighbors = create_vector();
    node->next = NULL;
    return node;
}

/**
 * Release the dynamically-allocated memory for graph
 * including its host identifier and
 * @param node pointer to a graph node
 */
void free_graph_node(graph_node_t *node) {
    if (node) {
        if (node->host != NULL) {
            // sentinel head's host is NULL
            free(node->host);
        }
        free_vector(node->neighbors);
        node->next = NULL;
        free(node);
    }
}

/**
 * Get the size of how many neighbors this graph node is holding
 * @param node pointer to a graph node
 * @return count of how many neighbors
 */
int64_t graph_node_size(graph_node_t *node) {
    return vec_size(node->neighbors);
}

/**
 * Try to add a neighbor into this graph node if not exists yet
 * @param node pointer to a graph node
 * @param new_neighbor pointer to a new neighbor's host identifier
 * @param equal_comp function pointer to a func if two neighbors are the same, true if the same
 * @return true if the addition is successful, false if already exists
 */
bool graph_node_add_neighbor(graph_node_t *node, ELEMENT_TYPE new_neighbor, bool (*equal_comp)(ELEMENT_TYPE, ELEMENT_TYPE)) {
    for (int64_t i = 0; i < node->neighbors->size; i++) {
        if ((*equal_comp)(new_neighbor, node->neighbors->data[i])) {
            free(new_neighbor);
            return false;
        }
    }
    vec_push_back(node->neighbors, new_neighbor);
    return true;
}

/**
 * Clear a graph node by removing all the existing neighbors
 * @param node pointer to a graph node
 */
void graph_node_clear(graph_node_t *node) {
    if (node) {
        vec_clear(node->neighbors);
    }
}

/**
 * Print out the graph node with the provided printer
 * the printer is applied both to the host and its each neighbor
 * @param node pointer to a graph node
 * @param printer function node to print out an individual element
 */
void graph_node_print(graph_node_t *node, void (*printer)(ELEMENT_TYPE)) {
    if (node) {
        printf("Graph node: host = ");
        (*printer)(node->host);
        printf(" has the following neighbors: [");
        for (int64_t i = 0; i < node->neighbors->size; i++) {
            (*printer)(node->neighbors->data[i]);
        }
        printf("]\n");
    }
}

// ======================== graph  ======================== //

/*
 * the graph data structure using adjacent list representation
 * it contains a single linked list of graph node, each node represent one host
 * such node contains a vector of that host's neighbor
 * this graph has a sentinel dummy header, i.e. the first node is always dummy
 * and it needs a equal_comparator when adding new neighbors into this graph
 */
typedef struct graph {
    graph_node_t *head;
    bool (*equal_comp)(ELEMENT_TYPE, ELEMENT_TYPE);
} graph_t;

/**
 * Create a graph data structure
 * @param equal_comp function pointer for testing if two elements are the same
 * @return pointer to a newly created graph
 */
graph_t *create_graph(bool (*equal_comp)(ELEMENT_TYPE, ELEMENT_TYPE)) {
    graph_t *graph = (graph_t *)malloc(sizeof(graph));
    graph->head = create_graph_node(NULL);
    graph->equal_comp = equal_comp;
    return graph;
}

/**
 * Release the dynamically allocated memory for the graph data structure
 * @param graph pointer to a graph
 */
void free_graph(graph_t *graph) {
    if (graph) {
        graph_node_t *next;
        graph_node_t *curr = graph->head;
        while (curr) {
            next = curr->next;
            free_graph_node(curr);
            curr = next;
        }
        free(graph);
    }
}

/**
 * Find a vertex in the graph specified by its host identifier
 * @param graph pointer to a graph
 * @param vertex_host pointer to a vertex host identifier
 * @return pointer to graph_node if found, NULL if not exist in the graph
 */
graph_node_t *graph_find_vertex(graph_t *graph, ELEMENT_TYPE vertex_host) {
    graph_node_t *curr = graph->head->next;
    while (curr) {
        if ((*graph->equal_comp)(curr->host, vertex_host)) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/**
 * Add a new vertex to the end of the linked list of this graph
 * caller should make sure that there is no existing vertex of this host identifier in the graph
 * @param graph pointer to a graph
 * @param vertex_host pointer to a vertex host identifier
 * @return pointer to the newly added vertex graph node
 */
graph_node_t *graph_add_vertex(graph_t *graph, ELEMENT_TYPE vertex_host) {
    graph_node_t *new_node = create_graph_node(vertex_host);
    graph_node_t *prev = graph->head;
    graph_node_t *curr = graph->head->next;
    while (curr) {
        prev = curr;
        curr = curr->next;
    }
    prev->next = new_node;
    return new_node;
}

/**
 * Try to add an edge with host's new neighbor into the graph
 * @param graph pointer to a graph
 * @param host pointer to a vertex host identifier
 * @param neighbor pointer to a neighbor identifier
 * @attention each neighbor must exclusively have their heap space
 * i.e. you cannot insert twice without allocate a new space with same value
 * @return true if the addition is successfully, false if already exists
 */
bool graph_add_edge(graph_t *graph, ELEMENT_TYPE host, ELEMENT_TYPE neighbor) {
    graph_node_t *vertex = graph_find_vertex(graph, host);
    if (!vertex) {
        vertex = graph_add_vertex(graph, host);
    } else {
        free(host);
    }
    return graph_node_add_neighbor(vertex, neighbor, graph->equal_comp);
}

/**
 * Print out the whole graph structure using the provided printer function
 * @param graph pointer to a graph
 * @param printer function printer to print each individual element
 */
void graph_print(graph_t *graph, void (*printer)(ELEMENT_TYPE)) {
    printf("The graph consists of the following vertex:\n");
    graph_node_t *curr = graph->head->next;
    while (curr) {
        graph_node_print(curr, printer);
        curr = curr->next;
    }
}

// ======================== MixNet specific  ======================== //

#define INFINITY (INT64_MAX / 2)

/*
 * the dijkstra_triple helps to maintain the computation result during
 * Dijkstra's shortest path algrithm by tracking both the current
 * distance to a node, but also it's last hop
 * so that we may reconstruct the whole path later on
 */
typedef struct dijkstra_triple {
    mixnet_address destination;
    mixnet_address last_hop;
    int64_t distance;
} dijkstra_t;

/**
 * Helper function to allcate a dijkstra triple with given paramter
 */
dijkstra_t *create_dijkstra_triple(mixnet_address destination, mixnet_address last_hop, int64_t distance) {
    dijkstra_t *triple = (dijkstra_t *)malloc(sizeof(dijkstra_t));
    triple->destination = destination;
    triple->last_hop = last_hop;
    triple->distance = distance;
    return triple;
}

/**
 * Function comparator to test against if two dijkstra_triple are the same
 * key on the destination, the rhs is just a plain pointer to mixnet_address
 * while lhs is a full dijkstra_triple
 */
bool dijkstra_triple_equal(ELEMENT_TYPE lhs, ELEMENT_TYPE rhs) {
    return ((dijkstra_t *)lhs)->destination == (*(mixnet_address *)rhs);
}

/**
 * Fetching the smallest distance triple
 * return true if left hand side is better
 * if distance equal prefer lower indexed destination
 */
bool dijkstra_triple_better(ELEMENT_TYPE lhs, ELEMENT_TYPE rhs) {
    dijkstra_t *lhs_t = (dijkstra_t *)lhs;
    dijkstra_t *rhs_t = (dijkstra_t *)rhs;
    if (lhs_t->distance != rhs_t->distance) {
        return lhs_t->distance < rhs_t->distance;
    } else {
        return lhs_t->destination < rhs_t->destination;
    }
}

/**
 * Function comparator to test against if two mixnet address pointer are the same
 */
bool mixnet_address_equal(ELEMENT_TYPE lhs, ELEMENT_TYPE rhs) {
    return *((mixnet_address *)lhs) == *((mixnet_address *)rhs);
}

/**
 * Function pointer to print out a mixnet address
 */
void mixnet_address_printer(ELEMENT_TYPE e) {
    printf("%hu ", *(mixnet_address *)e);
}

/**
 * Helper function to add an edge <host, neighbor> into the graph
 * the graph will manage the lifecycle of the dynamically allocated space
 * @param graph pointer to a graph
 * @param host mixnet address of the host
 * @param neighbor mixnet address of the neighbor
 * @return true if addition is successful, false if already exists
 */
bool mixnet_add_neighbor(graph_t *graph, mixnet_address host, mixnet_address neighbor) {
    mixnet_address *host_ptr = (mixnet_address *)malloc(sizeof(mixnet_address));
    mixnet_address *neighbor_ptr = (mixnet_address *)malloc(sizeof(mixnet_address));
    *host_ptr = host;
    *neighbor_ptr = neighbor;
    return graph_add_edge(graph, host_ptr, neighbor_ptr);
}

/**
 * The point-to-point shortest path algorithm
 * @param graph pointer to a graph
 * @param source source node
 * @return pointer to a vector containing result triples, user should free it after usage by 'free_vector()'
 */
vector_t *dijkstra_shortest_path(graph_t *graph, mixnet_address source) {
    // first create container for results and in-progress triple
    vector_t *finished = create_vector();
    vector_t *progress = create_vector();

    // add each **unique node** to the progress "priority queue"
    vec_push_back(progress, create_dijkstra_triple(source,source, 0)); // source node is 0 distance
    graph_node_t *curr = graph->head->next;
    while (curr) {
        // add a new node if it's unique
        if (vec_find(progress, curr->host, dijkstra_triple_equal) == -1) {
            vec_push_back(progress, create_dijkstra_triple(*(mixnet_address *)(curr->host), *(mixnet_address *)(curr->host), INFINITY));
        }
        for (int64_t i = 0; i < graph_node_size(curr); i++) {
            mixnet_address *neighbor_ptr = vec_get(curr->neighbors, i);
            if (vec_find(progress, neighbor_ptr, dijkstra_triple_equal) == -1) {
                vec_push_back(progress, create_dijkstra_triple(*neighbor_ptr, *neighbor_ptr, INFINITY));
            }
        }
        curr = curr->next;
    }

    // fetch smallest distance node each time, and try update neighbor-reaching distance accordingly
    while (vec_size(progress) > 0) {
        // find the smallest distance triple
        int64_t smallest_idx = vec_find_best(progress, dijkstra_triple_better);
        assert(smallest_idx != -1);
        dijkstra_t *smallest_triple = vec_get(progress, smallest_idx);
        mixnet_address curr_destination = smallest_triple->destination;
        mixnet_address curr_last_hop = smallest_triple->last_hop;
        int64_t curr_dist = smallest_triple->distance;
        // mark this destination as finished
        vec_push_back(finished, create_dijkstra_triple(curr_destination, curr_last_hop, curr_dist));
        // grab all the neighbors and try update, each hop is 1 distance by assumption
        graph_node_t *node = graph_find_vertex(graph, &curr_destination);
        assert(node != NULL);
        for (int64_t i = 0; i < graph_node_size(node); i++) {
            void *neighbor = vec_get(node->neighbors, i);
            int64_t neighbor_idx = vec_find(progress, neighbor, dijkstra_triple_equal);
            if (neighbor_idx != -1) {
                // this neighbor is not yet finished, might be able to update distance
                dijkstra_t *neighbor_triple = vec_get(progress, neighbor_idx);
                if (1 + curr_dist < neighbor_triple->distance) {
                    // make a new triple to replace the old position
                    dijkstra_t *new_triple = create_dijkstra_triple(neighbor_triple->destination, curr_destination, 1 + curr_dist);
                    vec_replace_by_index(progress, neighbor_idx, new_triple);
                }
            }
        }
        // remove the fetched-out triple from progress vector
        vec_remove_by_index(progress, smallest_idx);
    }
    return finished;
}

/**
 * Construct the shortest path from source to destination according to Dijkstra's result
 * @param dijkstra_shortest_triple vector of dijkstra calculation triples
 * @param source source mixnet address
 * @param destination destination mixnet address
 * @return pointer to a vector of shortest path
 */
vector_t *construct_path(vector_t *dijkstra_shortest_triple, mixnet_address source, mixnet_address destination) {
    vector_t *path = create_vector();
    mixnet_address to_find = destination;
    while (to_find != source) {
        int64_t idx = vec_find(dijkstra_shortest_triple, &to_find, dijkstra_triple_equal);
        assert(idx != -1);
        mixnet_address *curr_hop = (mixnet_address *)malloc(sizeof(mixnet_address));
        *curr_hop = ((dijkstra_t *)vec_get(dijkstra_shortest_triple, idx))->destination;
        vec_push_back(path, curr_hop);
        to_find = ((dijkstra_t *)vec_get(dijkstra_shortest_triple, idx))->last_hop;
    }
    mixnet_address *source_cpy = (mixnet_address *)malloc(sizeof(mixnet_address));
    *source_cpy = source;
    vec_push_back(path, source_cpy);
    vec_reverse(path); // going from source to destination
    return path;
}

#endif //MIXNET_UTILS_H

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
void vec_push_back(vector_t *vec, void *e) {
    if (vec->size == vec->capacity) {
        vec_expand(vec);
    }
    vec->data[vec->size] = e;
    vec->size++;
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
    if (!vec_size(vec)) {
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
        free(node->host);
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

#endif //MIXNET_UTILS_H

/**
 * utils.h
 * This is the utility file for CP2 to support Linked-State-Routing-Protocol
 * It contains a dynamically-expanding vector which supports basic vector operation
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
    new_vector->data = calloc(INITIAL_CAPACITY, sizeof(ELEMENT_TYPE));
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
    ELEMENT_TYPE *new_data = calloc(MUL_FACTOR * vec->capacity, sizeof(ELEMENT_TYPE));
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
 * @return the element, or NULL if the index is inappropriate
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
        vec->data = calloc(INITIAL_CAPACITY, sizeof(ELEMENT_TYPE));
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
#endif //MIXNET_UTILS_H

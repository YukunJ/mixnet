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

int main() {
    printf("A. Start testing the implementation of dynamically-expanding vector\n");
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

    free_vector(vec);
    printf("All dynamically-expanding vector tests passed. Vector freed\n");
    printf("===========================================================\n");
    return 0;
}
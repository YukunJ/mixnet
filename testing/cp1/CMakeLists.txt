link_libraries(rt
               mixnet
               harness
               testing
               orchestrator
               message_queue
               ${CMAKE_THREAD_LIBS_INIT})

add_executable(cp1_test_line_hard   test_line_hard.cpp)
add_executable(cp1_test_line_easy   test_line_easy.cpp)
add_executable(cp1_test_tree        test_tree.cpp)
add_executable(cp1_test_ring_easy   test_ring_easy.cpp)
add_executable(cp1_test_ring_hard   test_ring_hard.cpp)
add_executable(cp1_test_unreachable test_unreachable.cpp)

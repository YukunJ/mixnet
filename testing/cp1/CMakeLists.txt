link_libraries(rt
               mixnet
               harness
               testing
               orchestrator
               message_queue
               ${CMAKE_THREAD_LIBS_INIT})

add_executable(cp1_test_line_easy           test_line_easy.cpp)
add_executable(cp1_test_line_hard           test_line_hard.cpp)
add_executable(cp1_test_tree_easy           test_tree_easy.cpp)
add_executable(cp1_test_tree_medium         test_tree_medium.cpp)
add_executable(cp1_test_tree_hard           test_tree_hard.cpp)
add_executable(cp1_test_ring_easy           test_ring_easy.cpp)
add_executable(cp1_test_ring_hard           test_ring_hard.cpp)
add_executable(cp1_test_full_mesh_easy      test_full_mesh_easy.cpp)
add_executable(cp1_test_full_mesh_hard      test_full_mesh_hard.cpp)
add_executable(cp1_test_tiebreak_pathlen    test_tiebreak_pathlen.cpp)
add_executable(cp1_test_link_failure_root   test_link_failure_root.cpp)
add_executable(cp1_test_link_failure_ring   test_link_failure_ring.cpp)
add_executable(cp1_test_link_failure_mesh   test_link_failure_mesh.cpp)
add_executable(cp1_test_unreachable         test_unreachable.cpp)

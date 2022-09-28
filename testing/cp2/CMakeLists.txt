link_libraries(rt
               mixnet
               harness
               testing
               orchestrator
               message_queue
               ${CMAKE_THREAD_LIBS_INIT})

add_executable(cp2_test_sp_data_line        test_sp_data_line.cpp)
add_executable(cp2_test_sp_data_ring        test_sp_data_ring.cpp)
add_executable(cp2_test_sp_data_mesh        test_sp_data_mesh.cpp)
add_executable(cp2_test_random_data         test_random_data.cpp)
add_executable(cp2_test_mix_data            test_mix_data.cpp)
add_executable(cp2_test_ping                test_ping.cpp)

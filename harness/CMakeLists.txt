# CXX flags
add_compile_options(-m64 -O3 -Wall)

link_libraries(sctp)
add_library(harness SHARED networking.c message.c)

link_libraries(rt
               mixnet
               harness
               message_queue
               ${CMAKE_THREAD_LIBS_INIT})

add_library(fragment SHARED fragment.c)
add_library(orchestrator SHARED orchestrator.cpp)

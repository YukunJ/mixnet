# CXX flags
add_compile_options(-m64 -O3 -Wall)

add_library(message_queue SHARED
    message_queue.c
)

# CXX flags
add_compile_options(-m64 -O3 -pedantic-errors
                    -Wno-pointer-arith -Wall
                    -Wextra -Werror)

add_library(message_queue SHARED
    message_queue.c
)

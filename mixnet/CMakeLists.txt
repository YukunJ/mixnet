# CXX flags
add_compile_options(-m64 -O3 -pedantic-errors
                    -Wall -Wextra -Werror)

link_libraries(sctp message_queue)
add_library(mixnet SHARED connection.c)

# Compile node
link_libraries(mixnet
               fragment)

add_executable(node node.c)

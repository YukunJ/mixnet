# CXX flags
add_compile_options(-m64 -O3 -pedantic-errors
                    -Wall -Wextra -Werror)

add_library(testing SHARED
    test_common.cpp
)

# Includes
include_directories(.)

# Test sources
add_subdirectory(cp1)

cmake_minimum_required(VERSION 3.24)
project(ctr_cypher C)

set(CMAKE_C_STANDARD 11)

include_directories("include")

set(OPENMP_LIBRARIES "/opt/homebrew/opt/libomp/lib")
set(OPENMP_INCLUDES "/opt/homebrew/opt/libomp/include")

find_package(OpenMP REQUIRED)
if (OPENMP_FOUND)
    include_directories("${OPENMP_INCLUDES}")
    link_directories("${OPENMP_LIBRARIES}")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lomp -Ofast -Wall -Wpedantic ${OpenMP_C_FLAGS}")
endif()

add_executable(ctr_cypher src/main.c src/aes.c)

cmake_minimum_required(VERSION 3.5)

project(optimin
    LANGUAGES CXX
    DESCRIPTION "MaxSAT-based fuzzing corpus minimizer"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost COMPONENTS container REQUIRED)
message(STATUS "Found Boost ${Boost_VERSION_STRING}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")

include_directories(${Boost_INCLUDE_DIR})

add_subdirectory(EvalMaxSAT)
add_subdirectory(src)

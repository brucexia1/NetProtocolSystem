cmake_minimum_required(VERSION 2.8)
project(crypto)



# Add header file include directories
set(TOP_PATH ${CMAKE_CURRENT_SOURCE_DIR})
include_directories(
${TOP_PATH}/include
)

add_subdirectory(libcryptoo)
add_subdirectory(test)

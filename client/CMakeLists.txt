cmake_minimum_required(VERSION 3.16)

project(client)


set(CMAKE_CXX_STANDARD 17)


add_executable(client testBotan.cpp)

include_directories("/usr/local/include/botan-2")
target_link_libraries(client "/usr/local/lib/libbotan-2.so")

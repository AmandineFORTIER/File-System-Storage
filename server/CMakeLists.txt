cmake_minimum_required(VERSION 3.16)

project(server)


set(CMAKE_CXX_STANDARD 17)

find_package( Threads )
add_executable(server tlsSever.cpp)

include_directories("/usr/local/include/botan-2")
target_link_libraries(server "/usr/local/lib/libbotan-2.so" ${CMAKE_THREAD_LIBS_INIT})

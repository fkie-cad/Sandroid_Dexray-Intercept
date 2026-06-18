cmake_minimum_required(VERSION 3.22.1)

project("networke2e")

# Native socket syscall tests (send, recv, sendmsg, recvmsg, close)
add_library(
        net_native_sockets
        SHARED
        net_native_sockets.c
)

find_library(log-lib log)

target_link_libraries(
        net_native_sockets
        ${log-lib}
)
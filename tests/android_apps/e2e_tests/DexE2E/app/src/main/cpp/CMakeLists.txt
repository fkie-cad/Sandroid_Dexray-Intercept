cmake_minimum_required(VERSION 3.22.1)
project("dexe2e_native")

add_library(dexe2e_native SHARED dexe2e_native.c)
target_link_libraries(dexe2e_native android log)
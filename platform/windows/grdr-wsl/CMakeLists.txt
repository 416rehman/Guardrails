cmake_minimum_required(VERSION 3.24)
project(grdr_wsl C)

add_library(grdr-wsl SHARED
    grdr_wsl_plugin.c
    grdr_wsl.def
)
set_target_properties(grdr-wsl PROPERTIES OUTPUT_NAME "grdr-wsl")
target_link_libraries(grdr-wsl PRIVATE kernel32 advapi32)

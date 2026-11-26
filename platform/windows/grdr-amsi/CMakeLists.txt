cmake_minimum_required(VERSION 3.24)
project(grdr_amsi C)

add_library(grdr-amsi SHARED
    grdr_amsi_provider.c
    grdr_amsi.def
)
set_target_properties(grdr-amsi PROPERTIES OUTPUT_NAME "grdr-amsi")
target_link_libraries(grdr-amsi PRIVATE kernel32 advapi32 ole32)

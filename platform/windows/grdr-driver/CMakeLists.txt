# Requires Enterprise WDK + Microsoft WHCP HLK / EV code signing ([EXT]).
cmake_minimum_required(VERSION 3.24)
project(grdr_driver C)

find_package(WDK QUIET)
if(NOT WDK_FOUND)
    message(FATAL_ERROR "Windows Driver Kit (WDK) is required to build grdr-driver.sys ([EXT])")
endif()

wdk_add_driver(grdr_driver
    KMDF 1.15
    grdr_driver.c
    grdr_driver_protocol.h
)
target_link_libraries(grdr_driver WDK::FLTMGR WDK::FWPKCLNT)

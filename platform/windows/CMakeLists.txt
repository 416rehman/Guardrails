cmake_minimum_required(VERSION 3.24)
project(grdr_windows_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(GRDR_BUILD_KMDF_DRIVER "Build kernel-mode grdr-driver.sys (requires Enterprise WDK + WHCP)" OFF)

add_subdirectory(grdr-wsl)
add_subdirectory(grdr-amsi)

if(GRDR_BUILD_KMDF_DRIVER)
    add_subdirectory(grdr-driver)
endif()

# Project stamps
cmake_minimum_required(VERSION 3.10)
project(leave_me_here VERSION 1.0.0)

# Set C++ standard to C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include memflow libraries
include_directories(
    ${CMAKE_SOURCE_DIR}/Library/memflow/sdk
)

# Optional: link your libs here too if needed
link_directories(${CMAKE_SOURCE_DIR}/Library/memflow/sdk)

add_executable(
    leave_me_here
    main.cpp
    Core/Memflow/Memflow.cpp
)

# Link against memflow_ffi and other system libs
target_link_libraries(leave_me_here memflow_ffi dl pthread)

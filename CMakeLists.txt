cmake_minimum_required(VERSION 3.20)

project(DeadStop LANGUAGES CXX)

# C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Needed for compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})

file(GLOB_RECURSE SRC_FILES
    CONFIGURE_DEPENDS
    src/*.cpp
)
    
add_executable(main ${SRC_FILES})
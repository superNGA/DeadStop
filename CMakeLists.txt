cmake_minimum_required(VERSION 3.20)

project(DeadStop LANGUAGES CXX)

message(STATUS "C compiler:       ${CMAKE_C_COMPILER}")
message(STATUS "C++ compiler:     ${CMAKE_CXX_COMPILER}")
message(STATUS "Compiler ID:      ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version: ${CMAKE_CXX_COMPILER_VERSION}")

# C++ standard
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)


add_executable(DeadStop

# Include
"Include/Alias.h"
"Include/DeadStop.h"

# Util
"src/Util/Terminal/Terminal.h"
"src/Util/Terminal/ConsoleSystem.h"
"src/Util/Terminal/ConsoleSystem.cpp"

# src
"src/DeadStop.cpp"

# Example ( main.cpp )
"main.cpp"

)


target_compile_features(DeadStop PRIVATE cxx_std_17)

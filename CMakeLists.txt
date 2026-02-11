cmake_minimum_required(VERSION 3.20)

project(DeadStop LANGUAGES CXX)

message(STATUS "C compiler:       ${CMAKE_C_COMPILER}")
message(STATUS "C++ compiler:     ${CMAKE_CXX_COMPILER}")
message(STATUS "Compiler ID:      ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler version: ${CMAKE_CXX_COMPILER_VERSION}")

add_subdirectory(lib/IDASM)

# C++ standard
set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)


add_library(${PROJECT_NAME}

    # Util
    "src/Util/Terminal/Terminal.h"
    "src/Util/Terminal/ConsoleSystem.h"
    "src/Util/Terminal/ConsoleSystem.cpp"
    "src/Util/Assertion/Assertion.h"

    # src
    "src/DeadStop.cpp"
    "src/DeadStopImpl.h"
    "src/DeadStopImpl.cpp"

    # SignalHandler
    "src/SignalHandler/SignalHandler.h"
    "src/SignalHandler/SignalHandler.cpp"

    # Defs
    "src/Defs/MemRegion_t.h"
    "src/Defs/MemRegion_t.cpp"
)

target_link_libraries(${PROJECT_NAME} PRIVATE INSANE_DisassemblerAMD64)
target_compile_features(DeadStop PRIVATE cxx_std_17)
# To build with omitted stack frames.
# target_compile_options(DeadStop PRIVATE $<$<CXX_COMPILER_ID:GNU>:-fomit-frame-pointer>)


# Building example.
add_executable(DeadStopExample1 ${CMAKE_CURRENT_SOURCE_DIR}/Example/Example1.cpp)
target_link_libraries(DeadStopExample1 PRIVATE ${PROJECT_NAME})

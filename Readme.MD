<h1 align="center"> DeadStop </h1>

<p align="center"><i>
  <strong>A lightweight crash logging library for Linux x86_64</strong>
</i></p>

<p align="center">
  DeadStop catches crash signals, walks the call stack, disassembles the offending functions, and searches nearby memory for valid string references — providing richer context than a standard backtrace, without the overhead of full core dumps.
</p>

## Features

- **Signal Handling**: Intercepts common crash signals (SIGSEGV, SIGABRT, SIGILL, SIGFPE, etc.)
- **Call Stack Walking**: Reliable stack unwinding with configurable maximum depth
- **Function Disassembly**: Full AMD64 instruction disassembly around return addresses
- **String Reference Detection**: Scans memory near crash pointers and return addresses for valid UTF-8/ASCII strings
- **Detailed Crash Report**: Outputs human-readable logs with assembly, addresses, and discovered strings
- **Signature Dump**: IDA style signature at each return / crash location to easy find crashing function in static analysis tools.


## Requirements

- Linux x86_64
- C++17-compliant compiler (GCC or Clang recommended)
- NASM (required to build the disassembler submodule)

## Installation

```bae
git clone --recursive https://github.com/superNGA/DeadStop.git
cd DeadStop
mkdir out
cmake -S . -B out/
cmake --build out/
```
Now, you should have the static lib with the example executable in our DeadStop/out/ folder,
or you can just use the prebuild binary from the release section.

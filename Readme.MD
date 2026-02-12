<h1 align="center"> DeadStop </h1>

<p align="center"><i>
  A linux x86_64 only crash logging library similar to "core dump".
</i></p>

## Overview

If u crash, it catches the signal, and walks the call stack and write each function's
assembly code with any refrences strings.

## Features

- Searches pointers around crash / return addresses for valid string.
- Adjustable call stack depth.
- good ?

## Submodule

- github.com/superNGA/INSANE_DisassemblerAMD64

## Requirements

- C++17-compliant compiler (e.g., MSVC, GCC, Clang)
- NASM assembler (For submodule)

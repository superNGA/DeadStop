cmake -S . -B build Ninja
cmake -E copy build/compile_commands.json compile_commands.json

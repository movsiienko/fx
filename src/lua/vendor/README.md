# Vendored Lua

This folder holds the C source of Lua 5.4.8 from lua.org, which fx embeds to run extension hooks. `build.zig` compiles it into the native fx binary only. The license is at the end of `lua.h` and in `THIRD_PARTY_NOTICES.md`.

The folder keeps only the core, the auxiliary library, and the `base`, `string`, `table`, `math`, and `utf8` libraries. The `io`, `os`, `package`, `debug`, and `coroutine` libraries, `linit.c`, and the standalone `lua` and `luac` programs are left out, and `scripts/check-lua-boundary.sh` fails if one comes back.

The instruction budget counts only Lua instructions, so a loop inside one C call runs until it ends. fx changes two files to bound the work of library calls whose loops the budget cannot see. Each change is marked with an `fx:` comment:

- In `lstrlib.c`, a pattern match counts its steps and stops with "pattern too complex" after `MAXMATCHSTEPS`.
- In `lstrlib.c`, `string.rep` returns `""` at once when the string and the separator are both empty, instead of looping `n` times to build nothing.
- In `ltablib.c`, `table.insert`, `table.remove`, `table.move`, `table.concat`, and `table.sort` work over at most `MAXTABELEMS` (2^22) elements per call and fail beyond it with "too many elements to move", "too many elements to concatenate", or "array too big". Their counts come from arguments or a `__len` metamethod, and a C function such as `rawequal` can serve as `__index` or `__newindex`, so the loop need not run Lua code or allocate. 2^22 slots of 16 bytes fill fx's largest memory limit of 64 MiB, so no table an extension can build holds more elements.

A Debug build compiles the C source with `LUA_USE_APICHECK`, so misuse of the C API from fx's own code, such as pushing more values than a C function's stack space holds, fails an assertion in tests instead of corrupting memory. Release builds leave the checks out, as stock Lua does.

`fx_lua.h` is fx's own: it includes the three headers that `build.zig` translates for Zig.

To update Lua, replace the files with the same names from the new release, apply the `lstrlib.c` and `ltablib.c` changes again, and update the version in `src/lua/engine.zig` and `THIRD_PARTY_NOTICES.md`.

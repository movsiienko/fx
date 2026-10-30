# Vendored Lua

This folder holds the C source of Lua 5.4.8 from lua.org, which fx embeds to run extension hooks. `build.zig` compiles it into the native fx binary only. The license is at the end of `lua.h` and in `THIRD_PARTY_NOTICES.md`.

The folder keeps only the core, the auxiliary library, and the `base`, `string`, `table`, `math`, and `utf8` libraries. The `io`, `os`, `package`, `debug`, and `coroutine` libraries, `linit.c`, and the standalone `lua` and `luac` programs are left out, and `scripts/check-lua-boundary.sh` fails if one comes back.

fx changes one file. In `lstrlib.c`, a pattern match counts its steps and stops with "pattern too complex" after `MAXMATCHSTEPS`, because a match runs inside one C call, where the instruction budget cannot stop it. Each change is marked with an `fx:` comment.

`fx_lua.h` is fx's own: it includes the three headers that `build.zig` translates for Zig.

To update Lua, replace the files with the same names from the new release, apply the `lstrlib.c` change again, and update the version in `src/lua/engine.zig` and `THIRD_PARTY_NOTICES.md`.

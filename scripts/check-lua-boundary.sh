#!/usr/bin/env bash
# The Lua engine in src/lua sits behind one front door, engine.zig. Code
# outside imports only that file. The engine imports only the standard
# library, its own files, and the translated Lua header (lua_c), so it holds
# no fx state and reads no files: the host hands it every file an extension
# may load. Only src/core/lua_host adapts it to fx's hook runtime.
# The vendored C source must leave out the libraries the sandbox never opens.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

folder="src/lua"

reaching_in="$({
  git grep --untracked -n -E '@import\("[^"]*lua/[a-z_]+\.zig"\)' -- src ":(exclude)$folder" || true
} | grep -v 'lua/engine\.zig")' || true)"
if [[ -n "$reaching_in" ]]; then
  printf 'Only %s/engine.zig may be imported from outside the engine:\n%s\n' "$folder" "$reaching_in" >&2
  exit 1
fi

importers="$({
  git grep --untracked -l -E '@import\("[^"]*lua/engine\.zig"\)' -- src ":(exclude)$folder" || true
} | grep -v -E '^src/core/lua_host/|^src/main\.zig$|^src/fuzz_targets\.zig$' || true)"
if [[ -n "$importers" ]]; then
  printf 'Only src/core/lua_host may use the Lua engine:\n%s\n' "$importers" >&2
  exit 1
fi

allowed='^(std|builtin|lua_c|fuzz_seed|fuzz_corpus|[a-z_]+\.zig)$'
reaching_out=""
while IFS= read -r line; do
  target="${line#*@import(\"}"
  target="${target%\")}"
  if [[ ! "$target" =~ $allowed ]]; then
    reaching_out+="$line"$'\n'
  fi
done < <(git grep --untracked -n -o -E '@import\("[^"]+"\)' -- "$folder" || true)
if [[ -n "$reaching_out" ]]; then
  printf 'The Lua engine may import only std, its own files and lua_c:\n%s' "$reaching_out" >&2
  exit 1
fi

io_use="$(git grep --untracked -n -E 'std\.process|std\.Io\.Dir|std\.fs\b|std\.http|std\.net' -- "$folder" || true)"
if [[ -n "$io_use" ]]; then
  printf 'The Lua engine must not touch processes, files or the network:\n%s\n' "$io_use" >&2
  exit 1
fi

for library in liolib.c loslib.c loadlib.c ldblib.c lcorolib.c linit.c lua.c luac.c; do
  if [[ -e "$folder/vendor/$library" ]]; then
    printf 'The sandbox never opens %s; remove %s/vendor/%s\n' "$library" "$folder" "$library" >&2
    exit 1
  fi
done

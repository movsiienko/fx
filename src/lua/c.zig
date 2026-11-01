//! The Lua 5.4 C API, translated from `fx_lua.h`, plus Zig versions
//! of the API macros that translation cannot keep.

const std = @import("std");
const raw = @import("lua_c");

pub const State = raw.lua_State;
pub const Debug = raw.lua_Debug;
pub const CFunction = *const fn (?*State) callconv(.c) c_int;

pub const lua_newstate = raw.lua_newstate;
pub const lua_close = raw.lua_close;
pub const lua_gettop = raw.lua_gettop;
pub const lua_settop = raw.lua_settop;
pub const lua_checkstack = raw.lua_checkstack;
pub const lua_absindex = raw.lua_absindex;
pub const lua_type = raw.lua_type;
const lua_typename = raw.lua_typename;
pub const lua_isinteger = raw.lua_isinteger;
pub const lua_tointegerx = raw.lua_tointegerx;
pub const lua_tonumberx = raw.lua_tonumberx;
pub const lua_toboolean = raw.lua_toboolean;
const lua_tolstring = raw.lua_tolstring;
pub const lua_touserdata = raw.lua_touserdata;
pub const lua_rawlen = raw.lua_rawlen;
pub const lua_rawequal = raw.lua_rawequal;
pub const lua_pushnil = raw.lua_pushnil;
pub const lua_pushinteger = raw.lua_pushinteger;
pub const lua_pushnumber = raw.lua_pushnumber;
const lua_pushlstring = raw.lua_pushlstring;
pub const lua_pushcclosure = raw.lua_pushcclosure;
pub const lua_pushboolean = raw.lua_pushboolean;
pub const lua_pushlightuserdata = raw.lua_pushlightuserdata;
pub const lua_pushvalue = raw.lua_pushvalue;
pub const lua_rawget = raw.lua_rawget;
pub const lua_rawgeti = raw.lua_rawgeti;
pub const lua_rawset = raw.lua_rawset;
pub const lua_rawseti = raw.lua_rawseti;
pub const lua_setfield = raw.lua_setfield;
pub const lua_setglobal = raw.lua_setglobal;
pub const lua_getglobal = raw.lua_getglobal;
pub const lua_createtable = raw.lua_createtable;
pub const lua_getmetatable = raw.lua_getmetatable;
pub const lua_setmetatable = raw.lua_setmetatable;
pub const lua_newuserdatauv = raw.lua_newuserdatauv;
pub const lua_toclose = raw.lua_toclose;
pub const lua_closeslot = raw.lua_closeslot;
pub const lua_next = raw.lua_next;
pub const lua_error = raw.lua_error;
pub const lua_sethook = raw.lua_sethook;
pub const luaL_requiref = raw.luaL_requiref;
pub const luaL_loadbufferx = raw.luaL_loadbufferx;
pub const luaL_ref = raw.luaL_ref;
pub const luaL_tolstring = raw.luaL_tolstring;
pub const luaopen_base = raw.luaopen_base;
pub const luaopen_string = raw.luaopen_string;
pub const luaopen_table = raw.luaopen_table;
pub const luaopen_math = raw.luaopen_math;
pub const luaopen_utf8 = raw.luaopen_utf8;

pub const LUA_OK = 0;
pub const LUA_ERRMEM = 4;

pub const LUA_TNONE = -1;
pub const LUA_TNIL = 0;
pub const LUA_TBOOLEAN = 1;
pub const LUA_TLIGHTUSERDATA = 2;
pub const LUA_TNUMBER = 3;
pub const LUA_TSTRING = 4;
pub const LUA_TTABLE = 5;
pub const LUA_TFUNCTION = 6;

pub const LUA_MASKCOUNT = 1 << 3;
pub const LUA_NOREF = -2;

/// `LUAI_MAXSTACK` in Lua's `luaconf.h`.
const luai_maxstack = 1000000;
pub const LUA_REGISTRYINDEX = -luai_maxstack - 1000;

/// `lua_getextraspace`: the pointer-sized block Lua keeps in front of each
/// state for its host (`LUA_EXTRASPACE` in `luaconf.h`).
pub fn extraSpace(L: ?*State) *?*anyopaque {
    return @ptrFromInt(@intFromPtr(L.?) - @sizeOf(*anyopaque));
}

pub fn upvalueIndex(i: c_int) c_int {
    return LUA_REGISTRYINDEX - i;
}

pub fn pop(L: ?*State, n: c_int) void {
    lua_settop(L, -n - 1);
}

pub fn newTable(L: ?*State) void {
    lua_createtable(L, 0, 0);
}

pub fn pushCFunction(L: ?*State, f: CFunction) void {
    lua_pushcclosure(L, f, 0);
}

pub fn pushString(L: ?*State, bytes: []const u8) void {
    _ = lua_pushlstring(L, bytes.ptr, bytes.len);
}

pub fn pcall(L: ?*State, nargs: c_int, nresults: c_int) c_int {
    return raw.lua_pcallk(L, nargs, nresults, 0, 0, null);
}

pub fn call(L: ?*State, nargs: c_int, nresults: c_int) void {
    raw.lua_callk(L, nargs, nresults, 0, null);
}

/// Returns the string at `idx` without converting other types. A number is
/// not a string here, so this never allocates and never raises.
pub fn stringAt(L: ?*State, idx: c_int) ?[]const u8 {
    if (lua_type(L, idx) != LUA_TSTRING) return null;
    var len: usize = 0;
    const ptr = lua_tolstring(L, idx, &len) orelse return null;
    return ptr[0..len];
}

pub fn typeName(L: ?*State, idx: c_int) []const u8 {
    const name = lua_typename(L, lua_type(L, idx));
    return std.mem.span(name);
}

/// Raises `message` as a Lua error. Lua leaves through `longjmp`, so the
/// Zig frames between here and the protected call must own nothing.
pub fn raise(L: ?*State, message: []const u8) noreturn {
    pushString(L, message);
    _ = lua_error(L);
    unreachable;
}

import idc

types = [
    # Rust u8/i8
    "typedef unsigned char u8;",
    "typedef signed char i8;",

    # Rust u16/i16
    "typedef unsigned short u16;",
    "typedef signed short i16;",

    # Rust u32/i32
    "typedef unsigned int u32;",
    "typedef signed int i32;",

    # Rust u64/i64
    "typedef unsigned long long u64;",
    "typedef signed long long i64;",

    # Rust u128/i128 (as byte arrays, IDA has no 128-bit int)
    "typedef unsigned char u128[16];",
    "typedef signed char i128[16];",

    # Rust usize/isize (pointer-sized)
    "typedef unsigned __int64 usize;",
    "typedef signed __int64 isize;",

    # Rust f32/f64
    "typedef float f32;",
    "typedef double f64;",

    # Rust bool
    "typedef unsigned char bool_;",  # 'bool' may conflict, use bool_ if needed

    # Common C aliases (uint8_t style)
    "typedef unsigned char uint8_t;",
    "typedef signed char int8_t;",
    "typedef unsigned short uint16_t;",
    "typedef signed short int16_t;",
    "typedef unsigned int uint32_t;",
    "typedef signed int int32_t;",
    "typedef unsigned long long uint64_t;",
    "typedef signed long long int64_t;",

    # Common shorthand aliases
    "typedef unsigned char uint8;",
    "typedef unsigned char uint_8;",
    "typedef unsigned char u8;",
    "typedef signed char int8;",
    "typedef unsigned short uint16;",
    "typedef signed short int16;",
    "typedef unsigned int uint32;",
    "typedef signed int int32;",
    "typedef unsigned long long uint64;",
    "typedef signed long long int64;",

    # Pointer-sized aliases
    "typedef unsigned __int64 uintptr_t;",
    "typedef signed __int64 intptr_t;",
    "typedef unsigned __int64 size_t;",
    "typedef signed __int64 ssize_t;",
    "typedef signed __int64 ptrdiff_t;",

    # Rust Option-like null markers (commonly seen in decompiled Rust)
    "typedef unsigned char byte;",
    "typedef unsigned short word;",
    "typedef unsigned int dword;",
    "typedef unsigned long long qword;",
]

for t in types:
    result = idc.parse_decls(t, 0)
    if result != 0:
        print(f"Warning: failed to parse: {t}")

print("Done.")

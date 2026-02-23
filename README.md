# fastoml

A high-performance, single-header TOML parser and serializer written in C.

## Features

- **Single-header library** — drop `fastoml.h` into your project
- **C99 compatible** with C++ friendly
- **SIMD accelerated** — optional AVX2, SSE2, and ARM NEON
- **Complete TOML support** — parse, validate, build, and serialize
- **Arena allocator** — minimal allocation overhead
- **Custom allocators** — plug in your own malloc/realloc/free
- **Detailed error reporting** — line, column, and byte offset on failure
- **Parser reuse** — reset and parse again without reallocating
- **Cross-platform** — Windows, Linux, macOS

> **C++ users:** [fastoml-cpp](https://github.com/EldoDebug/fastoml-cpp) provides a C++23 wrapper with dot-notation access, fluent builder API, and compile-time struct mapping.

## Quick Start

Copy `fastoml.h` into your project. In **exactly one** `.c` file, define the implementation:

```c
#define FASTOML_IMPLEMENTATION
#include "fastoml.h"
```

All other files simply include the header:

```c
#include "fastoml.h"
```

### CMake

```cmake
add_subdirectory(fastoml)
target_link_libraries(your_target PRIVATE fastoml::fastoml)
```

## Usage

### Parsing a TOML string

```c
#include <stdio.h>
#include "fastoml.h"

int main(void) {
    const char* input =
        "[server]\n"
        "host = \"127.0.0.1\"\n"
        "port = 8080\n";

    fastoml_options options;
    fastoml_options_default(&options);

    fastoml_parser* parser = fastoml_parser_create(&options);
    const fastoml_document* doc = NULL;
    fastoml_error err = {0};

    fastoml_status st = fastoml_parse(parser, input, strlen(input), &doc, &err);
    if (st != FASTOML_OK) {
        fprintf(stderr, "parse error: %s (line %u, col %u)\n",
                fastoml_status_string(st), err.line, err.column);
        fastoml_parser_destroy(parser);
        return 1;
    }

    const fastoml_node* root = fastoml_doc_root(doc);
    const fastoml_node* server = fastoml_table_get_cstr(root, "server");

    const fastoml_node* host_node = fastoml_table_get_cstr(server, "host");
    fastoml_slice host = {0};
    fastoml_node_as_slice(host_node, &host);
    printf("host = %.*s\n", (int)host.len, host.ptr);

    const fastoml_node* port_node = fastoml_table_get_cstr(server, "port");
    int64_t port = 0;
    fastoml_node_as_int(port_node, &port);
    printf("port = %lld\n", (long long)port);

    fastoml_parser_destroy(parser);
    return 0;
}
```

### Building and serializing a TOML document

```c
#include <stdio.h>
#include "fastoml.h"

int main(void) {
    fastoml_builder_options options;
    fastoml_builder_options_default(&options);
    fastoml_builder* b = fastoml_builder_create(&options);

    fastoml_value* root = fastoml_builder_root(b);
    fastoml_value* server = fastoml_builder_new_table(b);
    fastoml_builder_table_set_cstr(root, "server", server);
    fastoml_builder_table_set_cstr(server, "host",
        fastoml_builder_new_string(b, (fastoml_slice){"0.0.0.0", 7}));
    fastoml_builder_table_set_cstr(server, "port",
        fastoml_builder_new_int(b, 3000));

    // Serialize to buffer
    fastoml_serialize_options ser_opts;
    fastoml_serialize_options_default(&ser_opts);
    ser_opts.flags |= FASTOML_SERIALIZE_FINAL_NEWLINE;

    size_t len = 0;
    fastoml_serialize_to_buffer(fastoml_builder_root(b), &ser_opts, NULL, 0, &len);

    char* buf = malloc(len + 1);
    fastoml_serialize_to_buffer(fastoml_builder_root(b), &ser_opts, buf, len + 1, &len);
    printf("%.*s", (int)len, buf);

    free(buf);
    fastoml_builder_destroy(b);
    return 0;
}
```

Output:

```toml
[server]
host = "0.0.0.0"
port = 3000
```

## API Overview

### Parser

| Function | Description |
|---|---|
| `fastoml_parser_create` | Create a new parser instance |
| `fastoml_parser_destroy` | Free parser and all parsed documents |
| `fastoml_parser_reset` | Reset parser for reuse |
| `fastoml_parse` | Parse a TOML string into a document |
| `fastoml_validate` | Validate without building a tree |

### Document Access

| Function | Description |
|---|---|
| `fastoml_doc_root` | Get the root table node |
| `fastoml_node_kindof` | Get the type of a node |
| `fastoml_table_get_cstr` | Look up a key in a table |
| `fastoml_table_size` | Number of entries in a table |
| `fastoml_table_key_at` | Get key at index |
| `fastoml_table_value_at` | Get value at index |
| `fastoml_array_size` | Number of elements in an array |
| `fastoml_array_at` | Get element at index |

### Value Extraction

| Function | Description |
|---|---|
| `fastoml_node_as_bool` | Extract boolean value |
| `fastoml_node_as_int` | Extract 64-bit integer value |
| `fastoml_node_as_float` | Extract double value |
| `fastoml_node_as_slice` | Extract string / datetime slice |

### Builder & Serializer

| Function | Description |
|---|---|
| `fastoml_builder_create` | Create a document builder |
| `fastoml_builder_new_table` | Create a new table value |
| `fastoml_builder_new_array` | Create a new array value |
| `fastoml_builder_new_string` | Create a new string value |
| `fastoml_builder_new_int` | Create a new integer value |
| `fastoml_builder_new_float` | Create a new float value |
| `fastoml_builder_new_bool` | Create a new boolean value |
| `fastoml_builder_table_set_cstr` | Insert a key-value pair |
| `fastoml_builder_array_push` | Append an element to an array |
| `fastoml_serialize_to_buffer` | Serialize to a memory buffer |
| `fastoml_serialize_to_sink` | Serialize with a custom write callback |

### Parse Options

| Flag | Description |
|---|---|
| `FASTOML_PARSE_VALIDATE_ONLY` | Validate syntax without building a tree |
| `FASTOML_PARSE_DISABLE_SIMD` | Disable SIMD optimizations |
| `FASTOML_PARSE_TRUST_UTF8` | Skip UTF-8 validation for trusted input |

## Benchmarks

Parse throughput measured with [Google Benchmark](https://github.com/google/benchmark) (10 repetitions, mean values).

**Environment:** 12th Gen Intel, 12 threads, Windows 11, Clang (Release)

| Input | Size | fastoml | toml++ v3.4.0 | toml11 v4.4.0 |
|---|---|---|---|---|
| small | 184 B | **92.17 MiB/s** | 39.10 MiB/s | 1.28 MiB/s |
| medium | 1,544 B | **232.26 MiB/s** | 38.05 MiB/s | 1.63 MiB/s |
| large | 108,599 B | **242.30 MiB/s** | 32.28 MiB/s | 1.69 MiB/s |
| invalid | 123 B | **79.16 MiB/s** | 20.15 MiB/s | 1.61 MiB/s |

### Speedup vs. alternatives

| Input | vs toml++ | vs toml11 |
|---|---|---|
| small | **2.4x** | **72x** |
| medium | **6.1x** | **142x** |
| large | **7.5x** | **143x** |
| invalid | **3.9x** | **49x** |

> All parsers create and destroy their parser state in every iteration for a fair comparison. I/O is excluded — only the parse call is measured.

## Building

### Requirements

- CMake 3.20+
- C99-compatible compiler (MSVC, GCC, Clang)

### Build the example

```bash
cmake -S . -B build
cmake --build build --config Release
./build/example/fastoml_example
```

### Build and run benchmarks

```bash
cmake -S . -B build -DFASTOML_BENCH=ON
cmake --build build --config Release
./build/bench/fastoml_bench_parse
```

## License

MIT

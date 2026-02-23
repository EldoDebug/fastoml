#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#include "fastoml.h"

enum {
    EXIT_USAGE = 2,
    EXIT_INPUT = 3,
    EXIT_PARSE = 4,
    EXIT_BUILD = 5
};

static int is_sep(char c) {
    return c == '/' || c == '\\';
}

static int try_open_read(const char* path) {
    FILE* f;
    if (!path) {
        return 0;
    }
    f = fopen(path, "rb");
    if (!f) {
        return 0;
    }
    fclose(f);
    return 1;
}

static const char* resolve_default_input_path(void) {
    static const char* candidates[] = {
        "example/sample/sample.toml",
        "sample/sample.toml",
        "../sample/sample.toml",
        "../example/sample/sample.toml",
        "../../example/sample/sample.toml",
        NULL};
    size_t i = 0u;
    while (candidates[i] != NULL) {
        if (try_open_read(candidates[i])) {
            return candidates[i];
        }
        ++i;
    }
    return NULL;
}

static int read_file_all(const char* path, char** out_data, size_t* out_len) {
    FILE* f = NULL;
    long pos = 0;
    size_t size = 0;
    char* data = NULL;

    if (!path || !out_data || !out_len) {
        return 0;
    }

    *out_data = NULL;
    *out_len = 0u;

    f = fopen(path, "rb");
    if (!f) {
        return 0;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return 0;
    }
    pos = ftell(f);
    if (pos < 0) {
        fclose(f);
        return 0;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return 0;
    }

    size = (size_t)pos;
    data = (char*)malloc(size + 1u);
    if (!data) {
        fclose(f);
        return 0;
    }

    if (size > 0u && fread(data, 1u, size, f) != size) {
        free(data);
        fclose(f);
        return 0;
    }
    data[size] = '\0';
    fclose(f);

    *out_data = data;
    *out_len = size;
    return 1;
}

static int mkdir_if_needed(const char* dir) {
    int rc;
    if (!dir || dir[0] == '\0') {
        return 1;
    }
#ifdef _WIN32
    rc = _mkdir(dir);
#else
    rc = mkdir(dir, 0755);
#endif
    if (rc == 0 || errno == EEXIST) {
        return 1;
    }
    return 0;
}

static int ensure_parent_dirs(const char* path) {
    size_t len;
    size_t i;
    char* copy;
    if (!path) {
        return 0;
    }
    len = strlen(path);
    if (len == 0u) {
        return 0;
    }
    copy = (char*)malloc(len + 1u);
    if (!copy) {
        return 0;
    }
    memcpy(copy, path, len + 1u);

    for (i = 0u; i < len; ++i) {
        char saved;
        if (!is_sep(copy[i])) {
            continue;
        }
        if (i == 0u || (i == 2u && copy[1] == ':')) {
            continue;
        }
        saved = copy[i];
        copy[i] = '\0';
        if (!mkdir_if_needed(copy)) {
            free(copy);
            return 0;
        }
        copy[i] = saved;
    }

    free(copy);
    return 1;
}

static int write_file_all(const char* path, const char* data, size_t len) {
    FILE* f;
    if (!path || !data) {
        return 0;
    }
    if (!ensure_parent_dirs(path)) {
        return 0;
    }
    f = fopen(path, "wb");
    if (!f) {
        return 0;
    }
    if (len > 0u && fwrite(data, 1u, len, f) != len) {
        fclose(f);
        return 0;
    }
    if (fclose(f) != 0) {
        return 0;
    }
    return 1;
}

static const char* kind_name(fastoml_node_kind kind) {
    switch (kind) {
    case FASTOML_NODE_TABLE:
        return "table";
    case FASTOML_NODE_ARRAY:
        return "array";
    case FASTOML_NODE_STRING:
        return "string";
    case FASTOML_NODE_INT:
        return "int";
    case FASTOML_NODE_FLOAT:
        return "float";
    case FASTOML_NODE_BOOL:
        return "bool";
    case FASTOML_NODE_DATETIME:
        return "datetime";
    case FASTOML_NODE_DATE:
        return "date";
    case FASTOML_NODE_TIME:
        return "time";
    default:
        return "unknown";
    }
}

static int slice_print_len(fastoml_slice s) {
    if (s.len > (uint32_t)INT32_MAX) {
        return INT32_MAX;
    }
    return (int)s.len;
}

static void print_indent(int indent) {
    int i;
    for (i = 0; i < indent; ++i) {
        putchar(' ');
    }
}

static void print_scalar_value(const fastoml_node* node) {
    fastoml_node_kind kind = fastoml_node_kindof(node);
    if (kind == FASTOML_NODE_BOOL) {
        int v = 0;
        if (fastoml_node_as_bool(node, &v) == FASTOML_OK) {
            printf("%s", v ? "true" : "false");
            return;
        }
    } else if (kind == FASTOML_NODE_INT) {
        int64_t v = 0;
        if (fastoml_node_as_int(node, &v) == FASTOML_OK) {
            printf("%" PRId64, v);
            return;
        }
    } else if (kind == FASTOML_NODE_FLOAT) {
        double v = 0.0;
        if (fastoml_node_as_float(node, &v) == FASTOML_OK) {
            printf("%.17g", v);
            return;
        }
    } else if (kind == FASTOML_NODE_STRING || kind == FASTOML_NODE_DATETIME || kind == FASTOML_NODE_DATE || kind == FASTOML_NODE_TIME) {
        fastoml_slice s = {0};
        if (fastoml_node_as_slice(node, &s) == FASTOML_OK) {
            printf("\"%.*s\"", slice_print_len(s), s.ptr ? s.ptr : "");
            return;
        }
    }
    printf("<unavailable>");
}

static void print_node(const fastoml_node* node, int indent);

static void print_table(const fastoml_node* table, int indent) {
    uint32_t count = fastoml_table_size(table);
    uint32_t i;
    print_indent(indent);
    printf("table (%u)\n", count);
    for (i = 0u; i < count; ++i) {
        fastoml_slice key = fastoml_table_key_at(table, i);
        const fastoml_node* value = fastoml_table_value_at(table, i);
        fastoml_node_kind vk = fastoml_node_kindof(value);
        if (vk == FASTOML_NODE_TABLE || vk == FASTOML_NODE_ARRAY) {
            print_indent(indent + 2);
            printf("%.*s:\n", slice_print_len(key), key.ptr ? key.ptr : "");
            print_node(value, indent + 4);
            continue;
        }
        print_indent(indent + 2);
        printf("%.*s = ", slice_print_len(key), key.ptr ? key.ptr : "");
        print_scalar_value(value);
        printf(" (%s)\n", kind_name(vk));
    }
}

static void print_array(const fastoml_node* array, int indent) {
    uint32_t count = fastoml_array_size(array);
    uint32_t i;
    print_indent(indent);
    printf("array (%u)\n", count);
    for (i = 0u; i < count; ++i) {
        const fastoml_node* item = fastoml_array_at(array, i);
        fastoml_node_kind k = fastoml_node_kindof(item);
        if (k == FASTOML_NODE_TABLE || k == FASTOML_NODE_ARRAY) {
            print_indent(indent + 2);
            printf("[%u]:\n", i);
            print_node(item, indent + 4);
            continue;
        }
        print_indent(indent + 2);
        printf("[%u] = ", i);
        print_scalar_value(item);
        printf(" (%s)\n", kind_name(k));
    }
}

static void print_node(const fastoml_node* node, int indent) {
    fastoml_node_kind kind = fastoml_node_kindof(node);
    if (kind == FASTOML_NODE_TABLE) {
        print_table(node, indent);
        return;
    }
    if (kind == FASTOML_NODE_ARRAY) {
        print_array(node, indent);
        return;
    }
    print_indent(indent);
    print_scalar_value(node);
    printf(" (%s)\n", kind_name(kind));
}

static fastoml_slice cstr_slice(const char* s) {
    fastoml_slice out;
    out.ptr = s;
    out.len = (uint32_t)strlen(s);
    return out;
}

static int set_table_value(fastoml_value* table, const char* key, fastoml_value* value) {
    fastoml_status st = fastoml_builder_table_set_cstr(table, key, value);
    if (st != FASTOML_OK) {
        fprintf(stderr, "builder error: set key '%s' failed (%s)\n", key, fastoml_status_string(st));
        return 0;
    }
    return 1;
}

static int build_sample_document(fastoml_builder* b) {
    fastoml_value* root = fastoml_builder_root(b);
    fastoml_value* app;
    fastoml_value* features;
    fastoml_value* limits;
    fastoml_value* meta;
    if (!root) {
        return 0;
    }

    app = fastoml_builder_new_table(b);
    features = fastoml_builder_new_array(b);
    limits = fastoml_builder_new_table(b);
    meta = fastoml_builder_new_table(b);
    if (!app || !features || !limits || !meta) {
        return 0;
    }

    if (!set_table_value(root, "app", app))
        return 0;
    if (!set_table_value(root, "features", features))
        return 0;
    if (!set_table_value(root, "limits", limits))
        return 0;
    if (!set_table_value(root, "meta", meta))
        return 0;

    if (!set_table_value(app, "name", fastoml_builder_new_string(b, cstr_slice("fastoml-example"))))
        return 0;
    if (!set_table_value(app, "version", fastoml_builder_new_int(b, 1)))
        return 0;
    if (!set_table_value(app, "debug", fastoml_builder_new_bool(b, 1)))
        return 0;

    if (fastoml_builder_array_push(features, fastoml_builder_new_string(b, cstr_slice("parse"))) != FASTOML_OK)
        return 0;
    if (fastoml_builder_array_push(features, fastoml_builder_new_string(b, cstr_slice("print"))) != FASTOML_OK)
        return 0;
    if (fastoml_builder_array_push(features, fastoml_builder_new_string(b, cstr_slice("serialize"))) != FASTOML_OK)
        return 0;

    if (!set_table_value(limits, "max_connections", fastoml_builder_new_int(b, 128)))
        return 0;
    if (!set_table_value(limits, "timeout_seconds", fastoml_builder_new_float(b, 2.5)))
        return 0;

    if (!set_table_value(meta, "generated_at", fastoml_builder_new_datetime_raw(b, cstr_slice("2026-02-22T12:00:00Z"))))
        return 0;
    if (!set_table_value(meta, "author", fastoml_builder_new_string(b, cstr_slice("example"))))
        return 0;

    return 1;
}

static int parse_and_print_input(const char* input_path) {
    char* input = NULL;
    size_t input_len = 0u;
    fastoml_options options;
    fastoml_parser* parser = NULL;
    const fastoml_document* doc = NULL;
    fastoml_error err;
    fastoml_status st;

    if (!read_file_all(input_path, &input, &input_len)) {
        fprintf(stderr, "failed to read input file: %s\n", input_path);
        return 0;
    }

    fastoml_options_default(&options);
    parser = fastoml_parser_create(&options);
    if (!parser) {
        free(input);
        fprintf(stderr, "failed to create parser\n");
        return 0;
    }

    memset(&err, 0, sizeof(err));
    st = fastoml_parse(parser, input, input_len, &doc, &err);
    if (st != FASTOML_OK) {
        fprintf(
            stderr,
            "parse error: %s (line=%u, column=%u, byte=%u)\n",
            fastoml_status_string(st),
            err.line,
            err.column,
            err.byte_offset);
        fastoml_parser_destroy(parser);
        free(input);
        return 0;
    }

    printf("== Parsed TOML (%s) ==\n", input_path);
    print_node(fastoml_doc_root(doc), 0);

    fastoml_parser_destroy(parser);
    free(input);
    return 1;
}

static int build_and_save_output(const char* output_path) {
    fastoml_builder_options options;
    fastoml_builder* builder;
    fastoml_serialize_options serialize_options;
    const fastoml_value* root;
    char* out = NULL;
    size_t out_len = 0u;
    fastoml_status st;

    fastoml_builder_options_default(&options);
    builder = fastoml_builder_create(&options);
    if (!builder) {
        fprintf(stderr, "failed to create builder\n");
        return 0;
    }

    if (!build_sample_document(builder)) {
        fprintf(stderr, "failed to build sample document\n");
        fastoml_builder_destroy(builder);
        return 0;
    }

    root = fastoml_builder_root(builder);
    fastoml_serialize_options_default(&serialize_options);
    serialize_options.flags |= FASTOML_SERIALIZE_FINAL_NEWLINE;

    st = fastoml_serialize_to_buffer(root, &serialize_options, NULL, 0u, &out_len);
    if (st != FASTOML_OK) {
        fprintf(stderr, "serialize size pass failed: %s\n", fastoml_status_string(st));
        fastoml_builder_destroy(builder);
        return 0;
    }

    out = (char*)malloc(out_len + 1u);
    if (!out) {
        fprintf(stderr, "failed to allocate output buffer\n");
        fastoml_builder_destroy(builder);
        return 0;
    }

    st = fastoml_serialize_to_buffer(root, &serialize_options, out, out_len + 1u, &out_len);
    if (st != FASTOML_OK) {
        fprintf(stderr, "serialize failed: %s\n", fastoml_status_string(st));
        free(out);
        fastoml_builder_destroy(builder);
        return 0;
    }

    if (!write_file_all(output_path, out, out_len)) {
        fprintf(stderr, "failed to write output file: %s\n", output_path);
        free(out);
        fastoml_builder_destroy(builder);
        return 0;
    }

    printf("== Generated TOML (%s) ==\n", output_path);
    printf("%.*s", (int)out_len, out);

    free(out);
    fastoml_builder_destroy(builder);
    return 1;
}

int main(int argc, char** argv) {
    const char* input_path;
    const char* output_path;
    if (argc > 3) {
        fprintf(stderr, "usage: %s [input.toml] [output.toml]\n", argv[0]);
        return EXIT_USAGE;
    }

    input_path = (argc >= 2) ? argv[1] : resolve_default_input_path();
    output_path = (argc >= 3) ? argv[2] : "example/out/generated.toml";

    if (!input_path) {
        fprintf(stderr, "default input file not found. pass input path explicitly.\n");
        return EXIT_INPUT;
    }

    if (!parse_and_print_input(input_path)) {
        return EXIT_PARSE;
    }

    if (!build_and_save_output(output_path)) {
        return EXIT_BUILD;
    }

    return 0;
}

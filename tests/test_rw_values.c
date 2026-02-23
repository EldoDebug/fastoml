#define FASTOML_IMPLEMENTATION
#include "fastoml.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_values(const fastoml_node* root) {
    const fastoml_node* node = NULL;
    fastoml_slice title = {0};
    int64_t port = 0;
    double pi = 0.0;
    int enabled = 0;
    double diff = 0.0;
    static const char expected_title[] = "fastoml";
    const double expected_pi = 3.1415926535;

    if (!root) {
        fprintf(stderr, "root node is null\n");
        return 0;
    }

    node = fastoml_table_get_cstr(root, "title");
    if (!node || fastoml_node_as_slice(node, &title) != FASTOML_OK) {
        fprintf(stderr, "failed to read title\n");
        return 0;
    }
    if (title.len != (uint32_t)(sizeof(expected_title) - 1u) ||
        memcmp(title.ptr, expected_title, sizeof(expected_title) - 1u) != 0) {
        fprintf(stderr, "title mismatch\n");
        return 0;
    }

    node = fastoml_table_get_cstr(root, "port");
    if (!node || fastoml_node_as_int(node, &port) != FASTOML_OK) {
        fprintf(stderr, "failed to read port\n");
        return 0;
    }
    if (port != 8080) {
        fprintf(stderr, "port mismatch: %lld\n", (long long)port);
        return 0;
    }

    node = fastoml_table_get_cstr(root, "pi");
    if (!node || fastoml_node_as_float(node, &pi) != FASTOML_OK) {
        fprintf(stderr, "failed to read pi\n");
        return 0;
    }
    diff = pi - expected_pi;
    if (diff < 0.0) {
        diff = -diff;
    }
    if (diff > 1e-12) {
        fprintf(stderr, "pi mismatch: %.17g\n", pi);
        return 0;
    }

    node = fastoml_table_get_cstr(root, "enabled");
    if (!node || fastoml_node_as_bool(node, &enabled) != FASTOML_OK) {
        fprintf(stderr, "failed to read enabled\n");
        return 0;
    }
    if (enabled != 1) {
        fprintf(stderr, "enabled mismatch: %d\n", enabled);
        return 0;
    }

    return 1;
}

int main(void) {
    const char* input =
        "title = \"fastoml\"\n"
        "port = 8080\n"
        "pi = 3.1415926535\n"
        "enabled = true\n";
    fastoml_options opt;
    fastoml_parser* parser = NULL;
    fastoml_error err = {0};
    fastoml_status st = FASTOML_OK;
    const fastoml_document* doc = NULL;
    const fastoml_node* root = NULL;
    fastoml_serialize_options ser_opt;
    size_t needed = 0u;
    size_t written = 0u;
    char* out = NULL;
    int rc = 1;

    fastoml_options_default(&opt);
    parser = fastoml_parser_create(&opt);
    if (!parser) {
        fprintf(stderr, "failed to create parser\n");
        return 1;
    }

    st = fastoml_parse(parser, input, strlen(input), &doc, &err);
    if (st != FASTOML_OK) {
        fprintf(stderr, "parse failed: %s (line=%u col=%u)\n",
                fastoml_status_string(st), err.line, err.column);
        goto cleanup;
    }
    root = fastoml_doc_root(doc);
    if (!check_values(root)) {
        goto cleanup;
    }

    fastoml_serialize_options_default(&ser_opt);
    st = fastoml_serialize_node_to_buffer(root, &ser_opt, NULL, 0u, &needed);
    if (st != FASTOML_OK || needed == 0u) {
        fprintf(stderr, "failed to calculate serialized size: %s\n", fastoml_status_string(st));
        goto cleanup;
    }

    out = (char*)malloc(needed + 1u);
    if (!out) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }
    st = fastoml_serialize_node_to_buffer(root, &ser_opt, out, needed + 1u, &written);
    if (st != FASTOML_OK) {
        fprintf(stderr, "serialize failed: %s\n", fastoml_status_string(st));
        goto cleanup;
    }
    out[written] = '\0';

    fastoml_parser_reset(parser);
    doc = NULL;
    memset(&err, 0, sizeof(err));
    st = fastoml_parse(parser, out, written, &doc, &err);
    if (st != FASTOML_OK) {
        fprintf(stderr, "re-parse failed: %s (line=%u col=%u)\n",
                fastoml_status_string(st), err.line, err.column);
        goto cleanup;
    }
    root = fastoml_doc_root(doc);
    if (!check_values(root)) {
        goto cleanup;
    }

    rc = 0;

cleanup:
    free(out);
    fastoml_parser_destroy(parser);
    return rc;
}

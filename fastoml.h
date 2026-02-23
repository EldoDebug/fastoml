
#ifndef FASTOML_H
#define FASTOML_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef FASTOML_API
#define FASTOML_API
#endif

typedef struct fastoml_parser fastoml_parser;
typedef struct fastoml_document fastoml_document;
typedef struct fastoml_node fastoml_node;
typedef struct fastoml_builder fastoml_builder;
typedef struct fastoml_value fastoml_value;

typedef struct fastoml_slice {
    const char* ptr;
    uint32_t len;
} fastoml_slice;

typedef enum fastoml_status {
    FASTOML_OK = 0,
    FASTOML_ERR_SYNTAX = 1,
    FASTOML_ERR_UTF8 = 2,
    FASTOML_ERR_DUP_KEY = 3,
    FASTOML_ERR_TYPE = 4,
    FASTOML_ERR_OOM = 5,
    FASTOML_ERR_OVERFLOW = 6,
    FASTOML_ERR_DEPTH = 7
} fastoml_status;

typedef enum fastoml_node_kind {
    FASTOML_NODE_TABLE = 1,
    FASTOML_NODE_ARRAY = 2,
    FASTOML_NODE_STRING = 3,
    FASTOML_NODE_INT = 4,
    FASTOML_NODE_FLOAT = 5,
    FASTOML_NODE_BOOL = 6,
    FASTOML_NODE_DATETIME = 7,
    FASTOML_NODE_DATE = 8,
    FASTOML_NODE_TIME = 9
} fastoml_node_kind;

typedef struct fastoml_allocator {
    void* ctx;
    void* (*malloc_fn)(void* ctx, size_t size);
    void* (*realloc_fn)(void* ctx, void* ptr, size_t size);
    void (*free_fn)(void* ctx, void* ptr);
} fastoml_allocator;

enum {
    FASTOML_PARSE_VALIDATE_ONLY = 1u << 0,
    FASTOML_PARSE_DISABLE_SIMD = 1u << 1,
    FASTOML_PARSE_TRUST_UTF8 = 1u << 2
};

typedef struct fastoml_options {
    uint32_t flags;
    fastoml_allocator alloc;
    uint32_t max_depth;
} fastoml_options;

typedef struct fastoml_error {
    fastoml_status code;
    uint32_t byte_offset;
    uint32_t line;
    uint32_t column;
} fastoml_error;

typedef struct fastoml_builder_options {
    fastoml_allocator alloc;
    uint32_t max_depth;
} fastoml_builder_options;

typedef fastoml_status (*fastoml_write_fn)(void* ctx, const char* data, size_t len);

enum {
    FASTOML_SERIALIZE_FINAL_NEWLINE = 1u << 0
};

typedef struct fastoml_serialize_options {
    uint32_t flags;
} fastoml_serialize_options;

FASTOML_API void fastoml_options_default(fastoml_options* out);
FASTOML_API const char* fastoml_status_string(fastoml_status s);

FASTOML_API fastoml_parser* fastoml_parser_create(const fastoml_options* opt);
FASTOML_API void fastoml_parser_destroy(fastoml_parser* p);
FASTOML_API void fastoml_parser_reset(fastoml_parser* p);

FASTOML_API fastoml_status fastoml_parse(
    fastoml_parser* p,
    const char* src,
    size_t len,
    const fastoml_document** out_doc,
    fastoml_error* out_err);

FASTOML_API fastoml_status fastoml_validate(
    fastoml_parser* p,
    const char* src,
    size_t len,
    fastoml_error* out_err);

FASTOML_API const fastoml_node* fastoml_doc_root(const fastoml_document* d);

FASTOML_API fastoml_node_kind fastoml_node_kindof(const fastoml_node* n);
FASTOML_API uint32_t fastoml_table_size(const fastoml_node* table);
FASTOML_API fastoml_slice fastoml_table_key_at(const fastoml_node* table, uint32_t idx);
FASTOML_API const fastoml_node* fastoml_table_value_at(const fastoml_node* table, uint32_t idx);
FASTOML_API const fastoml_node* fastoml_table_get(const fastoml_node* table, fastoml_slice key);
FASTOML_API const fastoml_node* fastoml_table_get_cstr(const fastoml_node* table, const char* key);

FASTOML_API uint32_t fastoml_array_size(const fastoml_node* array);
FASTOML_API const fastoml_node* fastoml_array_at(const fastoml_node* array, uint32_t idx);

FASTOML_API fastoml_status fastoml_node_as_bool(const fastoml_node* n, int* out_value);
FASTOML_API fastoml_status fastoml_node_as_int(const fastoml_node* n, int64_t* out_value);
FASTOML_API fastoml_status fastoml_node_as_float(const fastoml_node* n, double* out_value);
FASTOML_API fastoml_status fastoml_node_as_slice(const fastoml_node* n, fastoml_slice* out_value);

FASTOML_API void fastoml_builder_options_default(fastoml_builder_options* out);
FASTOML_API fastoml_builder* fastoml_builder_create(const fastoml_builder_options* opt);
FASTOML_API void fastoml_builder_destroy(fastoml_builder* b);
FASTOML_API void fastoml_builder_reset(fastoml_builder* b);
FASTOML_API fastoml_value* fastoml_builder_root(fastoml_builder* b);

FASTOML_API fastoml_value* fastoml_builder_new_table(fastoml_builder* b);
FASTOML_API fastoml_value* fastoml_builder_new_array(fastoml_builder* b);
FASTOML_API fastoml_value* fastoml_builder_new_string(fastoml_builder* b, fastoml_slice v);
FASTOML_API fastoml_value* fastoml_builder_new_int(fastoml_builder* b, int64_t v);
FASTOML_API fastoml_value* fastoml_builder_new_float(fastoml_builder* b, double v);
FASTOML_API fastoml_value* fastoml_builder_new_bool(fastoml_builder* b, int v);
FASTOML_API fastoml_value* fastoml_builder_new_datetime_raw(fastoml_builder* b, fastoml_slice raw);
FASTOML_API fastoml_value* fastoml_builder_new_date_raw(fastoml_builder* b, fastoml_slice raw);
FASTOML_API fastoml_value* fastoml_builder_new_time_raw(fastoml_builder* b, fastoml_slice raw);

FASTOML_API fastoml_status fastoml_builder_table_set(fastoml_value* table, fastoml_slice key, fastoml_value* value);
FASTOML_API fastoml_status fastoml_builder_table_set_cstr(fastoml_value* table, const char* key, fastoml_value* value);
FASTOML_API fastoml_status fastoml_builder_array_push(fastoml_value* array, fastoml_value* value);

FASTOML_API void fastoml_serialize_options_default(fastoml_serialize_options* out);
FASTOML_API fastoml_status fastoml_serialize_to_sink(
    const fastoml_value* root,
    const fastoml_serialize_options* opt,
    fastoml_write_fn write_fn,
    void* write_ctx);
FASTOML_API fastoml_status fastoml_serialize_to_buffer(
    const fastoml_value* root,
    const fastoml_serialize_options* opt,
    char* out,
    size_t out_cap,
    size_t* out_len);
FASTOML_API fastoml_status fastoml_serialize_node_to_sink(
    const fastoml_node* root,
    const fastoml_serialize_options* opt,
    fastoml_write_fn write_fn,
    void* write_ctx);
FASTOML_API fastoml_status fastoml_serialize_node_to_buffer(
    const fastoml_node* root,
    const fastoml_serialize_options* opt,
    char* out,
    size_t out_cap,
    size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* FASTOML_H */

#ifdef FASTOML_IMPLEMENTATION

#include <assert.h>
#include <ctype.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

#if defined(__SSE2__) && !defined(__AVX2__)
#include <emmintrin.h>
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#endif

#if (defined(_MSC_VER) || defined(__clang__)) && defined(_WIN32) && (defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__))
#include <intrin.h>
#endif

#ifndef FASTOML_LIKELY
#if defined(__GNUC__) || defined(__clang__)
#define FASTOML_LIKELY(x) __builtin_expect(!!(x), 1)
#else
#define FASTOML_LIKELY(x) (x)
#endif
#endif

#ifndef FASTOML_UNLIKELY
#if defined(__GNUC__) || defined(__clang__)
#define FASTOML_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define FASTOML_UNLIKELY(x) (x)
#endif
#endif

#ifndef FASTOML_INLINE
#if defined(_MSC_VER) && !defined(__clang__)
#define FASTOML_INLINE static __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define FASTOML_INLINE static inline __attribute__((always_inline))
#else
#define FASTOML_INLINE static inline
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fastoml_kv {
    fastoml_slice key;
    struct fastoml_node* value;
    uint64_t hash;
} fastoml_kv;

typedef struct fastoml_arena_block {
    struct fastoml_arena_block* next;
    size_t used;
    size_t cap;
    unsigned char data[1];
} fastoml_arena_block;

typedef struct fastoml_arena {
    fastoml_allocator alloc;
    fastoml_arena_block* first;
    fastoml_arena_block* current;
    size_t default_block_size;
} fastoml_arena;

enum {
    FASTOML_TABLE_EXPLICIT = 1u << 0,
    FASTOML_TABLE_INLINE_SEALED = 1u << 1,
    FASTOML_TABLE_INLINE_BUILDING = 1u << 2,
    FASTOML_ARRAY_OF_TABLES = 1u << 3,
    FASTOML_TABLE_DOTTED_DEFINED = 1u << 4
};

enum {
    FASTOML_TABLE_HASH_THRESHOLD = 32u
};

struct fastoml_node {
    fastoml_node_kind kind;
    uint32_t flags;
    union {
        struct
        {
            fastoml_kv* items;
            uint32_t len;
            uint32_t cap;
            uint32_t* hash_slots;
            uint32_t hash_cap;
        } table;
        struct
        {
            struct fastoml_node** items;
            uint32_t len;
            uint32_t cap;
        } array;
        struct
        {
            fastoml_slice view;
        } str;
        int64_t i64;
        double f64;
        int b;
        struct
        {
            fastoml_slice raw;
        } datetime;
    } as;
};

struct fastoml_document {
    const fastoml_node* root;
    const char* input;
    size_t input_len;
};

typedef struct fastoml_builder_kv {
    fastoml_slice key;
    struct fastoml_value* value;
    uint64_t hash;
} fastoml_builder_kv;

struct fastoml_value {
    fastoml_node_kind kind;
    uint32_t flags;
    struct fastoml_builder* owner;
    uint32_t epoch;
    union {
        struct
        {
            fastoml_builder_kv* items;
            uint32_t len;
            uint32_t cap;
        } table;
        struct
        {
            struct fastoml_value** items;
            uint32_t len;
            uint32_t cap;
        } array;
        struct
        {
            fastoml_slice view;
        } str;
        int64_t i64;
        double f64;
        int b;
        struct
        {
            fastoml_slice raw;
        } datetime;
    } as;
};

struct fastoml_builder {
    fastoml_builder_options opt;
    fastoml_arena arena;
    fastoml_value* root;
    uint32_t epoch;
};

struct fastoml_parser {
    fastoml_options opt;
    int simd_supported;
    fastoml_arena arena;
    fastoml_document doc;
};

typedef struct fastoml_reader {
    fastoml_parser* parser;
    const char* src;
    size_t len;
    size_t pos;
    uint32_t line;
    uint32_t col;
    uint32_t depth;
    fastoml_error err;
    fastoml_node* root;
    fastoml_node* current_table;
    int validate_only;
} fastoml_reader;

typedef struct fastoml_key_path {
    fastoml_slice* parts;
    uint64_t* hashes;
    fastoml_slice local_parts[16];
    uint64_t local_hashes[16];
    uint32_t count;
    uint32_t cap;
} fastoml_key_path;

static void* fastoml_std_malloc(void* ctx, size_t size) {
    (void)ctx;
    return malloc(size);
}

static void* fastoml_std_realloc(void* ctx, void* ptr, size_t size) {
    (void)ctx;
    return realloc(ptr, size);
}

static void fastoml_std_free(void* ctx, void* ptr) {
    (void)ctx;
    free(ptr);
}

static fastoml_allocator fastoml_make_default_allocator(void) {
    fastoml_allocator a;
    a.ctx = NULL;
    a.malloc_fn = &fastoml_std_malloc;
    a.realloc_fn = &fastoml_std_realloc;
    a.free_fn = &fastoml_std_free;
    return a;
}

void fastoml_options_default(fastoml_options* out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->flags = 0;
    out->alloc = fastoml_make_default_allocator();
    out->max_depth = 256;
}

const char* fastoml_status_string(fastoml_status s) {
    switch (s) {
    case FASTOML_OK:
        return "FASTOML_OK";
    case FASTOML_ERR_SYNTAX:
        return "FASTOML_ERR_SYNTAX";
    case FASTOML_ERR_UTF8:
        return "FASTOML_ERR_UTF8";
    case FASTOML_ERR_DUP_KEY:
        return "FASTOML_ERR_DUP_KEY";
    case FASTOML_ERR_TYPE:
        return "FASTOML_ERR_TYPE";
    case FASTOML_ERR_OOM:
        return "FASTOML_ERR_OOM";
    case FASTOML_ERR_OVERFLOW:
        return "FASTOML_ERR_OVERFLOW";
    case FASTOML_ERR_DEPTH:
        return "FASTOML_ERR_DEPTH";
    default:
        return "FASTOML_ERR_UNKNOWN";
    }
}

FASTOML_INLINE int fastoml_reader_eof(const fastoml_reader* r) {
    return r->pos >= r->len;
}

static fastoml_status fastoml_fail(fastoml_reader* r, fastoml_status code);

FASTOML_INLINE unsigned char fastoml_reader_peek(const fastoml_reader* r) {
    if (r->pos >= r->len) {
        return 0;
    }
    return (unsigned char)r->src[r->pos];
}

FASTOML_INLINE unsigned char fastoml_reader_peek_n(const fastoml_reader* r, size_t n) {
    const size_t p = r->pos + n;
    if (p >= r->len) {
        return 0;
    }
    return (unsigned char)r->src[p];
}

FASTOML_INLINE void fastoml_reader_advance_byte(fastoml_reader* r) {
    if (r->pos >= r->len) {
        return;
    }
    r->pos += 1;
    r->col += 1;
}

FASTOML_INLINE void fastoml_reader_advance_span_no_nl(fastoml_reader* r, size_t n) {
    if (n == 0) {
        return;
    }
    r->pos += n;
    r->col += (uint32_t)n;
}

static void fastoml_reader_advance_span_lf(fastoml_reader* r, const char* s, size_t n) {
    size_t i = 0;
    size_t last = 0;
    uint32_t newlines = 0;
    while (i < n) {
        if (s[i] == '\n') {
            last = i + 1u;
            newlines += 1u;
        }
        ++i;
    }
    r->pos += n;
    if (newlines == 0u) {
        r->col += (uint32_t)n;
        return;
    }
    r->line += newlines;
    r->col = 1u + (uint32_t)(n - last);
}

static fastoml_status fastoml_reader_advance_newline(fastoml_reader* r) {
    if (fastoml_reader_eof(r)) {
        return FASTOML_OK;
    }
    if (r->src[r->pos] == '\r') {
        if (r->pos + 1 >= r->len || r->src[r->pos + 1] != '\n') {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        r->pos += 1;
        r->pos += 1;
    } else if (r->src[r->pos] == '\n') {
        r->pos += 1;
    } else {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    r->line += 1;
    r->col = 1;
    return FASTOML_OK;
}

static fastoml_status fastoml_fail(fastoml_reader* r, fastoml_status code) {
    if (r->err.code == FASTOML_OK) {
        r->err.code = code;
        r->err.byte_offset = (uint32_t)r->pos;
        r->err.line = r->line;
        r->err.column = r->col;
    }
    return code;
}

FASTOML_INLINE uint64_t fastoml_rotl64(uint64_t x, uint32_t r) {
    return (x << r) | (x >> (64u - r));
}

FASTOML_INLINE uint64_t fastoml_read_u64_unaligned(const void* p) {
    uint64_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint64_t fastoml_hash_slice(fastoml_slice s) {
    const unsigned char* p = (const unsigned char*)s.ptr;
    size_t n = (size_t)s.len;
    uint64_t h;
    const uint64_t m0 = 0x9E3779B185EBCA87ull;
    const uint64_t m1 = 0xC2B2AE3D27D4EB4Full;

    if (n <= 24u) {
        h = 1469598103934665603ull;
        while (n > 0u) {
            h ^= (uint64_t)(*p++);
            h *= 1099511628211ull;
            n -= 1u;
        }
        return h;
    }

    h = 0x9E3779B185EBCA87ull ^ ((uint64_t)n * 0xC2B2AE3D27D4EB4Full);
    while (n >= 8u) {
        uint64_t v = fastoml_read_u64_unaligned(p);
        v ^= v >> 33u;
        v *= m0;
        v ^= v >> 29u;
        v *= m1;
        h ^= v;
        h = fastoml_rotl64(h, 27u) * m1 + 0x165667919E3779F9ull;
        p += 8u;
        n -= 8u;
    }

    if (n > 0u) {
        uint64_t tail = 0;
        memcpy(&tail, p, n);
        tail ^= tail >> 33u;
        tail *= m0;
        tail ^= tail >> 29u;
        h ^= tail;
    }

    h ^= h >> 33u;
    h *= m0;
    h ^= h >> 29u;
    h *= m1;
    h ^= h >> 32u;
    return h;
}

static int fastoml_slice_eq(fastoml_slice a, fastoml_slice b) {
    uint64_t a_lo = 0;
    uint64_t a_hi = 0;
    uint64_t b_lo = 0;
    uint64_t b_hi = 0;

    if (a.len != b.len) {
        return 0;
    }
    if (a.len == 0) {
        return 1;
    }
    if (a.len <= 8u) {
        memcpy(&a_lo, a.ptr, (size_t)a.len);
        memcpy(&b_lo, b.ptr, (size_t)b.len);
        return a_lo == b_lo;
    }
    if (a.len <= 16u) {
        memcpy(&a_lo, a.ptr, 8u);
        memcpy(&b_lo, b.ptr, 8u);
        memcpy(&a_hi, a.ptr + 8u, (size_t)a.len - 8u);
        memcpy(&b_hi, b.ptr + 8u, (size_t)b.len - 8u);
        return a_lo == b_lo && a_hi == b_hi;
    }
    return memcmp(a.ptr, b.ptr, a.len) == 0;
}

FASTOML_INLINE size_t fastoml_cstr_len(const char* s) {
    size_t n = 0;
    if (!s) {
        return 0;
    }
    while (s[n] != '\0') {
        ++n;
    }
    return n;
}

FASTOML_INLINE int fastoml_char_is_digit(unsigned char c) {
    return c >= '0' && c <= '9';
}

FASTOML_INLINE int fastoml_char_is_hex(unsigned char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

FASTOML_INLINE int fastoml_char_hex_value(unsigned char c) {
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(10 + (c - 'a'));
    if (c >= 'A' && c <= 'F')
        return (int)(10 + (c - 'A'));
    return -1;
}

FASTOML_INLINE int fastoml_char_is_bare_key(unsigned char c) {
    return ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-');
}

static size_t fastoml_utf8_skip_ascii(const unsigned char* s, size_t i, size_t n, int allow_simd) {
    if (allow_simd) {
#if defined(__AVX2__)
        while (i + 32u <= n) {
            const __m256i v = _mm256_loadu_si256((const __m256i*)(const void*)(s + i));
            if (_mm256_movemask_epi8(v) != 0) {
                break;
            }
            i += 32u;
        }
#endif

#if defined(__SSE2__)
        while (i + 16u <= n) {
            const __m128i v = _mm_loadu_si128((const __m128i*)(const void*)(s + i));
            if (_mm_movemask_epi8(v) != 0) {
                break;
            }
            i += 16u;
        }
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
        while (i + 16u <= n) {
            const uint8x16_t v = vld1q_u8((const uint8_t*)(const void*)(s + i));
            const uint8x16_t hi = vandq_u8(v, vdupq_n_u8(0x80u));
            const uint64x2_t hi64 = vreinterpretq_u64_u8(hi);
            if ((vgetq_lane_u64(hi64, 0) | vgetq_lane_u64(hi64, 1)) != 0u) {
                break;
            }
            i += 16u;
        }
#endif
    }

    while (i < n && s[i] < 0x80u) {
        ++i;
    }
    return i;
}

static int fastoml_utf8_validate(const fastoml_parser* p, const unsigned char* s, size_t n) {
    const int allow_simd = p && (p->opt.flags & FASTOML_PARSE_DISABLE_SIMD) == 0u;
    size_t i = fastoml_utf8_skip_ascii(s, 0u, n, allow_simd);
    while (i < n) {
        const unsigned char c = s[i];
        if (c < 0x80) {
            i = fastoml_utf8_skip_ascii(s, i, n, allow_simd);
            continue;
        }
        if (c < 0xC2) {
            return 0;
        }
        if (c <= 0xDF) {
            if (i + 1 >= n)
                return 0;
            if ((s[i + 1] & 0xC0) != 0x80)
                return 0;
            i += 2;
            continue;
        }
        if (c <= 0xEF) {
            if (i + 2 >= n)
                return 0;
            if ((s[i + 1] & 0xC0) != 0x80)
                return 0;
            if ((s[i + 2] & 0xC0) != 0x80)
                return 0;
            if (c == 0xE0 && s[i + 1] < 0xA0)
                return 0;
            if (c == 0xED && s[i + 1] >= 0xA0)
                return 0;
            i += 3;
            continue;
        }
        if (c <= 0xF4) {
            if (i + 3 >= n)
                return 0;
            if ((s[i + 1] & 0xC0) != 0x80)
                return 0;
            if ((s[i + 2] & 0xC0) != 0x80)
                return 0;
            if ((s[i + 3] & 0xC0) != 0x80)
                return 0;
            if (c == 0xF0 && s[i + 1] < 0x90)
                return 0;
            if (c == 0xF4 && s[i + 1] > 0x8F)
                return 0;
            i += 4;
            continue;
        }
        return 0;
    }
    return 1;
}

static int fastoml_arena_init(fastoml_arena* arena, fastoml_allocator alloc, size_t default_block_size) {
    memset(arena, 0, sizeof(*arena));
    arena->alloc = alloc;
    arena->default_block_size = default_block_size;
    return 1;
}

static void fastoml_arena_destroy(fastoml_arena* arena) {
    fastoml_arena_block* it = arena->first;
    while (it) {
        fastoml_arena_block* next = it->next;
        arena->alloc.free_fn(arena->alloc.ctx, it);
        it = next;
    }
    arena->first = NULL;
    arena->current = NULL;
}

static void fastoml_arena_reset(fastoml_arena* arena) {
    fastoml_arena_block* first = arena->first;
    if (!first) {
        return;
    }
    fastoml_arena_block* it = first->next;
    while (it) {
        fastoml_arena_block* next = it->next;
        arena->alloc.free_fn(arena->alloc.ctx, it);
        it = next;
    }
    first->next = NULL;
    first->used = 0;
    arena->current = first;
}

static size_t fastoml_align_up(size_t v, size_t a) {
    const size_t m = a - 1;
    return (v + m) & ~m;
}

static void* fastoml_arena_alloc(fastoml_arena* arena, size_t size, size_t align) {
    if (size == 0) {
        size = 1;
    }
    if (align < sizeof(void*)) {
        align = sizeof(void*);
    }

    {
        fastoml_arena_block* blk = arena->current;
        if (blk) {
            size_t p = fastoml_align_up(blk->used, align);
            if (p + size <= blk->cap) {
                void* out = blk->data + p;
                blk->used = p + size;
                return out;
            }
        }
    }

    {
        const size_t min_cap = size + align;
        size_t cap = arena->default_block_size;
        if (cap < min_cap) {
            cap = fastoml_align_up(min_cap, 64);
        }

        {
            const size_t total = sizeof(fastoml_arena_block) + cap;
            fastoml_arena_block* nblk = (fastoml_arena_block*)arena->alloc.malloc_fn(arena->alloc.ctx, total);
            if (!nblk) {
                return NULL;
            }
            nblk->next = NULL;
            nblk->used = 0;
            nblk->cap = cap;
            if (!arena->first) {
                arena->first = nblk;
                arena->current = nblk;
            } else {
                arena->current->next = nblk;
                arena->current = nblk;
            }
        }

        {
            fastoml_arena_block* blk = arena->current;
            size_t p = fastoml_align_up(blk->used, align);
            void* out = blk->data + p;
            blk->used = p + size;
            return out;
        }
    }
}

static void* fastoml_arena_grow_last_or_alloc(
    fastoml_arena* arena,
    void* prev_ptr,
    size_t prev_size,
    size_t new_size,
    size_t align) {
    if (new_size == 0u) {
        new_size = 1u;
    }
    if (align < sizeof(void*)) {
        align = sizeof(void*);
    }
    if (prev_ptr && prev_size <= new_size && arena->current) {
        fastoml_arena_block* blk = arena->current;
        unsigned char* p = (unsigned char*)prev_ptr;
        if (p >= blk->data && p <= blk->data + blk->cap) {
            const size_t start = (size_t)(p - blk->data);
            if (fastoml_align_up(start, align) == start &&
                start + prev_size == blk->used &&
                start + new_size <= blk->cap) {
                blk->used = start + new_size;
                return prev_ptr;
            }
        }
    }
    return fastoml_arena_alloc(arena, new_size, align);
}

typedef struct fastoml_tmpbuf {
    char* ptr;
    size_t len;
    size_t cap;
    char local[256];
} fastoml_tmpbuf;

static void fastoml_tmpbuf_init(fastoml_tmpbuf* b) {
    b->ptr = b->local;
    b->len = 0;
    b->cap = sizeof(b->local);
}

static int fastoml_tmpbuf_ensure(fastoml_reader* r, fastoml_tmpbuf* b, size_t add) {
    size_t need;
    if (add <= b->cap - b->len) {
        return 1;
    }
    need = b->len + add;
    {
        size_t next = b->cap;
        char* dst;
        while (next < need && next <= (SIZE_MAX / 2)) {
            next *= 2;
        }
        if (next < need) {
            next = need;
        }
        if (b->ptr == b->local) {
            dst = (char*)r->parser->opt.alloc.malloc_fn(r->parser->opt.alloc.ctx, next);
            if (!dst) {
                return 0;
            }
            if (b->len > 0) {
                memcpy(dst, b->ptr, b->len);
            }
        } else {
            dst = (char*)r->parser->opt.alloc.realloc_fn(r->parser->opt.alloc.ctx, b->ptr, next);
            if (!dst) {
                return 0;
            }
        }
        b->ptr = dst;
        b->cap = next;
    }
    return 1;
}

static int fastoml_tmpbuf_push_byte(fastoml_reader* r, fastoml_tmpbuf* b, char v) {
    if (!fastoml_tmpbuf_ensure(r, b, 1)) {
        return 0;
    }
    b->ptr[b->len++] = v;
    return 1;
}

static int fastoml_tmpbuf_push_mem(fastoml_reader* r, fastoml_tmpbuf* b, const char* src, size_t n) {
    if (n == 0) {
        return 1;
    }
    if (!fastoml_tmpbuf_ensure(r, b, n)) {
        return 0;
    }
    memcpy(b->ptr + b->len, src, n);
    b->len += n;
    return 1;
}

static void fastoml_tmpbuf_release(fastoml_reader* r, fastoml_tmpbuf* b) {
    if (b->ptr != b->local) {
        r->parser->opt.alloc.free_fn(r->parser->opt.alloc.ctx, b->ptr);
    }
}

static fastoml_status fastoml_tmpbuf_finish(fastoml_reader* r, fastoml_tmpbuf* b, fastoml_slice* out) {
    if (out) {
        char* dst = (char*)fastoml_arena_alloc(&r->parser->arena, b->len + 1, sizeof(char));
        if (!dst) {
            fastoml_tmpbuf_release(r, b);
            return fastoml_fail(r, FASTOML_ERR_OOM);
        }
        if (b->len > 0) {
            memcpy(dst, b->ptr, b->len);
        }
        dst[b->len] = '\0';
        out->ptr = dst;
        out->len = (uint32_t)b->len;
    }
    fastoml_tmpbuf_release(r, b);
    return FASTOML_OK;
}

typedef struct fastoml_arena_strbuf {
    char* ptr;
    size_t len;
    size_t cap;
} fastoml_arena_strbuf;

static fastoml_status fastoml_arena_strbuf_init(fastoml_reader* r, fastoml_arena_strbuf* b, size_t cap) {
    if (cap == 0u) {
        cap = 1u;
    }
    b->ptr = (char*)fastoml_arena_alloc(&r->parser->arena, cap + 1u, sizeof(char));
    if (!b->ptr) {
        return fastoml_fail(r, FASTOML_ERR_OOM);
    }
    b->len = 0u;
    b->cap = cap;
    return FASTOML_OK;
}

FASTOML_INLINE int fastoml_arena_strbuf_push_byte(fastoml_arena_strbuf* b, char v) {
    if (!b || b->len >= b->cap) {
        return 0;
    }
    b->ptr[b->len++] = v;
    return 1;
}

FASTOML_INLINE int fastoml_arena_strbuf_push_mem(fastoml_arena_strbuf* b, const char* src, size_t n) {
    if (!b || n > b->cap - b->len) {
        return 0;
    }
    if (n > 0u) {
        memcpy(b->ptr + b->len, src, n);
        b->len += n;
    }
    return 1;
}

static fastoml_status fastoml_arena_strbuf_finish(fastoml_arena_strbuf* b, fastoml_slice* out) {
    if (!b) {
        return FASTOML_OK;
    }
    b->ptr[b->len] = '\0';
    if (out) {
        out->ptr = b->ptr;
        out->len = (uint32_t)b->len;
    }
    return FASTOML_OK;
}

static int fastoml_detect_simd(void) {
#if defined(__AVX2__)
    return 1;
#elif defined(_WIN32) && (defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__))
    {
        int info[4] = {0, 0, 0, 0};
        __cpuid(info, 0);
        if (info[0] < 7)
            return 0;
        __cpuidex(info, 7, 0);
        return (info[1] & (1 << 5)) ? 1 : 0;
    }
#elif defined(__x86_64__) || defined(__i386)
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_cpu_supports("avx2") ? 1 : 0;
#else
    return 0;
#endif
#else
    return 0;
#endif
}

FASTOML_INLINE uint32_t fastoml_ctz32(uint32_t x) {
#if defined(_MSC_VER) && !defined(__clang__)
    unsigned long idx = 0;
    _BitScanForward(&idx, x);
    return (uint32_t)idx;
#elif defined(__GNUC__) || defined(__clang__)
    return (uint32_t)__builtin_ctz(x);
#else
    uint32_t c = 0;
    while ((x & 1u) == 0u) {
        x >>= 1u;
        ++c;
    }
    return c;
#endif
}

static size_t fastoml_find_value_delim_scalar(const char* s, size_t pos, size_t len) {
    while (pos + 4 <= len) {
        const unsigned char c0 = (unsigned char)s[pos + 0];
        const unsigned char c1 = (unsigned char)s[pos + 1];
        const unsigned char c2 = (unsigned char)s[pos + 2];
        const unsigned char c3 = (unsigned char)s[pos + 3];
        if (c0 == '\n' || c0 == '\r' || c0 == ',' || c0 == ']' || c0 == '}' || c0 == '#')
            return pos + 0;
        if (c1 == '\n' || c1 == '\r' || c1 == ',' || c1 == ']' || c1 == '}' || c1 == '#')
            return pos + 1;
        if (c2 == '\n' || c2 == '\r' || c2 == ',' || c2 == ']' || c2 == '}' || c2 == '#')
            return pos + 2;
        if (c3 == '\n' || c3 == '\r' || c3 == ',' || c3 == ']' || c3 == '}' || c3 == '#')
            return pos + 3;
        pos += 4;
    }
    while (pos < len) {
        const unsigned char c = (unsigned char)s[pos];
        if (c == '\n' || c == '\r' || c == ',' || c == ']' || c == '}' || c == '#') {
            break;
        }
        ++pos;
    }
    return pos;
}

static size_t fastoml_find_value_delim(const fastoml_parser* p, const char* s, size_t pos, size_t len) {
#if defined(__AVX2__)
    if (p->simd_supported && (p->opt.flags & FASTOML_PARSE_DISABLE_SIMD) == 0u) {
        while (pos + 32 <= len) {
            const __m256i v = _mm256_loadu_si256((const __m256i*)(const void*)(s + pos));
            __m256i m = _mm256_setzero_si256();
            m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, _mm256_set1_epi8('\n')));
            m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, _mm256_set1_epi8('\r')));
            m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, _mm256_set1_epi8(',')));
            m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, _mm256_set1_epi8(']')));
            m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, _mm256_set1_epi8('}')));
            m = _mm256_or_si256(m, _mm256_cmpeq_epi8(v, _mm256_set1_epi8('#')));
            {
                const uint32_t mask = (uint32_t)_mm256_movemask_epi8(m);
                if (FASTOML_UNLIKELY(mask != 0u)) {
                    return pos + fastoml_ctz32(mask);
                }
            }
            pos += 32;
        }
    }
#endif

    if ((p->opt.flags & FASTOML_PARSE_DISABLE_SIMD) == 0u) {
#if defined(__SSE2__)
        while (pos + 16u <= len) {
            const __m128i v = _mm_loadu_si128((const __m128i*)(const void*)(s + pos));
            __m128i m = _mm_setzero_si128();
            m = _mm_or_si128(m, _mm_cmpeq_epi8(v, _mm_set1_epi8('\n')));
            m = _mm_or_si128(m, _mm_cmpeq_epi8(v, _mm_set1_epi8('\r')));
            m = _mm_or_si128(m, _mm_cmpeq_epi8(v, _mm_set1_epi8(',')));
            m = _mm_or_si128(m, _mm_cmpeq_epi8(v, _mm_set1_epi8(']')));
            m = _mm_or_si128(m, _mm_cmpeq_epi8(v, _mm_set1_epi8('}')));
            m = _mm_or_si128(m, _mm_cmpeq_epi8(v, _mm_set1_epi8('#')));
            {
                const uint32_t mask = (uint32_t)_mm_movemask_epi8(m);
                if (FASTOML_UNLIKELY(mask != 0u)) {
                    return pos + (size_t)fastoml_ctz32(mask);
                }
            }
            pos += 16u;
        }
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
        while (pos + 16u <= len) {
            uint8_t mask_bytes[16];
            uint32_t i = 0u;
            const uint8x16_t v = vld1q_u8((const uint8_t*)(const void*)(s + pos));
            uint8x16_t m = vceqq_u8(v, vdupq_n_u8((uint8_t)'\n'));
            m = vorrq_u8(m, vceqq_u8(v, vdupq_n_u8((uint8_t)'\r')));
            m = vorrq_u8(m, vceqq_u8(v, vdupq_n_u8((uint8_t)',')));
            m = vorrq_u8(m, vceqq_u8(v, vdupq_n_u8((uint8_t)']')));
            m = vorrq_u8(m, vceqq_u8(v, vdupq_n_u8((uint8_t)'}')));
            m = vorrq_u8(m, vceqq_u8(v, vdupq_n_u8((uint8_t)'#')));
            vst1q_u8(mask_bytes, m);
            while (i < 16u && mask_bytes[i] == 0u) {
                ++i;
            }
            if (i != 16u) {
                return pos + (size_t)i;
            }
            pos += 16u;
        }
#endif
    }

    return fastoml_find_value_delim_scalar(s, pos, len);
}

static fastoml_node* fastoml_new_node(fastoml_reader* r, fastoml_node_kind kind) {
    fastoml_node* n = (fastoml_node*)fastoml_arena_alloc(&r->parser->arena, sizeof(fastoml_node), sizeof(void*));
    if (!n) {
        return NULL;
    }
    n->kind = kind;
    n->flags = 0u;
    switch (kind) {
    case FASTOML_NODE_TABLE:
        n->as.table.items = NULL;
        n->as.table.len = 0u;
        n->as.table.cap = 0u;
        n->as.table.hash_slots = NULL;
        n->as.table.hash_cap = 0u;
        break;
    case FASTOML_NODE_ARRAY:
        n->as.array.items = NULL;
        n->as.array.len = 0u;
        n->as.array.cap = 0u;
        break;
    case FASTOML_NODE_STRING:
    case FASTOML_NODE_DATETIME:
    case FASTOML_NODE_DATE:
    case FASTOML_NODE_TIME:
        n->as.datetime.raw.ptr = NULL;
        n->as.datetime.raw.len = 0u;
        break;
    case FASTOML_NODE_INT:
        n->as.i64 = 0;
        break;
    case FASTOML_NODE_FLOAT:
        n->as.f64 = 0.0;
        break;
    case FASTOML_NODE_BOOL:
        n->as.b = 0;
        break;
    default:
        memset(n, 0, sizeof(*n));
        n->kind = kind;
        break;
    }
    return n;
}

static int fastoml_table_reserve(fastoml_reader* r, fastoml_node* table, uint32_t new_cap) {
    fastoml_kv* items;
    fastoml_kv* old_items;
    const uint32_t old_cap = table ? table->as.table.cap : 0u;
    const size_t old_bytes = sizeof(fastoml_kv) * (size_t)old_cap;
    const size_t new_bytes = sizeof(fastoml_kv) * (size_t)new_cap;
    if (table->kind != FASTOML_NODE_TABLE) {
        return 0;
    }
    old_items = table->as.table.items;
    items = (fastoml_kv*)fastoml_arena_grow_last_or_alloc(
        &r->parser->arena,
        old_items,
        old_bytes,
        new_bytes,
        sizeof(void*));
    if (!items) {
        return 0;
    }
    if (items != old_items && old_items && table->as.table.len > 0u) {
        memcpy(items, old_items, sizeof(fastoml_kv) * (size_t)table->as.table.len);
    }
    table->as.table.items = items;
    table->as.table.cap = new_cap;
    return 1;
}

static int fastoml_array_reserve(fastoml_reader* r, fastoml_node* array, uint32_t new_cap) {
    fastoml_node** items;
    fastoml_node** old_items;
    const uint32_t old_cap = array ? array->as.array.cap : 0u;
    const size_t old_bytes = sizeof(fastoml_node*) * (size_t)old_cap;
    const size_t new_bytes = sizeof(fastoml_node*) * (size_t)new_cap;
    if (array->kind != FASTOML_NODE_ARRAY) {
        return 0;
    }
    old_items = array->as.array.items;
    items = (fastoml_node**)fastoml_arena_grow_last_or_alloc(
        &r->parser->arena,
        old_items,
        old_bytes,
        new_bytes,
        sizeof(void*));
    if (!items) {
        return 0;
    }
    if (items != old_items && old_items && array->as.array.len > 0u) {
        memcpy(items, old_items, sizeof(fastoml_node*) * (size_t)array->as.array.len);
    }
    array->as.array.items = items;
    array->as.array.cap = new_cap;
    return 1;
}

static uint32_t fastoml_u32_next_pow2(uint32_t v) {
    uint32_t n = 1u;
    while (n < v && n <= (UINT32_MAX / 2u)) {
        n <<= 1u;
    }
    if (n < v) {
        return UINT32_MAX;
    }
    return n;
}

static void fastoml_table_hash_insert_slot(fastoml_node* table, uint32_t idx) {
    const uint32_t cap = table->as.table.hash_cap;
    const uint32_t mask = cap - 1u;
    uint32_t slot = (uint32_t)(table->as.table.items[idx].hash & (uint64_t)mask);
    while (table->as.table.hash_slots[slot] != 0u) {
        slot = (slot + 1u) & mask;
    }
    table->as.table.hash_slots[slot] = idx + 1u;
}

static int fastoml_table_rebuild_hash(fastoml_reader* r, fastoml_node* table, uint32_t min_items) {
    uint32_t want = min_items;
    uint32_t i;
    uint32_t cap;
    uint32_t* slots;

    if (!table || table->kind != FASTOML_NODE_TABLE) {
        return 0;
    }
    if (table->as.table.len > want) {
        want = table->as.table.len;
    }
    if (want < FASTOML_TABLE_HASH_THRESHOLD) {
        want = FASTOML_TABLE_HASH_THRESHOLD;
    }
    if (want > (UINT32_MAX / 2u)) {
        return 0;
    }
    cap = fastoml_u32_next_pow2(want * 2u);
    if (cap == UINT32_MAX || cap == 0u) {
        return 0;
    }

    slots = (uint32_t*)fastoml_arena_grow_last_or_alloc(
        &r->parser->arena,
        table->as.table.hash_slots,
        sizeof(uint32_t) * (size_t)table->as.table.hash_cap,
        sizeof(uint32_t) * (size_t)cap,
        sizeof(uint32_t));
    if (!slots) {
        return 0;
    }
    memset(slots, 0, sizeof(uint32_t) * (size_t)cap);

    table->as.table.hash_slots = slots;
    table->as.table.hash_cap = cap;
    i = 0;
    while (i < table->as.table.len) {
        fastoml_table_hash_insert_slot(table, i);
        ++i;
    }
    return 1;
}

static int fastoml_table_prepare_hash_for_insert(fastoml_reader* r, fastoml_node* table) {
    const uint32_t next_len = table->as.table.len + 1u;
    if (next_len < FASTOML_TABLE_HASH_THRESHOLD) {
        return 1;
    }
    if (!table->as.table.hash_slots || table->as.table.hash_cap == 0u) {
        return fastoml_table_rebuild_hash(r, table, next_len);
    }
    if ((uint64_t)next_len * 10u >= (uint64_t)table->as.table.hash_cap * 7u) {
        return fastoml_table_rebuild_hash(r, table, next_len);
    }
    return 1;
}

static fastoml_kv* fastoml_table_find_kv(const fastoml_node* table, fastoml_slice key, uint64_t hash) {
    uint32_t i;
    if (!table || table->kind != FASTOML_NODE_TABLE) {
        return NULL;
    }
    if (table->as.table.hash_slots && table->as.table.hash_cap > 0u) {
        const uint32_t mask = table->as.table.hash_cap - 1u;
        uint32_t slot = (uint32_t)(hash & (uint64_t)mask);
        for (;;) {
            const uint32_t entry = table->as.table.hash_slots[slot];
            if (entry == 0u) {
                return NULL;
            }
            {
                fastoml_kv* kv = (fastoml_kv*)&table->as.table.items[entry - 1u];
                if (kv->hash == hash && fastoml_slice_eq(kv->key, key)) {
                    return kv;
                }
            }
            slot = (slot + 1u) & mask;
        }
    }
    i = 0;
    while (i < table->as.table.len) {
        fastoml_kv* kv = &table->as.table.items[i];
        if (kv->hash == hash && fastoml_slice_eq(kv->key, key)) {
            return kv;
        }
        ++i;
    }
    return NULL;
}

static fastoml_status fastoml_table_insert_hashed(fastoml_reader* r, fastoml_node* table, fastoml_slice key, uint64_t hash, fastoml_node* value) {
    if (!table || table->kind != FASTOML_NODE_TABLE) {
        return fastoml_fail(r, FASTOML_ERR_TYPE);
    }
    if (!fastoml_table_prepare_hash_for_insert(r, table)) {
        return fastoml_fail(r, FASTOML_ERR_OOM);
    }
    if (fastoml_table_find_kv(table, key, hash)) {
        return fastoml_fail(r, FASTOML_ERR_DUP_KEY);
    }
    if (table->as.table.len == table->as.table.cap) {
        const uint32_t next_cap = table->as.table.cap == 0 ? 8u : table->as.table.cap * 2u;
        if (!fastoml_table_reserve(r, table, next_cap)) {
            return fastoml_fail(r, FASTOML_ERR_OOM);
        }
    }
    table->as.table.items[table->as.table.len].key = key;
    table->as.table.items[table->as.table.len].value = value;
    table->as.table.items[table->as.table.len].hash = hash;
    if (table->as.table.hash_slots && table->as.table.hash_cap > 0u) {
        fastoml_table_hash_insert_slot(table, table->as.table.len);
    }
    table->as.table.len += 1;
    return FASTOML_OK;
}

static fastoml_status fastoml_array_push(fastoml_reader* r, fastoml_node* array, fastoml_node* value) {
    if (!array || array->kind != FASTOML_NODE_ARRAY) {
        return fastoml_fail(r, FASTOML_ERR_TYPE);
    }
    if (array->as.array.len == array->as.array.cap) {
        const uint32_t next_cap = array->as.array.cap == 0 ? 8u : array->as.array.cap * 2u;
        if (!fastoml_array_reserve(r, array, next_cap)) {
            return fastoml_fail(r, FASTOML_ERR_OOM);
        }
    }
    array->as.array.items[array->as.array.len] = value;
    array->as.array.len += 1;
    return FASTOML_OK;
}

static size_t fastoml_skip_space_tab_simd(const fastoml_reader* r, size_t pos) {
    const char* s = r->src;
    const size_t len = r->len;
    if ((r->parser->opt.flags & FASTOML_PARSE_DISABLE_SIMD) != 0u) {
        return pos;
    }

#if defined(__AVX2__)
    if (r->parser->simd_supported) {
        while (pos + 32u <= len) {
            const __m256i v = _mm256_loadu_si256((const __m256i*)(const void*)(s + pos));
            const __m256i sp = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(' '));
            const __m256i tb = _mm256_cmpeq_epi8(v, _mm256_set1_epi8('\t'));
            const uint32_t ok = (uint32_t)_mm256_movemask_epi8(_mm256_or_si256(sp, tb));
            if (ok != 0xFFFFFFFFu) {
                return pos + (size_t)fastoml_ctz32(~ok);
            }
            pos += 32u;
        }
    }
#endif

#if defined(__SSE2__)
    while (pos + 16u <= len) {
        const __m128i v = _mm_loadu_si128((const __m128i*)(const void*)(s + pos));
        const __m128i sp = _mm_cmpeq_epi8(v, _mm_set1_epi8(' '));
        const __m128i tb = _mm_cmpeq_epi8(v, _mm_set1_epi8('\t'));
        const uint32_t ok = (uint32_t)_mm_movemask_epi8(_mm_or_si128(sp, tb));
        if (ok != 0xFFFFu) {
            return pos + (size_t)fastoml_ctz32((~ok) & 0xFFFFu);
        }
        pos += 16u;
    }
#endif

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    while (pos + 16u <= len) {
        uint8_t mask_bytes[16];
        const uint8x16_t v = vld1q_u8((const uint8_t*)(const void*)(s + pos));
        const uint8x16_t sp = vceqq_u8(v, vdupq_n_u8((uint8_t)' '));
        const uint8x16_t tb = vceqq_u8(v, vdupq_n_u8((uint8_t)'\t'));
        const uint8x16_t ok = vorrq_u8(sp, tb);
        uint32_t i = 0;
        vst1q_u8(mask_bytes, ok);
        while (i < 16u && mask_bytes[i] == 0xFFu) {
            ++i;
        }
        if (i != 16u) {
            return pos + i;
        }
        pos += 16u;
    }
#endif

    return pos;
}

static void fastoml_skip_space_tab(fastoml_reader* r) {
    const size_t start = r->pos;
    size_t p = fastoml_skip_space_tab_simd(r, start);
    while (p < r->len) {
        const unsigned char c = (unsigned char)r->src[p];
        if (c != ' ' && c != '\t') {
            break;
        }
        ++p;
    }
    if (p != start) {
        fastoml_reader_advance_span_no_nl(r, p - start);
    }
}

static fastoml_status fastoml_skip_comment(fastoml_reader* r) {
    size_t p;
    if (fastoml_reader_peek(r) != '#') {
        return FASTOML_OK;
    }
    p = r->pos + 1;

#if defined(__AVX2__)
    if (r->parser->simd_supported && (r->parser->opt.flags & FASTOML_PARSE_DISABLE_SIMD) == 0u) {
        while (p + 32u <= r->len) {
            const __m256i v = _mm256_loadu_si256((const __m256i*)(const void*)(r->src + p));
            const uint32_t m_nl = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, _mm256_set1_epi8('\n')));
            const uint32_t m_cr = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, _mm256_set1_epi8('\r')));
            const uint32_t m_tab = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, _mm256_set1_epi8('\t')));
            const uint32_t m_7f = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, _mm256_set1_epi8(0x7F)));
            const uint32_t m_lt20 = (uint32_t)_mm256_movemask_epi8(_mm256_cmpgt_epi8(_mm256_set1_epi8(0x20), v));
            const uint32_t m_non_ascii = (uint32_t)_mm256_movemask_epi8(v);
            const uint32_t m_bad = ((m_lt20 & ~m_non_ascii) & ~(m_tab | m_nl | m_cr)) | m_7f;
            const uint32_t m_stop = m_bad | m_nl | m_cr;
            if (FASTOML_UNLIKELY(m_stop != 0u)) {
                p += (size_t)fastoml_ctz32(m_stop);
                break;
            }
            p += 32u;
        }
    }
#endif

#if defined(__SSE2__)
    if ((r->parser->opt.flags & FASTOML_PARSE_DISABLE_SIMD) == 0u) {
        while (p + 16u <= r->len) {
            const __m128i v = _mm_loadu_si128((const __m128i*)(const void*)(r->src + p));
            const uint32_t m_nl = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(v, _mm_set1_epi8('\n')));
            const uint32_t m_cr = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(v, _mm_set1_epi8('\r')));
            const uint32_t m_tab = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(v, _mm_set1_epi8('\t')));
            const uint32_t m_7f = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(v, _mm_set1_epi8(0x7F)));
            const uint32_t m_lt20 = (uint32_t)_mm_movemask_epi8(_mm_cmpgt_epi8(_mm_set1_epi8(0x20), v));
            const uint32_t m_non_ascii = (uint32_t)_mm_movemask_epi8(v);
            const uint32_t m_bad = ((m_lt20 & ~m_non_ascii) & ~(m_tab | m_nl | m_cr)) | m_7f;
            const uint32_t m_stop = m_bad | m_nl | m_cr;
            if (FASTOML_UNLIKELY(m_stop != 0u)) {
                p += (size_t)fastoml_ctz32(m_stop);
                break;
            }
            p += 16u;
        }
    }
#endif

    while (p < r->len) {
        const unsigned char c = (unsigned char)r->src[p];
        if (c == '\n' || c == '\r') {
            break;
        }
        if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F) {
            fastoml_reader_advance_span_no_nl(r, p - r->pos);
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        ++p;
    }
    if (p != r->pos) {
        fastoml_reader_advance_span_no_nl(r, p - r->pos);
    }
    return FASTOML_OK;
}

static fastoml_status fastoml_skip_ws_comment_nl(fastoml_reader* r) {
    for (;;) {
        unsigned char c;
        fastoml_skip_space_tab(r);
        if (fastoml_reader_eof(r)) {
            break;
        }
        c = (unsigned char)r->src[r->pos];
        if (c == '#') {
            if (fastoml_skip_comment(r) != FASTOML_OK) {
                return r->err.code;
            }
            if (fastoml_reader_eof(r)) {
                break;
            }
            c = (unsigned char)r->src[r->pos];
        }
        if (c == '\n' || c == '\r') {
            if (fastoml_reader_advance_newline(r) != FASTOML_OK) {
                return r->err.code;
            }
            continue;
        }
        break;
    }
    return FASTOML_OK;
}

static fastoml_status fastoml_expect_line_end(fastoml_reader* r) {
    fastoml_skip_space_tab(r);
    if (fastoml_reader_peek(r) == '#') {
        const fastoml_status s = fastoml_skip_comment(r);
        if (s != FASTOML_OK) {
            return s;
        }
    }
    if (fastoml_reader_eof(r)) {
        return FASTOML_OK;
    }
    if (fastoml_reader_peek(r) == '\n' || fastoml_reader_peek(r) == '\r') {
        return fastoml_reader_advance_newline(r);
    }
    return fastoml_fail(r, FASTOML_ERR_SYNTAX);
}

static fastoml_status fastoml_parse_hex_escape(fastoml_reader* r, uint32_t digits, uint32_t* out_code) {
    uint32_t i = 0;
    uint32_t cp = 0;
    while (i < digits) {
        const int v = fastoml_char_hex_value(fastoml_reader_peek(r));
        if (v < 0) {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        cp = (cp << 4) | (uint32_t)v;
        fastoml_reader_advance_byte(r);
        ++i;
    }
    *out_code = cp;
    return FASTOML_OK;
}

static int fastoml_utf8_encode(uint32_t cp, char* out, size_t* out_len) {
    if (cp <= 0x7F) {
        out[0] = (char)cp;
        *out_len = 1;
        return 1;
    }
    if (cp <= 0x7FF) {
        out[0] = (char)(0xC0u | (cp >> 6));
        out[1] = (char)(0x80u | (cp & 0x3Fu));
        *out_len = 2;
        return 1;
    }
    if (cp >= 0xD800 && cp <= 0xDFFF) {
        return 0;
    }
    if (cp <= 0xFFFF) {
        out[0] = (char)(0xE0u | (cp >> 12));
        out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (cp & 0x3Fu));
        *out_len = 3;
        return 1;
    }
    if (cp <= 0x10FFFF) {
        out[0] = (char)(0xF0u | (cp >> 18));
        out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
        out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[3] = (char)(0x80u | (cp & 0x3Fu));
        *out_len = 4;
        return 1;
    }
    return 0;
}
static fastoml_status fastoml_parse_basic_string(fastoml_reader* r, int multiline, fastoml_slice* out, int for_key) {
    fastoml_status s = FASTOML_OK;
    fastoml_arena_strbuf sb;
    fastoml_arena_strbuf* sb_ptr = NULL;

    if (multiline) {
        if (fastoml_reader_peek(r) != '"' || fastoml_reader_peek_n(r, 1) != '"' || fastoml_reader_peek_n(r, 2) != '"') {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        fastoml_reader_advance_byte(r);
        fastoml_reader_advance_byte(r);
        fastoml_reader_advance_byte(r);
        if (fastoml_reader_peek(r) == '\n' || fastoml_reader_peek(r) == '\r') {
            s = fastoml_reader_advance_newline(r);
            if (s != FASTOML_OK)
                return s;
        }
    } else {
        if (fastoml_reader_peek(r) != '"') {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        fastoml_reader_advance_byte(r);
    }

    if (!multiline) {
        const size_t start = r->pos;
        size_t p = start;
        while (p < r->len) {
            const unsigned char c = (unsigned char)r->src[p];
            if (c == '"') {
                if (out) {
                    out->ptr = r->src + start;
                    out->len = (uint32_t)(p - start);
                }
                fastoml_reader_advance_span_no_nl(r, (p + 1u) - r->pos);
                return FASTOML_OK;
            }
            if (c == '\\') {
                break;
            }
            if (c == '\n' || c == '\r') {
                fastoml_reader_advance_span_no_nl(r, p - r->pos);
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            if ((c < 0x20 && c != '\t') || c == 0x7F) {
                fastoml_reader_advance_span_no_nl(r, p - r->pos);
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            ++p;
        }
        if (p >= r->len) {
            fastoml_reader_advance_span_no_nl(r, p - r->pos);
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
    } else {
        const size_t start = r->pos;
        size_t p = start;
        while (p < r->len) {
            const unsigned char c = (unsigned char)r->src[p];
            if (c == '\\' || c == '\r') {
                break;
            }
            if (c == '"') {
                size_t run = 0;
                while (p + run < r->len && r->src[p + run] == '"') {
                    run += 1;
                }
                if (run >= 3u) {
                    const size_t lit = run - 3u;
                    if (run > 5u) {
                        fastoml_reader_advance_span_lf(r, r->src + r->pos, p - r->pos);
                        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                    }
                    if (out) {
                        out->ptr = r->src + start;
                        out->len = (uint32_t)((p - start) + lit);
                    }
                    fastoml_reader_advance_span_lf(r, r->src + r->pos, p - r->pos);
                    fastoml_reader_advance_span_no_nl(r, run);
                    return FASTOML_OK;
                }
                p += run;
                continue;
            }
            if ((c < 0x20 && c != '\t' && c != '\n') || c == 0x7F) {
                fastoml_reader_advance_span_lf(r, r->src + r->pos, p - r->pos);
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            ++p;
        }
    }

    {
        if (out) {
            s = fastoml_arena_strbuf_init(r, &sb, r->len - r->pos);
            if (s != FASTOML_OK) {
                return s;
            }
            sb_ptr = &sb;
        }

        while (!fastoml_reader_eof(r)) {
            const unsigned char c = fastoml_reader_peek(r);

            if (!multiline && c == '"') {
                fastoml_reader_advance_byte(r);
                return fastoml_arena_strbuf_finish(sb_ptr, out);
            }

            if (multiline && c == '"') {
                size_t run = 0;
                while (fastoml_reader_peek_n(r, run) == '"') {
                    run += 1;
                }
                if (run >= 3) {
                    size_t lit;
                    if (run > 5) {
                        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                    }
                    lit = run - 3;
                    if (lit > 0u) {
                        if (sb_ptr && !fastoml_arena_strbuf_push_mem(sb_ptr, r->src + r->pos, lit)) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                    }
                    while (run > 0) {
                        fastoml_reader_advance_byte(r);
                        run -= 1;
                    }
                    return fastoml_arena_strbuf_finish(sb_ptr, out);
                }
                if (sb_ptr && !fastoml_arena_strbuf_push_mem(sb_ptr, r->src + r->pos, run)) {
                    return fastoml_fail(r, FASTOML_ERR_OOM);
                }
                fastoml_reader_advance_span_no_nl(r, run);
                continue;
            }

            if (c == '\\') {
                fastoml_reader_advance_byte(r);
                if (fastoml_reader_eof(r)) {
                    return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                }
                {
                    const unsigned char e = fastoml_reader_peek(r);
                    if (e == 'b') {
                        if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, '\b')) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        fastoml_reader_advance_byte(r);
                        continue;
                    }
                    if (e == 't') {
                        if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, '\t')) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        fastoml_reader_advance_byte(r);
                        continue;
                    }
                    if (e == 'n') {
                        if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, '\n')) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        fastoml_reader_advance_byte(r);
                        continue;
                    }
                    if (e == 'f') {
                        if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, '\f')) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        fastoml_reader_advance_byte(r);
                        continue;
                    }
                    if (e == 'r') {
                        if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, '\r')) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        fastoml_reader_advance_byte(r);
                        continue;
                    }
                    if (e == 'e') {
                        if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, 0x1B)) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        fastoml_reader_advance_byte(r);
                        continue;
                    }
                    if (e == '"') {
                        if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, '"')) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        fastoml_reader_advance_byte(r);
                        continue;
                    }
                    if (e == '\\') {
                        if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, '\\')) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        fastoml_reader_advance_byte(r);
                        continue;
                    }
                    if (e == 'x' || e == 'u' || e == 'U') {
                        uint32_t cp = 0;
                        char enc[4];
                        size_t enc_len = 0;
                        const uint32_t digits = (e == 'x') ? 2u : ((e == 'u') ? 4u : 8u);
                        fastoml_reader_advance_byte(r);
                        s = fastoml_parse_hex_escape(r, digits, &cp);
                        if (s != FASTOML_OK) {
                            return s;
                        }
                        if (!fastoml_utf8_encode(cp, enc, &enc_len)) {
                            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                        }
                        if (sb_ptr && !fastoml_arena_strbuf_push_mem(sb_ptr, enc, enc_len)) {
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        continue;
                    }
                    if (multiline) {
                        while (fastoml_reader_peek(r) == ' ' || fastoml_reader_peek(r) == '\t') {
                            fastoml_reader_advance_byte(r);
                        }
                        if (fastoml_reader_peek(r) == '\n' || fastoml_reader_peek(r) == '\r') {
                            s = fastoml_reader_advance_newline(r);
                            if (s != FASTOML_OK) {
                                return s;
                            }
                            while (!fastoml_reader_eof(r)) {
                                const unsigned char k = fastoml_reader_peek(r);
                                if (k == ' ' || k == '\t') {
                                    fastoml_reader_advance_byte(r);
                                    continue;
                                }
                                if (k == '\n' || k == '\r') {
                                    s = fastoml_reader_advance_newline(r);
                                    if (s != FASTOML_OK) {
                                        return s;
                                    }
                                    continue;
                                }
                                break;
                            }
                            continue;
                        }
                    }
                    return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                }
            }

            if (c != '"' && c != '\\' && c != '\n' && c != '\r') {
                const size_t start = r->pos;
                size_t p = start;
                while (p < r->len) {
                    const unsigned char k = (unsigned char)r->src[p];
                    if (k == '"' || k == '\\' || k == '\n' || k == '\r') {
                        break;
                    }
                    if ((k < 0x20 && k != '\t') || k == 0x7F) {
                        fastoml_reader_advance_span_no_nl(r, p - start);
                        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                    }
                    ++p;
                }
                if (p > start) {
                    const size_t n = p - start;
                    if (sb_ptr && !fastoml_arena_strbuf_push_mem(sb_ptr, r->src + start, n)) {
                        return fastoml_fail(r, FASTOML_ERR_OOM);
                    }
                    fastoml_reader_advance_span_no_nl(r, n);
                    continue;
                }
            }

            if (!multiline && (c == '\n' || c == '\r')) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            if (for_key && (c == '\n' || c == '\r')) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }

            if (c == '\n' || c == '\r') {
                if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, '\n')) {
                    return fastoml_fail(r, FASTOML_ERR_OOM);
                }
                s = fastoml_reader_advance_newline(r);
                if (s != FASTOML_OK) {
                    return s;
                }
            } else {
                if (sb_ptr && !fastoml_arena_strbuf_push_byte(sb_ptr, (char)c)) {
                    return fastoml_fail(r, FASTOML_ERR_OOM);
                }
                fastoml_reader_advance_byte(r);
            }
        }

        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
}

static fastoml_status fastoml_parse_literal_string(fastoml_reader* r, int multiline, fastoml_slice* out, int for_key) {
    fastoml_status s = FASTOML_OK;

    if (multiline) {
        if (fastoml_reader_peek(r) != '\'' || fastoml_reader_peek_n(r, 1) != '\'' || fastoml_reader_peek_n(r, 2) != '\'') {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        fastoml_reader_advance_byte(r);
        fastoml_reader_advance_byte(r);
        fastoml_reader_advance_byte(r);
        if (fastoml_reader_peek(r) == '\n' || fastoml_reader_peek(r) == '\r') {
            s = fastoml_reader_advance_newline(r);
            if (s != FASTOML_OK)
                return s;
        }
    } else {
        if (fastoml_reader_peek(r) != '\'') {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        fastoml_reader_advance_byte(r);
    }

    if (!multiline) {
        const size_t start = r->pos;
        size_t p = start;
        while (p < r->len) {
            const unsigned char c = (unsigned char)r->src[p];
            if (c == '\'') {
                if (out) {
                    out->ptr = r->src + start;
                    out->len = (uint32_t)(p - start);
                }
                fastoml_reader_advance_span_no_nl(r, (p + 1u) - r->pos);
                return FASTOML_OK;
            }
            if (c == '\n' || c == '\r') {
                fastoml_reader_advance_span_no_nl(r, p - r->pos);
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            if ((c < 0x20 && c != '\t') || c == 0x7F) {
                fastoml_reader_advance_span_no_nl(r, p - r->pos);
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            ++p;
        }
        if (p >= r->len) {
            fastoml_reader_advance_span_no_nl(r, p - r->pos);
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
    } else {
        const size_t start = r->pos;
        size_t p = start;
        while (p < r->len) {
            const unsigned char c = (unsigned char)r->src[p];
            if (c == '\r') {
                break;
            }
            if (c == '\'') {
                size_t run = 0;
                while (p + run < r->len && r->src[p + run] == '\'') {
                    run += 1;
                }
                if (run >= 3u) {
                    const size_t lit = run - 3u;
                    if (run > 5u) {
                        fastoml_reader_advance_span_lf(r, r->src + r->pos, p - r->pos);
                        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                    }
                    if (out) {
                        out->ptr = r->src + start;
                        out->len = (uint32_t)((p - start) + lit);
                    }
                    fastoml_reader_advance_span_lf(r, r->src + r->pos, p - r->pos);
                    fastoml_reader_advance_span_no_nl(r, run);
                    return FASTOML_OK;
                }
                p += run;
                continue;
            }
            if ((c < 0x20 && c != '\t' && c != '\n') || c == 0x7F) {
                fastoml_reader_advance_span_lf(r, r->src + r->pos, p - r->pos);
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            ++p;
        }
    }

    {
        fastoml_tmpbuf tmp;
        fastoml_tmpbuf_init(&tmp);

        while (!fastoml_reader_eof(r)) {
            const unsigned char c = fastoml_reader_peek(r);

            if (!multiline && c == '\'') {
                fastoml_reader_advance_byte(r);
                return fastoml_tmpbuf_finish(r, &tmp, out);
            }
            if (multiline && c == '\'') {
                size_t run = 0;
                while (fastoml_reader_peek_n(r, run) == '\'') {
                    run += 1;
                }
                if (run >= 3) {
                    size_t lit;
                    if (run > 5) {
                        fastoml_tmpbuf_release(r, &tmp);
                        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                    }
                    lit = run - 3;
                    while (lit > 0) {
                        if (!fastoml_tmpbuf_push_byte(r, &tmp, '\'')) {
                            fastoml_tmpbuf_release(r, &tmp);
                            return fastoml_fail(r, FASTOML_ERR_OOM);
                        }
                        lit -= 1;
                    }
                    while (run > 0) {
                        fastoml_reader_advance_byte(r);
                        run -= 1;
                    }
                    return fastoml_tmpbuf_finish(r, &tmp, out);
                }
                while (run > 0) {
                    if (!fastoml_tmpbuf_push_byte(r, &tmp, '\'')) {
                        fastoml_tmpbuf_release(r, &tmp);
                        return fastoml_fail(r, FASTOML_ERR_OOM);
                    }
                    fastoml_reader_advance_byte(r);
                    run -= 1;
                }
                continue;
            }
            if (!multiline && (c == '\n' || c == '\r')) {
                fastoml_tmpbuf_release(r, &tmp);
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            if (for_key && (c == '\n' || c == '\r')) {
                fastoml_tmpbuf_release(r, &tmp);
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }

            if (c == '\n' || c == '\r') {
                if (!fastoml_tmpbuf_push_byte(r, &tmp, '\n')) {
                    fastoml_tmpbuf_release(r, &tmp);
                    return fastoml_fail(r, FASTOML_ERR_OOM);
                }
                s = fastoml_reader_advance_newline(r);
                if (s != FASTOML_OK) {
                    fastoml_tmpbuf_release(r, &tmp);
                    return s;
                }
            } else {
                if ((c < 0x20 && c != '\t') || c == 0x7F) {
                    fastoml_tmpbuf_release(r, &tmp);
                    return fastoml_fail(r, FASTOML_ERR_SYNTAX);
                }
                if (!fastoml_tmpbuf_push_byte(r, &tmp, (char)c)) {
                    fastoml_tmpbuf_release(r, &tmp);
                    return fastoml_fail(r, FASTOML_ERR_OOM);
                }
                fastoml_reader_advance_byte(r);
            }
        }
        fastoml_tmpbuf_release(r, &tmp);
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
}

static fastoml_status fastoml_parse_key_part(fastoml_reader* r, fastoml_slice* out) {
    const unsigned char c = fastoml_reader_peek(r);
    if (c == '"') {
        if (fastoml_reader_peek_n(r, 1) == '"' && fastoml_reader_peek_n(r, 2) == '"') {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        return fastoml_parse_basic_string(r, 0, out, 1);
    }
    if (c == '\'') {
        if (fastoml_reader_peek_n(r, 1) == '\'' && fastoml_reader_peek_n(r, 2) == '\'') {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        return fastoml_parse_literal_string(r, 0, out, 1);
    }
    if (fastoml_char_is_bare_key(c)) {
        const size_t start = r->pos;
        size_t p = start;
        while (p < r->len && fastoml_char_is_bare_key((unsigned char)r->src[p])) {
            ++p;
        }
        fastoml_reader_advance_span_no_nl(r, p - start);
        out->ptr = r->src + start;
        out->len = (uint32_t)(r->pos - start);
        return FASTOML_OK;
    }
    return fastoml_fail(r, FASTOML_ERR_SYNTAX);
}

static void fastoml_key_path_init(fastoml_key_path* path) {
    path->parts = path->local_parts;
    path->hashes = path->local_hashes;
    path->count = 0;
    path->cap = (uint32_t)(sizeof(path->local_parts) / sizeof(path->local_parts[0]));
}

static void fastoml_key_path_release(fastoml_reader* r, fastoml_key_path* path) {
    if (path->parts && path->parts != path->local_parts) {
        r->parser->opt.alloc.free_fn(r->parser->opt.alloc.ctx, path->parts);
    }
    if (path->hashes && path->hashes != path->local_hashes) {
        r->parser->opt.alloc.free_fn(r->parser->opt.alloc.ctx, path->hashes);
    }
    path->parts = path->local_parts;
    path->hashes = path->local_hashes;
    path->count = 0;
    path->cap = (uint32_t)(sizeof(path->local_parts) / sizeof(path->local_parts[0]));
}

static fastoml_status fastoml_key_path_grow(fastoml_reader* r, fastoml_key_path* path, uint32_t max_parts) {
    uint32_t next_cap;
    fastoml_slice* next_parts;
    uint64_t* next_hashes;
    if (path->cap >= max_parts) {
        return fastoml_fail(r, FASTOML_ERR_DEPTH);
    }
    next_cap = path->cap < 8u ? 8u : path->cap * 2u;
    if (next_cap > max_parts) {
        next_cap = max_parts;
    }
    next_parts = (fastoml_slice*)r->parser->opt.alloc.malloc_fn(
        r->parser->opt.alloc.ctx,
        sizeof(fastoml_slice) * (size_t)next_cap);
    if (!next_parts) {
        return fastoml_fail(r, FASTOML_ERR_OOM);
    }
    next_hashes = (uint64_t*)r->parser->opt.alloc.malloc_fn(
        r->parser->opt.alloc.ctx,
        sizeof(uint64_t) * (size_t)next_cap);
    if (!next_hashes) {
        r->parser->opt.alloc.free_fn(r->parser->opt.alloc.ctx, next_parts);
        return fastoml_fail(r, FASTOML_ERR_OOM);
    }
    if (path->count > 0u) {
        memcpy(next_parts, path->parts, sizeof(fastoml_slice) * (size_t)path->count);
        memcpy(next_hashes, path->hashes, sizeof(uint64_t) * (size_t)path->count);
    }
    if (path->parts != path->local_parts) {
        r->parser->opt.alloc.free_fn(r->parser->opt.alloc.ctx, path->parts);
    }
    if (path->hashes != path->local_hashes) {
        r->parser->opt.alloc.free_fn(r->parser->opt.alloc.ctx, path->hashes);
    }
    path->parts = next_parts;
    path->hashes = next_hashes;
    path->cap = next_cap;
    return FASTOML_OK;
}

static fastoml_status fastoml_parse_key_path(fastoml_reader* r, fastoml_key_path* out) {
    const uint32_t max_parts = r->parser->opt.max_depth;
    fastoml_key_path_init(out);
    if (max_parts == 0u) {
        return fastoml_fail(r, FASTOML_ERR_DEPTH);
    }
    for (;;) {
        if (out->count >= max_parts) {
            return fastoml_fail(r, FASTOML_ERR_DEPTH);
        }
        if (out->count >= out->cap) {
            fastoml_status s = fastoml_key_path_grow(r, out, max_parts);
            if (s != FASTOML_OK) {
                return s;
            }
        }
        if (fastoml_parse_key_part(r, &out->parts[out->count]) != FASTOML_OK) {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        out->hashes[out->count] = fastoml_hash_slice(out->parts[out->count]);
        out->count += 1;
        fastoml_skip_space_tab(r);
        if (fastoml_reader_peek(r) == '.') {
            fastoml_reader_advance_byte(r);
            fastoml_skip_space_tab(r);
            continue;
        }
        break;
    }
    return FASTOML_OK;
}

static fastoml_status fastoml_insert_path_value(fastoml_reader* r, fastoml_node* base, const fastoml_key_path* path, fastoml_node* value, int inline_context) {
    uint32_t i = 0;
    fastoml_node* cur = base;
    while (i + 1 < path->count) {
        const fastoml_slice key = path->parts[i];
        const uint64_t hash = path->hashes[i];
        fastoml_kv* kv = fastoml_table_find_kv(cur, key, hash);
        if (!kv) {
            fastoml_node* child = fastoml_new_node(r, FASTOML_NODE_TABLE);
            if (!child) {
                return fastoml_fail(r, FASTOML_ERR_OOM);
            }
            if (inline_context) {
                child->flags |= FASTOML_TABLE_INLINE_BUILDING;
            } else {
                child->flags |= FASTOML_TABLE_DOTTED_DEFINED;
            }
            if (fastoml_table_insert_hashed(r, cur, key, hash, child) != FASTOML_OK) {
                return r->err.code;
            }
            cur = child;
        } else {
            if (!kv->value || kv->value->kind != FASTOML_NODE_TABLE) {
                return fastoml_fail(r, FASTOML_ERR_TYPE);
            }
            if ((kv->value->flags & FASTOML_TABLE_INLINE_SEALED) != 0) {
                return fastoml_fail(r, FASTOML_ERR_TYPE);
            }
            if (!inline_context && (kv->value->flags & FASTOML_TABLE_EXPLICIT) != 0) {
                return fastoml_fail(r, FASTOML_ERR_DUP_KEY);
            }
            if (!inline_context) {
                kv->value->flags |= FASTOML_TABLE_DOTTED_DEFINED;
            }
            cur = kv->value;
        }
        ++i;
    }

    if ((cur->flags & FASTOML_TABLE_INLINE_SEALED) != 0) {
        return fastoml_fail(r, FASTOML_ERR_TYPE);
    }
    return fastoml_table_insert_hashed(
        r,
        cur,
        path->parts[path->count - 1],
        path->hashes[path->count - 1],
        value);
}

static int fastoml_is_leap(int y) {
    if ((y % 400) == 0)
        return 1;
    if ((y % 100) == 0)
        return 0;
    return (y % 4) == 0;
}

static int fastoml_days_in_month(int y, int m) {
    static const int days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m < 1 || m > 12)
        return 0;
    if (m == 2)
        return fastoml_is_leap(y) ? 29 : 28;
    return days[m - 1];
}

static int fastoml_parse_2digits(const char* p, int* out) {
    if (!fastoml_char_is_digit((unsigned char)p[0]) || !fastoml_char_is_digit((unsigned char)p[1])) {
        return 0;
    }
    *out = (p[0] - '0') * 10 + (p[1] - '0');
    return 1;
}

static int fastoml_parse_4digits(const char* p, int* out) {
    int y;
    if (!fastoml_char_is_digit((unsigned char)p[0]) ||
        !fastoml_char_is_digit((unsigned char)p[1]) ||
        !fastoml_char_is_digit((unsigned char)p[2]) ||
        !fastoml_char_is_digit((unsigned char)p[3])) {
        return 0;
    }
    y = (p[0] - '0') * 1000 + (p[1] - '0') * 100 + (p[2] - '0') * 10 + (p[3] - '0');
    *out = y;
    return 1;
}

static int fastoml_try_parse_local_date(fastoml_slice tok) {
    int y, m, d;
    if (tok.len != 10)
        return 0;
    if (!fastoml_parse_4digits(tok.ptr + 0, &y))
        return 0;
    if (tok.ptr[4] != '-')
        return 0;
    if (!fastoml_parse_2digits(tok.ptr + 5, &m))
        return 0;
    if (tok.ptr[7] != '-')
        return 0;
    if (!fastoml_parse_2digits(tok.ptr + 8, &d))
        return 0;
    if (m < 1 || m > 12)
        return 0;
    if (d < 1 || d > fastoml_days_in_month(y, m))
        return 0;
    return 1;
}

static int fastoml_parse_time_core(const char* p, size_t n, size_t* consumed) {
    int hh, mm, ss;
    size_t i = 0;
    int has_seconds = 0;
    if (n < 5)
        return 0;
    if (!fastoml_parse_2digits(p + 0, &hh))
        return 0;
    if (p[2] != ':')
        return 0;
    if (!fastoml_parse_2digits(p + 3, &mm))
        return 0;
    if (hh < 0 || hh > 23)
        return 0;
    if (mm < 0 || mm > 59)
        return 0;
    i = 5;

    if (i < n && p[i] == ':') {
        has_seconds = 1;
        i += 1;
        if (i + 2 > n)
            return 0;
        if (!fastoml_parse_2digits(p + i, &ss))
            return 0;
        if (ss < 0 || ss > 60)
            return 0;
        i += 2;
    }

    if (i < n && p[i] == '.') {
        size_t frac = 0;
        if (!has_seconds)
            return 0;
        i += 1;
        while (i < n && fastoml_char_is_digit((unsigned char)p[i])) {
            i += 1;
            frac += 1;
        }
        if (frac == 0)
            return 0;
    }

    *consumed = i;
    return 1;
}

static int fastoml_try_parse_local_time(fastoml_slice tok) {
    size_t c = 0;
    if (!fastoml_parse_time_core(tok.ptr, tok.len, &c))
        return 0;
    return c == tok.len;
}

static int fastoml_try_parse_datetime(fastoml_slice tok, fastoml_node_kind* kind_out) {
    size_t c = 0;
    if (fastoml_try_parse_local_date(tok)) {
        *kind_out = FASTOML_NODE_DATE;
        return 1;
    }

    if (fastoml_try_parse_local_time(tok)) {
        *kind_out = FASTOML_NODE_TIME;
        return 1;
    }

    if (tok.len < 11) {
        return 0;
    }
    if (!fastoml_try_parse_local_date((fastoml_slice){tok.ptr, 10})) {
        return 0;
    }
    if (!(tok.ptr[10] == 'T' || tok.ptr[10] == 't' || tok.ptr[10] == ' ')) {
        return 0;
    }
    if (!fastoml_parse_time_core(tok.ptr + 11, tok.len - 11, &c)) {
        return 0;
    }
    {
        size_t rest = tok.len - 11 - c;
        const char* p = tok.ptr + 11 + c;
        if (rest == 0) {
            *kind_out = FASTOML_NODE_DATETIME;
            return 1;
        }
        if (rest == 1 && (p[0] == 'Z' || p[0] == 'z')) {
            *kind_out = FASTOML_NODE_DATETIME;
            return 1;
        }
        if (rest == 6 && (p[0] == '+' || p[0] == '-')) {
            int oh, om;
            if (!fastoml_parse_2digits(p + 1, &oh))
                return 0;
            if (p[3] != ':')
                return 0;
            if (!fastoml_parse_2digits(p + 4, &om))
                return 0;
            if (oh < 0 || oh > 23)
                return 0;
            if (om < 0 || om > 59)
                return 0;
            *kind_out = FASTOML_NODE_DATETIME;
            return 1;
        }
    }
    return 0;
}

static int fastoml_token_equals(fastoml_slice tok, const char* lit) {
    const size_t n = fastoml_cstr_len(lit);
    if (tok.len != (uint32_t)n)
        return 0;
    if (n == 0)
        return 1;
    return memcmp(tok.ptr, lit, n) == 0;
}

static int fastoml_token_is_nondecimal_int(fastoml_slice tok) {
    size_t i = 0;
    if (tok.len < 3)
        return 0;
    if (tok.ptr[i] == '+' || tok.ptr[i] == '-') {
        i += 1;
    }
    if (i + 1 >= tok.len)
        return 0;
    if (tok.ptr[i] != '0')
        return 0;
    return tok.ptr[i + 1] == 'x' || tok.ptr[i + 1] == 'o' || tok.ptr[i + 1] == 'b';
}

static fastoml_status fastoml_parse_int_token(fastoml_reader* r, fastoml_slice tok, int64_t* out) {
    int sign = 1;
    int sign_present = 0;
    size_t i = 0;
    int base = 10;
    uint64_t acc = 0;
    int prev_digit = 0;
    int saw_digit = 0;
    size_t digit_count = 0;
    size_t first_digit_idx = 0;

    if (tok.len == 0)
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);

    if (tok.ptr[i] == '+' || tok.ptr[i] == '-') {
        sign = tok.ptr[i] == '-' ? -1 : 1;
        sign_present = 1;
        i += 1;
        if (i >= tok.len)
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }

    if (i + 1 < tok.len && tok.ptr[i] == '0' &&
        (tok.ptr[i + 1] == 'x' || tok.ptr[i + 1] == 'o' || tok.ptr[i + 1] == 'b')) {
        if (sign_present)
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        base = tok.ptr[i + 1] == 'x' ? 16 : (tok.ptr[i + 1] == 'o' ? 8 : 2);
        i += 2;
        first_digit_idx = i;
    } else {
        first_digit_idx = i;
    }

    while (i < tok.len) {
        const unsigned char c = (unsigned char)tok.ptr[i];
        int digit = -1;

        if (c == '_') {
            if (!prev_digit)
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            if (i + 1 >= tok.len)
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            if (base == 10 && !fastoml_char_is_digit((unsigned char)tok.ptr[i + 1])) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            if (base == 16 && !fastoml_char_is_hex((unsigned char)tok.ptr[i + 1])) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            if (base == 8 && !(tok.ptr[i + 1] >= '0' && tok.ptr[i + 1] <= '7')) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            if (base == 2 && !(tok.ptr[i + 1] == '0' || tok.ptr[i + 1] == '1')) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            prev_digit = 0;
            ++i;
            continue;
        }

        if (base == 10) {
            if (!fastoml_char_is_digit(c))
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            digit = c - '0';
        } else if (base == 16) {
            digit = fastoml_char_hex_value(c);
            if (digit < 0)
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        } else if (base == 8) {
            if (!(c >= '0' && c <= '7'))
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            digit = c - '0';
        } else {
            if (!(c == '0' || c == '1'))
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            digit = c - '0';
        }

        {
            const uint64_t limit = (sign < 0) ? 9223372036854775808ull : 9223372036854775807ull;
            if (acc > (limit - (uint64_t)digit) / (uint64_t)base) {
                return fastoml_fail(r, FASTOML_ERR_OVERFLOW);
            }
        }
        acc = acc * (uint64_t)base + (uint64_t)digit;
        prev_digit = 1;
        saw_digit = 1;
        digit_count += 1;
        ++i;
    }

    if (!saw_digit || !prev_digit) {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }

    if (base == 10 && digit_count > 1 && tok.ptr[first_digit_idx] == '0') {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }

    if (sign < 0) {
        if (acc == 9223372036854775808ull) {
            *out = INT64_MIN;
        } else {
            *out = -(int64_t)acc;
        }
    } else {
        *out = (int64_t)acc;
    }
    return FASTOML_OK;
}

FASTOML_INLINE long double fastoml_scale_pow10_ld(long double v, int exp10) {
    static const long double pow10_pos[] = {
        1e1L, 1e2L, 1e4L, 1e8L, 1e16L, 1e32L, 1e64L, 1e128L, 1e256L};
    static const long double pow10_neg[] = {
        1e-1L, 1e-2L, 1e-4L, 1e-8L, 1e-16L, 1e-32L, 1e-64L, 1e-128L, 1e-256L};
    uint32_t bit = 0u;
    uint32_t e = (uint32_t)(exp10 < 0 ? -exp10 : exp10);
    if (exp10 >= 0) {
        while (e != 0u) {
            if ((e & 1u) != 0u) {
                v *= pow10_pos[bit];
            }
            e >>= 1u;
            bit += 1u;
        }
    } else {
        while (e != 0u) {
            if ((e & 1u) != 0u) {
                v *= pow10_neg[bit];
            }
            e >>= 1u;
            bit += 1u;
        }
    }
    return v;
}

static fastoml_status fastoml_parse_float_decimal(int sign, uint64_t mantissa, int exp10, double* out) {
    if (exp10 > 308 || exp10 < -400) {
        return FASTOML_ERR_OVERFLOW;
    }

    if (exp10 >= -22 && exp10 <= 22 && mantissa <= 9007199254740991ull) {
        static const double pow10_small_pos[] = {
            1.0, 10.0, 100.0, 1000.0, 10000.0, 100000.0, 1000000.0, 10000000.0,
            100000000.0, 1000000000.0, 10000000000.0, 100000000000.0, 1000000000000.0,
            10000000000000.0, 100000000000000.0, 1000000000000000.0, 10000000000000000.0,
            100000000000000000.0, 1000000000000000000.0, 10000000000000000000.0,
            100000000000000000000.0, 1000000000000000000000.0, 10000000000000000000000.0};
        double v = (double)mantissa;
        if (exp10 >= 0) {
            v *= pow10_small_pos[(size_t)exp10];
        } else {
            v /= pow10_small_pos[(size_t)(-exp10)];
        }
        if (!isfinite(v) || v == 0.0) {
            return FASTOML_ERR_OVERFLOW;
        }
        *out = sign < 0 ? -v : v;
        return FASTOML_OK;
    }

    {
        const long double lv = fastoml_scale_pow10_ld((long double)mantissa, exp10);
        const double v = (double)lv;
        if (!isfinite(v) || v == 0.0) {
            return FASTOML_ERR_OVERFLOW;
        }
        *out = sign < 0 ? -v : v;
    }
    return FASTOML_OK;
}

static int fastoml_token_is_float_keyword(fastoml_slice tok) {
    return fastoml_token_equals(tok, "inf") || fastoml_token_equals(tok, "+inf") || fastoml_token_equals(tok, "-inf") ||
           fastoml_token_equals(tok, "nan") || fastoml_token_equals(tok, "+nan") || fastoml_token_equals(tok, "-nan");
}

static fastoml_status fastoml_parse_float_token(fastoml_reader* r, fastoml_slice tok, double* out) {
    size_t i = 0u;
    int sign = 1;
    int seen_dot = 0;
    int seen_exp = 0;
    int in_frac = 0;
    int in_exp = 0;
    int exp_sign = 1;
    int exp_value = 0;
    size_t int_digits = 0u;
    size_t frac_digits = 0u;
    size_t exp_digits = 0u;
    char first_int_digit = '\0';
    int prev_is_digit = 0;
    int sig_started = 0;
    uint64_t mantissa = 0u;
    int mantissa_digits = 0;
    int dropped_digits = 0;
    int round_digit = -1;
    int round_sticky = 0;

    if (fastoml_token_equals(tok, "inf") || fastoml_token_equals(tok, "+inf")) {
        *out = INFINITY;
        return FASTOML_OK;
    }
    if (fastoml_token_equals(tok, "-inf")) {
        *out = -INFINITY;
        return FASTOML_OK;
    }
    if (fastoml_token_equals(tok, "nan") || fastoml_token_equals(tok, "+nan")) {
        *out = NAN;
        return FASTOML_OK;
    }
    if (fastoml_token_equals(tok, "-nan")) {
        *out = -NAN;
        return FASTOML_OK;
    }

    if (tok.len == 0u) {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    if (tok.ptr[i] == '+' || tok.ptr[i] == '-') {
        sign = tok.ptr[i] == '-' ? -1 : 1;
        i += 1u;
        if (i >= tok.len) {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
    }

    while (i < tok.len) {
        const unsigned char c = (unsigned char)tok.ptr[i];
        if (c == '_') {
            if (!prev_is_digit || i + 1u >= tok.len || !fastoml_char_is_digit((unsigned char)tok.ptr[i + 1u])) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            prev_is_digit = 0;
            i += 1u;
            continue;
        }

        if (!in_exp && c == '.') {
            if (seen_dot) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            seen_dot = 1;
            in_frac = 1;
            prev_is_digit = 0;
            i += 1u;
            continue;
        }

        if (c == 'e' || c == 'E') {
            if (seen_exp) {
                return fastoml_fail(r, FASTOML_ERR_SYNTAX);
            }
            seen_exp = 1;
            in_exp = 1;
            prev_is_digit = 0;
            i += 1u;
            if (i < tok.len && (tok.ptr[i] == '+' || tok.ptr[i] == '-')) {
                exp_sign = tok.ptr[i] == '-' ? -1 : 1;
                i += 1u;
            }
            continue;
        }

        if (!fastoml_char_is_digit(c)) {
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        prev_is_digit = 1;

        if (in_exp) {
            if (exp_value < 100000) {
                exp_value = exp_value * 10 + (int)(c - '0');
            }
            exp_digits += 1u;
            i += 1u;
            continue;
        }

        if (!in_frac) {
            if (int_digits == 0u) {
                first_int_digit = (char)c;
            }
            int_digits += 1u;
        } else {
            frac_digits += 1u;
        }

        {
            const uint32_t d = (uint32_t)(c - '0');
            if (!sig_started) {
                if (d == 0u) {
                    i += 1u;
                    continue;
                }
                sig_started = 1;
            }
            if (mantissa_digits < 19) {
                mantissa = mantissa * 10u + (uint64_t)d;
                mantissa_digits += 1;
            } else {
                if (round_digit < 0) {
                    round_digit = (int)d;
                } else if (d != 0u) {
                    round_sticky = 1;
                }
                dropped_digits += 1;
            }
        }
        i += 1u;
    }

    if (!seen_dot && !seen_exp) {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    if (seen_dot && (int_digits == 0u || frac_digits == 0u)) {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    if (!seen_dot && int_digits == 0u) {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    if (seen_exp && exp_digits == 0u) {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    if (int_digits > 1u && first_int_digit == '0') {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }

    if (!sig_started) {
        *out = sign < 0 ? -0.0 : 0.0;
        return FASTOML_OK;
    }

    if (round_digit > 5 || (round_digit == 5 && (round_sticky || (mantissa & 1u) != 0u))) {
        mantissa += 1u;
        if (mantissa == 10000000000000000000ull) {
            mantissa = 1000000000000000000ull;
            dropped_digits += 1;
        }
    }

    {
        const int exp10 = exp_sign * exp_value - (int)frac_digits + dropped_digits;
        const fastoml_status ps = fastoml_parse_float_decimal(sign, mantissa, exp10, out);
        if (ps != FASTOML_OK) {
            return fastoml_fail(r, ps == FASTOML_ERR_SYNTAX ? FASTOML_ERR_SYNTAX : FASTOML_ERR_OVERFLOW);
        }
    }
    return FASTOML_OK;
}

static fastoml_node* fastoml_validate_marker_node(fastoml_node_kind kind) {
    static fastoml_node marker_table = {FASTOML_NODE_TABLE, 0, {0}};
    static fastoml_node marker_array = {FASTOML_NODE_ARRAY, 0, {0}};
    static fastoml_node marker_string = {FASTOML_NODE_STRING, 0, {0}};
    static fastoml_node marker_int = {FASTOML_NODE_INT, 0, {0}};
    static fastoml_node marker_float = {FASTOML_NODE_FLOAT, 0, {0}};
    static fastoml_node marker_bool = {FASTOML_NODE_BOOL, 0, {0}};
    static fastoml_node marker_datetime = {FASTOML_NODE_DATETIME, 0, {0}};
    static fastoml_node marker_date = {FASTOML_NODE_DATE, 0, {0}};
    static fastoml_node marker_time = {FASTOML_NODE_TIME, 0, {0}};

    switch (kind) {
    case FASTOML_NODE_TABLE:
        return &marker_table;
    case FASTOML_NODE_ARRAY:
        return &marker_array;
    case FASTOML_NODE_STRING:
        return &marker_string;
    case FASTOML_NODE_INT:
        return &marker_int;
    case FASTOML_NODE_FLOAT:
        return &marker_float;
    case FASTOML_NODE_BOOL:
        return &marker_bool;
    case FASTOML_NODE_DATETIME:
        return &marker_datetime;
    case FASTOML_NODE_DATE:
        return &marker_date;
    case FASTOML_NODE_TIME:
        return &marker_time;
    default:
        return &marker_string;
    }
}

static fastoml_status fastoml_parse_value(fastoml_reader* r, fastoml_node** out_node);
static fastoml_status fastoml_parse_array(fastoml_reader* r, fastoml_node** out_node) {
    fastoml_node* arr = NULL;
    fastoml_status s;
    if (fastoml_reader_peek(r) != '[') {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    fastoml_reader_advance_byte(r);
    if (!r->validate_only) {
        arr = fastoml_new_node(r, FASTOML_NODE_ARRAY);
        if (!arr) {
            return fastoml_fail(r, FASTOML_ERR_OOM);
        }
    }

    s = fastoml_skip_ws_comment_nl(r);
    if (s != FASTOML_OK)
        return s;
    if (fastoml_reader_peek(r) == ']') {
        fastoml_reader_advance_byte(r);
        *out_node = r->validate_only ? fastoml_validate_marker_node(FASTOML_NODE_ARRAY) : arr;
        return FASTOML_OK;
    }

    for (;;) {
        fastoml_node* item = NULL;
        s = fastoml_parse_value(r, &item);
        if (s != FASTOML_OK)
            return s;
        if (!r->validate_only) {
            s = fastoml_array_push(r, arr, item);
            if (s != FASTOML_OK)
                return s;
        }

        s = fastoml_skip_ws_comment_nl(r);
        if (s != FASTOML_OK)
            return s;
        if (fastoml_reader_peek(r) == ',') {
            fastoml_reader_advance_byte(r);
            s = fastoml_skip_ws_comment_nl(r);
            if (s != FASTOML_OK)
                return s;
            if (fastoml_reader_peek(r) == ']') {
                fastoml_reader_advance_byte(r);
                *out_node = r->validate_only ? fastoml_validate_marker_node(FASTOML_NODE_ARRAY) : arr;
                return FASTOML_OK;
            }
            continue;
        }
        if (fastoml_reader_peek(r) == ']') {
            fastoml_reader_advance_byte(r);
            *out_node = r->validate_only ? fastoml_validate_marker_node(FASTOML_NODE_ARRAY) : arr;
            return FASTOML_OK;
        }
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
}

static void fastoml_seal_inline_tree(fastoml_node* n) {
    uint32_t i;
    if (!n || n->kind != FASTOML_NODE_TABLE) {
        return;
    }
    n->flags &= ~FASTOML_TABLE_INLINE_BUILDING;
    n->flags |= FASTOML_TABLE_INLINE_SEALED;
    for (i = 0; i < n->as.table.len; ++i) {
        fastoml_node* child = n->as.table.items[i].value;
        if (child && child->kind == FASTOML_NODE_TABLE) {
            fastoml_seal_inline_tree(child);
        }
    }
}

enum {
    FASTOML_VALIDATE_INLINE_VALUE = 1u,
    FASTOML_VALIDATE_INLINE_TABLE_OPEN = 2u,
    FASTOML_VALIDATE_INLINE_TABLE_SEALED = 3u
};

typedef struct fastoml_validate_inline_entry {
    fastoml_slice key;
    uint64_t hash;
    uint32_t child_table;
    uint8_t state;
} fastoml_validate_inline_entry;

typedef struct fastoml_validate_inline_table {
    fastoml_validate_inline_entry* items;
    uint32_t len;
    uint32_t cap;
} fastoml_validate_inline_table;

typedef struct fastoml_validate_inline_ctx {
    fastoml_validate_inline_table* tables;
    uint32_t len;
    uint32_t cap;
} fastoml_validate_inline_ctx;

static int fastoml_validate_inline_table_reserve(fastoml_reader* r, fastoml_validate_inline_table* t, uint32_t new_cap) {
    fastoml_validate_inline_entry* items;
    fastoml_validate_inline_entry* old_items = t->items;
    const size_t old_bytes = sizeof(fastoml_validate_inline_entry) * (size_t)t->cap;
    const size_t new_bytes = sizeof(fastoml_validate_inline_entry) * (size_t)new_cap;
    items = (fastoml_validate_inline_entry*)fastoml_arena_grow_last_or_alloc(
        &r->parser->arena,
        old_items,
        old_bytes,
        new_bytes,
        sizeof(void*));
    if (!items) {
        return 0;
    }
    if (items != old_items && t->len > 0u && old_items) {
        memcpy(items, old_items, sizeof(fastoml_validate_inline_entry) * (size_t)t->len);
    }
    t->items = items;
    t->cap = new_cap;
    return 1;
}

static int fastoml_validate_inline_ctx_reserve_tables(fastoml_reader* r, fastoml_validate_inline_ctx* ctx, uint32_t new_cap) {
    fastoml_validate_inline_table* tables;
    fastoml_validate_inline_table* old_tables = ctx->tables;
    const size_t old_bytes = sizeof(fastoml_validate_inline_table) * (size_t)ctx->cap;
    const size_t new_bytes = sizeof(fastoml_validate_inline_table) * (size_t)new_cap;
    tables = (fastoml_validate_inline_table*)fastoml_arena_grow_last_or_alloc(
        &r->parser->arena,
        old_tables,
        old_bytes,
        new_bytes,
        sizeof(void*));
    if (!tables) {
        return 0;
    }
    if (tables != old_tables && ctx->len > 0u && old_tables) {
        memcpy(tables, old_tables, sizeof(fastoml_validate_inline_table) * (size_t)ctx->len);
    }
    ctx->tables = tables;
    ctx->cap = new_cap;
    return 1;
}

static int fastoml_validate_inline_ctx_add_table(fastoml_reader* r, fastoml_validate_inline_ctx* ctx, uint32_t* out_idx) {
    if (ctx->len == ctx->cap) {
        const uint32_t next_cap = ctx->cap == 0u ? 8u : ctx->cap * 2u;
        if (!fastoml_validate_inline_ctx_reserve_tables(r, ctx, next_cap)) {
            return 0;
        }
    }
    ctx->tables[ctx->len].items = NULL;
    ctx->tables[ctx->len].len = 0u;
    ctx->tables[ctx->len].cap = 0u;
    *out_idx = ctx->len;
    ctx->len += 1u;
    return 1;
}

static fastoml_validate_inline_entry* fastoml_validate_inline_find(fastoml_validate_inline_table* t, fastoml_slice key, uint64_t hash) {
    uint32_t i = 0;
    while (i < t->len) {
        fastoml_validate_inline_entry* e = &t->items[i];
        if (e->hash == hash && fastoml_slice_eq(e->key, key)) {
            return e;
        }
        ++i;
    }
    return NULL;
}

static fastoml_status fastoml_validate_inline_insert_path(
    fastoml_reader* r,
    fastoml_validate_inline_ctx* ctx,
    const fastoml_key_path* path,
    int value_is_inline_table) {
    uint32_t table_idx = 0u;
    uint32_t i = 0u;
    while (i < path->count) {
        fastoml_validate_inline_table* t = &ctx->tables[table_idx];
        const fastoml_slice key = path->parts[i];
        const uint64_t hash = path->hashes[i];
        fastoml_validate_inline_entry* e = fastoml_validate_inline_find(t, key, hash);
        const int is_tail = (i + 1u == path->count);
        if (!is_tail) {
            if (!e) {
                uint32_t child_idx = 0u;
                if (t->len == t->cap) {
                    const uint32_t next_cap = t->cap == 0u ? 8u : t->cap * 2u;
                    if (!fastoml_validate_inline_table_reserve(r, t, next_cap)) {
                        return fastoml_fail(r, FASTOML_ERR_OOM);
                    }
                }
                if (!fastoml_validate_inline_ctx_add_table(r, ctx, &child_idx)) {
                    return fastoml_fail(r, FASTOML_ERR_OOM);
                }
                e = &t->items[t->len++];
                e->key = key;
                e->hash = hash;
                e->child_table = child_idx;
                e->state = FASTOML_VALIDATE_INLINE_TABLE_OPEN;
            } else if (e->state != FASTOML_VALIDATE_INLINE_TABLE_OPEN) {
                return fastoml_fail(r, FASTOML_ERR_TYPE);
            }
            table_idx = e->child_table;
            ++i;
            continue;
        }

        if (e) {
            return fastoml_fail(r, FASTOML_ERR_DUP_KEY);
        }
        if (t->len == t->cap) {
            const uint32_t next_cap = t->cap == 0u ? 8u : t->cap * 2u;
            if (!fastoml_validate_inline_table_reserve(r, t, next_cap)) {
                return fastoml_fail(r, FASTOML_ERR_OOM);
            }
        }
        e = &t->items[t->len++];
        e->key = key;
        e->hash = hash;
        e->child_table = 0u;
        e->state = value_is_inline_table ? FASTOML_VALIDATE_INLINE_TABLE_SEALED : FASTOML_VALIDATE_INLINE_VALUE;
        ++i;
    }
    return FASTOML_OK;
}

static fastoml_status fastoml_parse_inline_table_validate_only(fastoml_reader* r, fastoml_node** out_node) {
    fastoml_validate_inline_ctx ctx;
    uint32_t root_idx = 0u;
    fastoml_status s;
    memset(&ctx, 0, sizeof(ctx));
    if (!fastoml_validate_inline_ctx_add_table(r, &ctx, &root_idx)) {
        return fastoml_fail(r, FASTOML_ERR_OOM);
    }

    s = fastoml_skip_ws_comment_nl(r);
    if (s != FASTOML_OK)
        return s;
    if (fastoml_reader_peek(r) == '}') {
        fastoml_reader_advance_byte(r);
        *out_node = fastoml_validate_marker_node(FASTOML_NODE_TABLE);
        return FASTOML_OK;
    }

    for (;;) {
        fastoml_key_path path;
        fastoml_node* value = NULL;
        int value_is_inline_table;
        fastoml_key_path_init(&path);

        s = fastoml_parse_key_path(r, &path);
        if (s != FASTOML_OK) {
            fastoml_key_path_release(r, &path);
            return s;
        }
        fastoml_skip_space_tab(r);
        if (fastoml_reader_peek(r) != '=') {
            fastoml_key_path_release(r, &path);
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        fastoml_reader_advance_byte(r);
        fastoml_skip_space_tab(r);
        s = fastoml_parse_value(r, &value);
        if (s != FASTOML_OK) {
            fastoml_key_path_release(r, &path);
            return s;
        }
        value_is_inline_table = value && value->kind == FASTOML_NODE_TABLE;
        s = fastoml_validate_inline_insert_path(r, &ctx, &path, value_is_inline_table);
        fastoml_key_path_release(r, &path);
        if (s != FASTOML_OK)
            return s;

        s = fastoml_skip_ws_comment_nl(r);
        if (s != FASTOML_OK)
            return s;
        if (fastoml_reader_peek(r) == ',') {
            fastoml_reader_advance_byte(r);
            s = fastoml_skip_ws_comment_nl(r);
            if (s != FASTOML_OK)
                return s;
            if (fastoml_reader_peek(r) == '}') {
                fastoml_reader_advance_byte(r);
                *out_node = fastoml_validate_marker_node(FASTOML_NODE_TABLE);
                return FASTOML_OK;
            }
            continue;
        }
        if (fastoml_reader_peek(r) == '}') {
            fastoml_reader_advance_byte(r);
            *out_node = fastoml_validate_marker_node(FASTOML_NODE_TABLE);
            return FASTOML_OK;
        }
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
}

static fastoml_status fastoml_parse_inline_table(fastoml_reader* r, fastoml_node** out_node) {
    fastoml_node* tbl;
    fastoml_status s;
    if (fastoml_reader_peek(r) != '{') {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    fastoml_reader_advance_byte(r);
    if (r->validate_only) {
        return fastoml_parse_inline_table_validate_only(r, out_node);
    }
    tbl = fastoml_new_node(r, FASTOML_NODE_TABLE);
    if (!tbl) {
        return fastoml_fail(r, FASTOML_ERR_OOM);
    }
    tbl->flags |= FASTOML_TABLE_INLINE_BUILDING;

    s = fastoml_skip_ws_comment_nl(r);
    if (s != FASTOML_OK)
        return s;
    if (fastoml_reader_peek(r) == '}') {
        fastoml_reader_advance_byte(r);
        fastoml_seal_inline_tree(tbl);
        *out_node = tbl;
        return FASTOML_OK;
    }

    for (;;) {
        fastoml_key_path path;
        fastoml_node* value = NULL;
        fastoml_key_path_init(&path);
        s = fastoml_parse_key_path(r, &path);
        if (s != FASTOML_OK) {
            fastoml_key_path_release(r, &path);
            return s;
        }
        fastoml_skip_space_tab(r);
        if (fastoml_reader_peek(r) != '=') {
            fastoml_key_path_release(r, &path);
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        fastoml_reader_advance_byte(r);
        fastoml_skip_space_tab(r);
        s = fastoml_parse_value(r, &value);
        if (s != FASTOML_OK) {
            fastoml_key_path_release(r, &path);
            return s;
        }
        s = fastoml_insert_path_value(r, tbl, &path, value, 1);
        fastoml_key_path_release(r, &path);
        if (s != FASTOML_OK)
            return s;

        s = fastoml_skip_ws_comment_nl(r);
        if (s != FASTOML_OK)
            return s;
        if (fastoml_reader_peek(r) == ',') {
            fastoml_reader_advance_byte(r);
            s = fastoml_skip_ws_comment_nl(r);
            if (s != FASTOML_OK)
                return s;
            if (fastoml_reader_peek(r) == '}') {
                fastoml_reader_advance_byte(r);
                fastoml_seal_inline_tree(tbl);
                *out_node = tbl;
                return FASTOML_OK;
            }
            continue;
        }
        if (fastoml_reader_peek(r) == '}') {
            fastoml_reader_advance_byte(r);
            fastoml_seal_inline_tree(tbl);
            *out_node = tbl;
            return FASTOML_OK;
        }
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
}

static fastoml_status fastoml_parse_token_value(fastoml_reader* r, fastoml_slice tok, fastoml_node** out_node) {
    fastoml_node* n;
    int tok_is_true;
    int tok_is_false;
    int looks_like_datetime;
    int has_float_marker;
    int is_float_keyword;
    uint32_t i;
    if (FASTOML_UNLIKELY(tok.len == 0)) {
        return fastoml_fail(r, FASTOML_ERR_SYNTAX);
    }
    tok_is_true = fastoml_token_equals(tok, "true");
    tok_is_false = tok_is_true ? 0 : fastoml_token_equals(tok, "false");
    if (tok_is_true || tok_is_false) {
        if (r->validate_only) {
            *out_node = fastoml_validate_marker_node(FASTOML_NODE_BOOL);
            return FASTOML_OK;
        }
        n = fastoml_new_node(r, FASTOML_NODE_BOOL);
        if (FASTOML_UNLIKELY(!n))
            return fastoml_fail(r, FASTOML_ERR_OOM);
        n->as.b = tok_is_true ? 1 : 0;
        *out_node = n;
        return FASTOML_OK;
    }

    looks_like_datetime = (tok.len >= 10u && tok.ptr[4] == '-' && tok.ptr[7] == '-') ||
                          (tok.len >= 5u && tok.ptr[2] == ':');
    has_float_marker = 0;
    i = 0u;
    while (i < tok.len) {
        const char c = tok.ptr[i];
        if (!looks_like_datetime && (c == ':' || c == 'T' || c == 't')) {
            looks_like_datetime = 1;
        }
        if (!has_float_marker && (c == '.' || c == 'e' || c == 'E')) {
            has_float_marker = 1;
        }
        if (looks_like_datetime && has_float_marker) {
            break;
        }
        i += 1u;
    }

    {
        if (looks_like_datetime) {
            fastoml_node_kind dk = FASTOML_NODE_DATETIME;
            if (fastoml_try_parse_datetime(tok, &dk)) {
                if (r->validate_only) {
                    *out_node = fastoml_validate_marker_node(dk);
                    return FASTOML_OK;
                }
                n = fastoml_new_node(r, dk);
                if (FASTOML_UNLIKELY(!n))
                    return fastoml_fail(r, FASTOML_ERR_OOM);
                n->as.datetime.raw = tok;
                *out_node = n;
                return FASTOML_OK;
            }
        }

        is_float_keyword = fastoml_token_is_float_keyword(tok);
        if ((has_float_marker || is_float_keyword) && !fastoml_token_is_nondecimal_int(tok)) {
            double v = 0.0;
            if (fastoml_parse_float_token(r, tok, &v) == FASTOML_OK) {
                if (r->validate_only) {
                    *out_node = fastoml_validate_marker_node(FASTOML_NODE_FLOAT);
                    return FASTOML_OK;
                }
                n = fastoml_new_node(r, FASTOML_NODE_FLOAT);
                if (FASTOML_UNLIKELY(!n))
                    return fastoml_fail(r, FASTOML_ERR_OOM);
                n->as.f64 = v;
                *out_node = n;
                return FASTOML_OK;
            }
            return r->err.code;
        }
    }

    {
        int64_t v = 0;
        if (fastoml_parse_int_token(r, tok, &v) == FASTOML_OK) {
            if (r->validate_only) {
                *out_node = fastoml_validate_marker_node(FASTOML_NODE_INT);
                return FASTOML_OK;
            }
            n = fastoml_new_node(r, FASTOML_NODE_INT);
            if (FASTOML_UNLIKELY(!n))
                return fastoml_fail(r, FASTOML_ERR_OOM);
            n->as.i64 = v;
            *out_node = n;
            return FASTOML_OK;
        }
    }
    return r->err.code;
}

static fastoml_status fastoml_parse_value(fastoml_reader* r, fastoml_node** out_node) {
    const unsigned char c = fastoml_reader_peek(r);
    fastoml_status s;
    if (r->depth >= r->parser->opt.max_depth) {
        return fastoml_fail(r, FASTOML_ERR_DEPTH);
    }
    r->depth += 1;

    if (c == '"') {
        fastoml_slice text;
        fastoml_node* n;
        if (fastoml_reader_peek_n(r, 1) == '"' && fastoml_reader_peek_n(r, 2) == '"') {
            s = fastoml_parse_basic_string(r, 1, r->validate_only ? NULL : &text, 0);
        } else {
            s = fastoml_parse_basic_string(r, 0, r->validate_only ? NULL : &text, 0);
        }
        if (s != FASTOML_OK) {
            r->depth -= 1;
            return s;
        }
        if (r->validate_only) {
            *out_node = fastoml_validate_marker_node(FASTOML_NODE_STRING);
            r->depth -= 1;
            return FASTOML_OK;
        }
        n = fastoml_new_node(r, FASTOML_NODE_STRING);
        if (!n) {
            r->depth -= 1;
            return fastoml_fail(r, FASTOML_ERR_OOM);
        }
        n->as.str.view = text;
        *out_node = n;
        r->depth -= 1;
        return FASTOML_OK;
    }
    if (c == '\'') {
        fastoml_slice text;
        fastoml_node* n;
        if (fastoml_reader_peek_n(r, 1) == '\'' && fastoml_reader_peek_n(r, 2) == '\'') {
            s = fastoml_parse_literal_string(r, 1, r->validate_only ? NULL : &text, 0);
        } else {
            s = fastoml_parse_literal_string(r, 0, r->validate_only ? NULL : &text, 0);
        }
        if (s != FASTOML_OK) {
            r->depth -= 1;
            return s;
        }
        if (r->validate_only) {
            *out_node = fastoml_validate_marker_node(FASTOML_NODE_STRING);
            r->depth -= 1;
            return FASTOML_OK;
        }
        n = fastoml_new_node(r, FASTOML_NODE_STRING);
        if (!n) {
            r->depth -= 1;
            return fastoml_fail(r, FASTOML_ERR_OOM);
        }
        n->as.str.view = text;
        *out_node = n;
        r->depth -= 1;
        return FASTOML_OK;
    }
    if (c == '[') {
        s = fastoml_parse_array(r, out_node);
        r->depth -= 1;
        return s;
    }
    if (c == '{') {
        s = fastoml_parse_inline_table(r, out_node);
        r->depth -= 1;
        return s;
    }
    {
        const size_t start = r->pos;
        const size_t end = fastoml_find_value_delim(r->parser, r->src, r->pos, r->len);
        size_t token_end = end;
        fastoml_slice tok;
        if (end <= start) {
            r->depth -= 1;
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        while (token_end > start &&
               (r->src[token_end - 1] == ' ' || r->src[token_end - 1] == '\t')) {
            token_end -= 1;
        }
        if (token_end <= start) {
            r->depth -= 1;
            return fastoml_fail(r, FASTOML_ERR_SYNTAX);
        }
        fastoml_reader_advance_span_no_nl(r, end - r->pos);
        tok.ptr = r->src + start;
        tok.len = (uint32_t)(token_end - start);
        s = fastoml_parse_token_value(r, tok, out_node);
        r->depth -= 1;
        return s;
    }
}

static fastoml_status fastoml_resolve_table_prefix(fastoml_reader* r, fastoml_node* cur, fastoml_slice key, uint64_t hash, fastoml_node** out_table) {
    fastoml_kv* kv = fastoml_table_find_kv(cur, key, hash);
    if (!kv) {
        fastoml_node* t = fastoml_new_node(r, FASTOML_NODE_TABLE);
        if (!t)
            return fastoml_fail(r, FASTOML_ERR_OOM);
        if (fastoml_table_insert_hashed(r, cur, key, hash, t) != FASTOML_OK)
            return r->err.code;
        *out_table = t;
        return FASTOML_OK;
    }
    if (kv->value->kind == FASTOML_NODE_TABLE) {
        if ((kv->value->flags & FASTOML_TABLE_INLINE_SEALED) != 0) {
            return fastoml_fail(r, FASTOML_ERR_TYPE);
        }
        *out_table = kv->value;
        return FASTOML_OK;
    }
    if (kv->value->kind == FASTOML_NODE_ARRAY && (kv->value->flags & FASTOML_ARRAY_OF_TABLES)) {
        if (kv->value->as.array.len == 0) {
            return fastoml_fail(r, FASTOML_ERR_TYPE);
        }
        *out_table = kv->value->as.array.items[kv->value->as.array.len - 1];
        return FASTOML_OK;
    }
    return fastoml_fail(r, FASTOML_ERR_TYPE);
}

static fastoml_status fastoml_parse_table_header(fastoml_reader* r, int array_table) {
    fastoml_key_path path;
    fastoml_node* cur = r->root;
    uint32_t i = 0;
    fastoml_status s;
    fastoml_key_path_init(&path);

    if (array_table) {
        if (!(fastoml_reader_peek(r) == '[' && fastoml_reader_peek_n(r, 1) == '[')) {
            s = fastoml_fail(r, FASTOML_ERR_SYNTAX);
            goto cleanup;
        }
        fastoml_reader_advance_byte(r);
        fastoml_reader_advance_byte(r);
    } else {
        if (fastoml_reader_peek(r) != '[') {
            s = fastoml_fail(r, FASTOML_ERR_SYNTAX);
            goto cleanup;
        }
        fastoml_reader_advance_byte(r);
    }

    fastoml_skip_space_tab(r);
    s = fastoml_parse_key_path(r, &path);
    if (s != FASTOML_OK)
        goto cleanup;
    fastoml_skip_space_tab(r);

    if (array_table) {
        if (!(fastoml_reader_peek(r) == ']' && fastoml_reader_peek_n(r, 1) == ']')) {
            s = fastoml_fail(r, FASTOML_ERR_SYNTAX);
            goto cleanup;
        }
        fastoml_reader_advance_byte(r);
        fastoml_reader_advance_byte(r);
    } else {
        if (fastoml_reader_peek(r) != ']') {
            s = fastoml_fail(r, FASTOML_ERR_SYNTAX);
            goto cleanup;
        }
        fastoml_reader_advance_byte(r);
    }

    if (path.count == 0) {
        s = fastoml_fail(r, FASTOML_ERR_SYNTAX);
        goto cleanup;
    }

    for (i = 0; i + 1 < path.count; ++i) {
        s = fastoml_resolve_table_prefix(r, cur, path.parts[i], path.hashes[i], &cur);
        if (s != FASTOML_OK)
            goto cleanup;
    }

    {
        fastoml_slice tail = path.parts[path.count - 1];
        const uint64_t h = path.hashes[path.count - 1];
        fastoml_kv* kv = fastoml_table_find_kv(cur, tail, h);

        if (array_table) {
            fastoml_node* arr = NULL;
            fastoml_node* new_table = NULL;
            if (!kv) {
                arr = fastoml_new_node(r, FASTOML_NODE_ARRAY);
                if (!arr) {
                    s = fastoml_fail(r, FASTOML_ERR_OOM);
                    goto cleanup;
                }
                arr->flags |= FASTOML_ARRAY_OF_TABLES;
                if (fastoml_table_insert_hashed(r, cur, tail, h, arr) != FASTOML_OK) {
                    s = r->err.code;
                    goto cleanup;
                }
            } else {
                if (!kv->value || kv->value->kind != FASTOML_NODE_ARRAY || (kv->value->flags & FASTOML_ARRAY_OF_TABLES) == 0) {
                    s = fastoml_fail(r, FASTOML_ERR_TYPE);
                    goto cleanup;
                }
                arr = kv->value;
            }
            new_table = fastoml_new_node(r, FASTOML_NODE_TABLE);
            if (!new_table) {
                s = fastoml_fail(r, FASTOML_ERR_OOM);
                goto cleanup;
            }
            new_table->flags |= FASTOML_TABLE_EXPLICIT;
            s = fastoml_array_push(r, arr, new_table);
            if (s != FASTOML_OK)
                goto cleanup;
            r->current_table = new_table;
        } else {
            if (!kv) {
                fastoml_node* t = fastoml_new_node(r, FASTOML_NODE_TABLE);
                if (!t) {
                    s = fastoml_fail(r, FASTOML_ERR_OOM);
                    goto cleanup;
                }
                t->flags |= FASTOML_TABLE_EXPLICIT;
                if (fastoml_table_insert_hashed(r, cur, tail, h, t) != FASTOML_OK) {
                    s = r->err.code;
                    goto cleanup;
                }
                r->current_table = t;
            } else {
                fastoml_node* t = kv->value;
                if (!t || t->kind != FASTOML_NODE_TABLE) {
                    s = fastoml_fail(r, FASTOML_ERR_TYPE);
                    goto cleanup;
                }
                if ((t->flags & FASTOML_TABLE_INLINE_SEALED) != 0) {
                    s = fastoml_fail(r, FASTOML_ERR_TYPE);
                    goto cleanup;
                }
                if ((t->flags & FASTOML_TABLE_EXPLICIT) != 0) {
                    s = fastoml_fail(r, FASTOML_ERR_DUP_KEY);
                    goto cleanup;
                }
                if ((t->flags & FASTOML_TABLE_DOTTED_DEFINED) != 0) {
                    s = fastoml_fail(r, FASTOML_ERR_DUP_KEY);
                    goto cleanup;
                }
                t->flags |= FASTOML_TABLE_EXPLICIT;
                r->current_table = t;
            }
        }
    }
    s = FASTOML_OK;
cleanup:
    fastoml_key_path_release(r, &path);
    return s;
}

static fastoml_status fastoml_parse_key_value_line(fastoml_reader* r) {
    fastoml_key_path path;
    fastoml_node* value = NULL;
    fastoml_status s;
    fastoml_key_path_init(&path);

    s = fastoml_parse_key_path(r, &path);
    if (s != FASTOML_OK)
        goto cleanup;
    fastoml_skip_space_tab(r);
    if (fastoml_reader_peek(r) != '=') {
        s = fastoml_fail(r, FASTOML_ERR_SYNTAX);
        goto cleanup;
    }
    fastoml_reader_advance_byte(r);
    fastoml_skip_space_tab(r);
    s = fastoml_parse_value(r, &value);
    if (s != FASTOML_OK)
        goto cleanup;
    s = fastoml_insert_path_value(r, r->current_table, &path, value, 0);
    if (s != FASTOML_OK)
        goto cleanup;
    s = fastoml_expect_line_end(r);
cleanup:
    fastoml_key_path_release(r, &path);
    return s;
}

static fastoml_status fastoml_parse_internal(fastoml_parser* p, const char* src, size_t len, int validate_only, fastoml_error* out_err) {
    fastoml_reader r;

    if (!p || !src) {
        if (out_err) {
            out_err->code = FASTOML_ERR_SYNTAX;
            out_err->byte_offset = 0;
            out_err->line = 1;
            out_err->column = 1;
        }
        return FASTOML_ERR_SYNTAX;
    }

    fastoml_parser_reset(p);

    if (len >= 3 &&
        (unsigned char)src[0] == 0xEF &&
        (unsigned char)src[1] == 0xBB &&
        (unsigned char)src[2] == 0xBF) {
        src += 3;
        len -= 3;
    }

    if ((p->opt.flags & FASTOML_PARSE_TRUST_UTF8) == 0u &&
        !fastoml_utf8_validate(p, (const unsigned char*)src, len)) {
        if (out_err) {
            out_err->code = FASTOML_ERR_UTF8;
            out_err->byte_offset = 0;
            out_err->line = 1;
            out_err->column = 1;
        }
        return FASTOML_ERR_UTF8;
    }

    memset(&r, 0, sizeof(r));
    r.parser = p;
    r.src = src;
    r.len = len;
    r.pos = 0;
    r.line = 1;
    r.col = 1;
    r.depth = 0;
    r.err.code = FASTOML_OK;
    r.validate_only = validate_only ? 1 : 0;

    r.root = fastoml_new_node(&r, FASTOML_NODE_TABLE);
    if (!r.root) {
        if (out_err) {
            out_err->code = FASTOML_ERR_OOM;
            out_err->byte_offset = 0;
            out_err->line = 1;
            out_err->column = 1;
        }
        return FASTOML_ERR_OOM;
    }
    r.root->flags |= FASTOML_TABLE_EXPLICIT;
    r.current_table = r.root;

    while (!fastoml_reader_eof(&r)) {
        unsigned char c;
        fastoml_skip_space_tab(&r);
        if (fastoml_reader_eof(&r))
            break;

        c = (unsigned char)r.src[r.pos];
        if (c == '\n' || c == '\r') {
            fastoml_status s = fastoml_reader_advance_newline(&r);
            if (s != FASTOML_OK)
                goto fail;
            continue;
        }
        if (c == '#') {
            fastoml_status s = fastoml_skip_comment(&r);
            if (s != FASTOML_OK)
                goto fail;
            if (!fastoml_reader_eof(&r)) {
                c = (unsigned char)r.src[r.pos];
                if (c == '\n' || c == '\r') {
                    s = fastoml_reader_advance_newline(&r);
                    if (s != FASTOML_OK)
                        goto fail;
                }
            }
            continue;
        }
        if (c == '[') {
            fastoml_status s = fastoml_parse_table_header(&r, (r.pos + 1u < r.len && r.src[r.pos + 1u] == '['));
            if (s != FASTOML_OK)
                goto fail;
            s = fastoml_expect_line_end(&r);
            if (s != FASTOML_OK)
                goto fail;
            continue;
        } else {
            fastoml_status s = fastoml_parse_key_value_line(&r);
            if (s != FASTOML_OK)
                goto fail;
            continue;
        }
    }

    if (!validate_only) {
        p->doc.root = r.root;
        p->doc.input = src;
        p->doc.input_len = len;
    }

    if (out_err) {
        out_err->code = FASTOML_OK;
        out_err->byte_offset = 0;
        out_err->line = 1;
        out_err->column = 1;
    }
    return FASTOML_OK;

fail:
    if (out_err) {
        *out_err = r.err;
    }
    return r.err.code;
}
fastoml_parser* fastoml_parser_create(const fastoml_options* opt) {
    fastoml_options options;
    fastoml_parser* p;
    fastoml_allocator alloc;

    fastoml_options_default(&options);
    if (opt) {
        options = *opt;
        if (!options.alloc.malloc_fn || !options.alloc.realloc_fn || !options.alloc.free_fn) {
            options.alloc = fastoml_make_default_allocator();
        }
        if (options.max_depth == 0) {
            options.max_depth = 256;
        }
    }

    alloc = options.alloc;
    p = (fastoml_parser*)alloc.malloc_fn(alloc.ctx, sizeof(fastoml_parser));
    if (!p) {
        return NULL;
    }
    memset(p, 0, sizeof(*p));
    p->opt = options;
    p->simd_supported = fastoml_detect_simd();
    if (!fastoml_arena_init(&p->arena, p->opt.alloc, 64 * 1024)) {
        p->opt.alloc.free_fn(p->opt.alloc.ctx, p);
        return NULL;
    }
    return p;
}

void fastoml_parser_destroy(fastoml_parser* p) {
    if (!p) {
        return;
    }
    fastoml_arena_destroy(&p->arena);
    p->opt.alloc.free_fn(p->opt.alloc.ctx, p);
}

void fastoml_parser_reset(fastoml_parser* p) {
    if (!p) {
        return;
    }
    fastoml_arena_reset(&p->arena);
    memset(&p->doc, 0, sizeof(p->doc));
}

fastoml_status fastoml_parse(fastoml_parser* p, const char* src, size_t len, const fastoml_document** out_doc, fastoml_error* out_err) {
    const int validate_only = (p->opt.flags & FASTOML_PARSE_VALIDATE_ONLY) != 0;
    const fastoml_status s = fastoml_parse_internal(p, src, len, validate_only, out_err);
    if (out_doc) {
        *out_doc = (s == FASTOML_OK && !validate_only) ? &p->doc : NULL;
    }
    return s;
}

fastoml_status fastoml_validate(fastoml_parser* p, const char* src, size_t len, fastoml_error* out_err) {
    return fastoml_parse_internal(p, src, len, 1, out_err);
}

const fastoml_node* fastoml_doc_root(const fastoml_document* d) {
    if (!d)
        return NULL;
    return d->root;
}

fastoml_node_kind fastoml_node_kindof(const fastoml_node* n) {
    if (!n)
        return 0;
    return n->kind;
}

uint32_t fastoml_table_size(const fastoml_node* table) {
    if (!table || table->kind != FASTOML_NODE_TABLE)
        return 0;
    return table->as.table.len;
}

fastoml_slice fastoml_table_key_at(const fastoml_node* table, uint32_t idx) {
    fastoml_slice s;
    s.ptr = NULL;
    s.len = 0;
    if (!table || table->kind != FASTOML_NODE_TABLE)
        return s;
    if (idx >= table->as.table.len)
        return s;
    return table->as.table.items[idx].key;
}

const fastoml_node* fastoml_table_value_at(const fastoml_node* table, uint32_t idx) {
    if (!table || table->kind != FASTOML_NODE_TABLE)
        return NULL;
    if (idx >= table->as.table.len)
        return NULL;
    return table->as.table.items[idx].value;
}

const fastoml_node* fastoml_table_get(const fastoml_node* table, fastoml_slice key) {
    fastoml_kv* kv;
    if (!table || table->kind != FASTOML_NODE_TABLE)
        return NULL;
    kv = fastoml_table_find_kv(table, key, fastoml_hash_slice(key));
    return kv ? kv->value : NULL;
}

const fastoml_node* fastoml_table_get_cstr(const fastoml_node* table, const char* key) {
    fastoml_slice s;
    s.ptr = key;
    s.len = (uint32_t)fastoml_cstr_len(key);
    return fastoml_table_get(table, s);
}

uint32_t fastoml_array_size(const fastoml_node* array) {
    if (!array || array->kind != FASTOML_NODE_ARRAY)
        return 0;
    return array->as.array.len;
}

const fastoml_node* fastoml_array_at(const fastoml_node* array, uint32_t idx) {
    if (!array || array->kind != FASTOML_NODE_ARRAY)
        return NULL;
    if (idx >= array->as.array.len)
        return NULL;
    return array->as.array.items[idx];
}

fastoml_status fastoml_node_as_bool(const fastoml_node* n, int* out_value) {
    if (!n || n->kind != FASTOML_NODE_BOOL)
        return FASTOML_ERR_TYPE;
    if (out_value)
        *out_value = n->as.b;
    return FASTOML_OK;
}

fastoml_status fastoml_node_as_int(const fastoml_node* n, int64_t* out_value) {
    if (!n || n->kind != FASTOML_NODE_INT)
        return FASTOML_ERR_TYPE;
    if (out_value)
        *out_value = n->as.i64;
    return FASTOML_OK;
}

fastoml_status fastoml_node_as_float(const fastoml_node* n, double* out_value) {
    if (!n || n->kind != FASTOML_NODE_FLOAT)
        return FASTOML_ERR_TYPE;
    if (out_value)
        *out_value = n->as.f64;
    return FASTOML_OK;
}

fastoml_status fastoml_node_as_slice(const fastoml_node* n, fastoml_slice* out_value) {
    if (!n)
        return FASTOML_ERR_TYPE;
    if (n->kind == FASTOML_NODE_STRING) {
        if (out_value)
            *out_value = n->as.str.view;
        return FASTOML_OK;
    }
    if (n->kind == FASTOML_NODE_DATETIME || n->kind == FASTOML_NODE_DATE || n->kind == FASTOML_NODE_TIME) {
        if (out_value)
            *out_value = n->as.datetime.raw;
        return FASTOML_OK;
    }
    return FASTOML_ERR_TYPE;
}

static fastoml_value* fastoml_builder_new_value(fastoml_builder* b, fastoml_node_kind kind) {
    fastoml_value* v;
    if (!b) {
        return NULL;
    }
    v = (fastoml_value*)fastoml_arena_alloc(&b->arena, sizeof(fastoml_value), sizeof(void*));
    if (!v) {
        return NULL;
    }
    v->kind = kind;
    v->flags = 0u;
    v->owner = b;
    v->epoch = b->epoch;
    switch (kind) {
    case FASTOML_NODE_TABLE:
        v->as.table.items = NULL;
        v->as.table.len = 0u;
        v->as.table.cap = 0u;
        break;
    case FASTOML_NODE_ARRAY:
        v->as.array.items = NULL;
        v->as.array.len = 0u;
        v->as.array.cap = 0u;
        break;
    case FASTOML_NODE_STRING:
    case FASTOML_NODE_DATETIME:
    case FASTOML_NODE_DATE:
    case FASTOML_NODE_TIME:
        v->as.datetime.raw.ptr = NULL;
        v->as.datetime.raw.len = 0u;
        break;
    case FASTOML_NODE_INT:
        v->as.i64 = 0;
        break;
    case FASTOML_NODE_FLOAT:
        v->as.f64 = 0.0;
        break;
    case FASTOML_NODE_BOOL:
        v->as.b = 0;
        break;
    default:
        memset(v, 0, sizeof(*v));
        v->kind = kind;
        v->owner = b;
        break;
    }
    return v;
}

static int fastoml_builder_slice_utf8_ok(fastoml_slice s) {
    if (!s.ptr && s.len > 0u) {
        return 0;
    }
    if (s.len == 0u) {
        return 1;
    }
    return fastoml_utf8_validate(NULL, (const unsigned char*)(const void*)s.ptr, s.len) ? 1 : 0;
}

static fastoml_status fastoml_builder_copy_slice(fastoml_builder* b, fastoml_slice in, fastoml_slice* out) {
    char* dst;
    if (!b || !out) {
        return FASTOML_ERR_TYPE;
    }
    if (!in.ptr && in.len > 0u) {
        return FASTOML_ERR_TYPE;
    }
    dst = (char*)fastoml_arena_alloc(&b->arena, (size_t)in.len + 1u, sizeof(char));
    if (!dst) {
        return FASTOML_ERR_OOM;
    }
    if (in.len > 0u) {
        memcpy(dst, in.ptr, in.len);
    }
    dst[in.len] = '\0';
    out->ptr = dst;
    out->len = in.len;
    return FASTOML_OK;
}

static int fastoml_builder_table_reserve(fastoml_builder* b, fastoml_value* table, uint32_t new_cap) {
    fastoml_builder_kv* items;
    fastoml_builder_kv* old_items;
    size_t old_bytes;
    size_t new_bytes;
    if (!b || !table || table->kind != FASTOML_NODE_TABLE) {
        return 0;
    }
    old_bytes = sizeof(fastoml_builder_kv) * (size_t)table->as.table.cap;
    new_bytes = sizeof(fastoml_builder_kv) * (size_t)new_cap;
    old_items = table->as.table.items;
    items = (fastoml_builder_kv*)fastoml_arena_grow_last_or_alloc(
        &b->arena,
        old_items,
        old_bytes,
        new_bytes,
        sizeof(void*));
    if (!items) {
        return 0;
    }
    if (items != old_items && old_items && table->as.table.len > 0u) {
        memcpy(items, old_items, sizeof(fastoml_builder_kv) * (size_t)table->as.table.len);
    }
    table->as.table.items = items;
    table->as.table.cap = new_cap;
    return 1;
}

static int fastoml_builder_array_reserve(fastoml_builder* b, fastoml_value* array, uint32_t new_cap) {
    fastoml_value** items;
    fastoml_value** old_items;
    size_t old_bytes;
    size_t new_bytes;
    if (!b || !array || array->kind != FASTOML_NODE_ARRAY) {
        return 0;
    }
    old_bytes = sizeof(fastoml_value*) * (size_t)array->as.array.cap;
    new_bytes = sizeof(fastoml_value*) * (size_t)new_cap;
    old_items = array->as.array.items;
    items = (fastoml_value**)fastoml_arena_grow_last_or_alloc(
        &b->arena,
        old_items,
        old_bytes,
        new_bytes,
        sizeof(void*));
    if (!items) {
        return 0;
    }
    if (items != old_items && old_items && array->as.array.len > 0u) {
        memcpy(items, old_items, sizeof(fastoml_value*) * (size_t)array->as.array.len);
    }
    array->as.array.items = items;
    array->as.array.cap = new_cap;
    return 1;
}

static fastoml_builder_kv* fastoml_builder_table_find_kv(const fastoml_value* table, fastoml_slice key, uint64_t hash) {
    uint32_t i;
    if (!table || table->kind != FASTOML_NODE_TABLE) {
        return NULL;
    }
    i = 0u;
    while (i < table->as.table.len) {
        fastoml_builder_kv* kv = &table->as.table.items[i];
        if (kv->hash == hash && fastoml_slice_eq(kv->key, key)) {
            return kv;
        }
        ++i;
    }
    return NULL;
}

void fastoml_builder_options_default(fastoml_builder_options* out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->alloc = fastoml_make_default_allocator();
    out->max_depth = 256u;
}

fastoml_builder* fastoml_builder_create(const fastoml_builder_options* opt) {
    fastoml_builder_options options;
    fastoml_builder* b;
    fastoml_allocator alloc;

    fastoml_builder_options_default(&options);
    if (opt) {
        options = *opt;
        if (!options.alloc.malloc_fn || !options.alloc.realloc_fn || !options.alloc.free_fn) {
            options.alloc = fastoml_make_default_allocator();
        }
        if (options.max_depth == 0u) {
            options.max_depth = 256u;
        }
    }

    alloc = options.alloc;
    b = (fastoml_builder*)alloc.malloc_fn(alloc.ctx, sizeof(fastoml_builder));
    if (!b) {
        return NULL;
    }
    memset(b, 0, sizeof(*b));
    b->opt = options;
    b->epoch = 1u;
    if (!fastoml_arena_init(&b->arena, b->opt.alloc, 64 * 1024)) {
        b->opt.alloc.free_fn(b->opt.alloc.ctx, b);
        return NULL;
    }
    b->root = fastoml_builder_new_value(b, FASTOML_NODE_TABLE);
    if (!b->root) {
        fastoml_arena_destroy(&b->arena);
        b->opt.alloc.free_fn(b->opt.alloc.ctx, b);
        return NULL;
    }
    return b;
}

void fastoml_builder_destroy(fastoml_builder* b) {
    if (!b) {
        return;
    }
    fastoml_arena_destroy(&b->arena);
    b->opt.alloc.free_fn(b->opt.alloc.ctx, b);
}

void fastoml_builder_reset(fastoml_builder* b) {
    if (!b) {
        return;
    }
    b->epoch += 1u;
    if (b->epoch == 0u) {
        b->epoch = 1u;
    }
    fastoml_arena_reset(&b->arena);
    b->root = fastoml_builder_new_value(b, FASTOML_NODE_TABLE);
}

fastoml_value* fastoml_builder_root(fastoml_builder* b) {
    if (!b) {
        return NULL;
    }
    return b->root;
}

fastoml_value* fastoml_builder_new_table(fastoml_builder* b) {
    return fastoml_builder_new_value(b, FASTOML_NODE_TABLE);
}

fastoml_value* fastoml_builder_new_array(fastoml_builder* b) {
    return fastoml_builder_new_value(b, FASTOML_NODE_ARRAY);
}

static int fastoml_builder_validate_date_raw(fastoml_slice raw) {
    if (!raw.ptr || raw.len == 0u) {
        return 0;
    }
    return fastoml_try_parse_local_date(raw);
}

static int fastoml_builder_validate_time_raw(fastoml_slice raw) {
    if (!raw.ptr || raw.len == 0u) {
        return 0;
    }
    return fastoml_try_parse_local_time(raw);
}

static int fastoml_builder_validate_datetime_raw(fastoml_slice raw) {
    fastoml_node_kind kind = 0;
    if (!raw.ptr || raw.len == 0u) {
        return 0;
    }
    if (!fastoml_try_parse_datetime(raw, &kind)) {
        return 0;
    }
    return kind == FASTOML_NODE_DATETIME;
}

fastoml_value* fastoml_builder_new_string(fastoml_builder* b, fastoml_slice v) {
    fastoml_value* out;
    if (!b || !fastoml_builder_slice_utf8_ok(v)) {
        return NULL;
    }
    out = fastoml_builder_new_value(b, FASTOML_NODE_STRING);
    if (!out) {
        return NULL;
    }
    if (fastoml_builder_copy_slice(b, v, &out->as.str.view) != FASTOML_OK) {
        return NULL;
    }
    return out;
}

fastoml_value* fastoml_builder_new_int(fastoml_builder* b, int64_t v) {
    fastoml_value* out = fastoml_builder_new_value(b, FASTOML_NODE_INT);
    if (!out) {
        return NULL;
    }
    out->as.i64 = v;
    return out;
}

fastoml_value* fastoml_builder_new_float(fastoml_builder* b, double v) {
    fastoml_value* out;
    if (!b) {
        return NULL;
    }
    out = fastoml_builder_new_value(b, FASTOML_NODE_FLOAT);
    if (!out) {
        return NULL;
    }
    out->as.f64 = v;
    return out;
}

fastoml_value* fastoml_builder_new_bool(fastoml_builder* b, int v) {
    fastoml_value* out = fastoml_builder_new_value(b, FASTOML_NODE_BOOL);
    if (!out) {
        return NULL;
    }
    out->as.b = v ? 1 : 0;
    return out;
}

fastoml_value* fastoml_builder_new_datetime_raw(fastoml_builder* b, fastoml_slice raw) {
    fastoml_value* out;
    if (!b || !fastoml_builder_slice_utf8_ok(raw) || !fastoml_builder_validate_datetime_raw(raw)) {
        return NULL;
    }
    out = fastoml_builder_new_value(b, FASTOML_NODE_DATETIME);
    if (!out) {
        return NULL;
    }
    if (fastoml_builder_copy_slice(b, raw, &out->as.datetime.raw) != FASTOML_OK) {
        return NULL;
    }
    return out;
}

fastoml_value* fastoml_builder_new_date_raw(fastoml_builder* b, fastoml_slice raw) {
    fastoml_value* out;
    if (!b || !fastoml_builder_slice_utf8_ok(raw) || !fastoml_builder_validate_date_raw(raw)) {
        return NULL;
    }
    out = fastoml_builder_new_value(b, FASTOML_NODE_DATE);
    if (!out) {
        return NULL;
    }
    if (fastoml_builder_copy_slice(b, raw, &out->as.datetime.raw) != FASTOML_OK) {
        return NULL;
    }
    return out;
}

fastoml_value* fastoml_builder_new_time_raw(fastoml_builder* b, fastoml_slice raw) {
    fastoml_value* out;
    if (!b || !fastoml_builder_slice_utf8_ok(raw) || !fastoml_builder_validate_time_raw(raw)) {
        return NULL;
    }
    out = fastoml_builder_new_value(b, FASTOML_NODE_TIME);
    if (!out) {
        return NULL;
    }
    if (fastoml_builder_copy_slice(b, raw, &out->as.datetime.raw) != FASTOML_OK) {
        return NULL;
    }
    return out;
}

fastoml_status fastoml_builder_table_set(fastoml_value* table, fastoml_slice key, fastoml_value* value) {
    uint64_t hash;
    fastoml_slice key_copy;
    fastoml_builder* owner;

    if (!table || !value || table->kind != FASTOML_NODE_TABLE) {
        return FASTOML_ERR_TYPE;
    }
    if (!key.ptr && key.len > 0u) {
        return FASTOML_ERR_TYPE;
    }
    if (!fastoml_builder_slice_utf8_ok(key)) {
        return FASTOML_ERR_UTF8;
    }

    owner = table->owner;
    if (!owner || value->owner != owner || table->epoch != owner->epoch || value->epoch != owner->epoch) {
        return FASTOML_ERR_TYPE;
    }

    hash = fastoml_hash_slice(key);
    if (fastoml_builder_table_find_kv(table, key, hash)) {
        return FASTOML_ERR_DUP_KEY;
    }
    if (table->as.table.len == table->as.table.cap) {
        const uint32_t next_cap = table->as.table.cap == 0u ? 8u : table->as.table.cap * 2u;
        if (!fastoml_builder_table_reserve(owner, table, next_cap)) {
            return FASTOML_ERR_OOM;
        }
    }
    if (fastoml_builder_copy_slice(owner, key, &key_copy) != FASTOML_OK) {
        return FASTOML_ERR_OOM;
    }
    table->as.table.items[table->as.table.len].key = key_copy;
    table->as.table.items[table->as.table.len].value = value;
    table->as.table.items[table->as.table.len].hash = hash;
    table->as.table.len += 1u;
    return FASTOML_OK;
}

fastoml_status fastoml_builder_table_set_cstr(fastoml_value* table, const char* key, fastoml_value* value) {
    fastoml_slice s;
    if (!key) {
        return FASTOML_ERR_TYPE;
    }
    s.ptr = key;
    s.len = (uint32_t)fastoml_cstr_len(key);
    return fastoml_builder_table_set(table, s, value);
}

fastoml_status fastoml_builder_array_push(fastoml_value* array, fastoml_value* value) {
    fastoml_builder* owner;
    if (!array || !value || array->kind != FASTOML_NODE_ARRAY) {
        return FASTOML_ERR_TYPE;
    }
    owner = array->owner;
    if (!owner || value->owner != owner || array->epoch != owner->epoch || value->epoch != owner->epoch) {
        return FASTOML_ERR_TYPE;
    }
    if (array->as.array.len == array->as.array.cap) {
        const uint32_t next_cap = array->as.array.cap == 0u ? 8u : array->as.array.cap * 2u;
        if (!fastoml_builder_array_reserve(owner, array, next_cap)) {
            return FASTOML_ERR_OOM;
        }
    }
    array->as.array.items[array->as.array.len++] = value;
    return FASTOML_OK;
}

typedef struct fastoml_serialize_view {
    fastoml_node_kind (*kindof)(const void* n);
    uint32_t (*table_size)(const void* table);
    fastoml_slice (*table_key_at)(const void* table, uint32_t idx);
    const void* (*table_value_at)(const void* table, uint32_t idx);
    uint32_t (*array_size)(const void* array);
    const void* (*array_at)(const void* array, uint32_t idx);
    fastoml_status (*as_bool)(const void* n, int* out_value);
    fastoml_status (*as_int)(const void* n, int64_t* out_value);
    fastoml_status (*as_float)(const void* n, double* out_value);
    fastoml_status (*as_slice)(const void* n, fastoml_slice* out_value);
} fastoml_serialize_view;

enum {
    FASTOML_SERIALIZE_DEPTH_LIMIT = 1024u,
    FASTOML_SERIALIZE_PATH_LIMIT = 1024u
};

typedef struct fastoml_serialize_state {
    const fastoml_serialize_view* view;
    fastoml_write_fn write_fn;
    void* write_ctx;
    uint32_t flags;
    uint32_t depth_limit;
    fastoml_slice path[FASTOML_SERIALIZE_PATH_LIMIT];
    uint32_t path_len;
    size_t line_count;
} fastoml_serialize_state;

static fastoml_node_kind fastoml_serialize_node_kindof_cb(const void* n) {
    return fastoml_node_kindof((const fastoml_node*)n);
}

static uint32_t fastoml_serialize_node_table_size_cb(const void* table) {
    return fastoml_table_size((const fastoml_node*)table);
}

static fastoml_slice fastoml_serialize_node_table_key_at_cb(const void* table, uint32_t idx) {
    return fastoml_table_key_at((const fastoml_node*)table, idx);
}

static const void* fastoml_serialize_node_table_value_at_cb(const void* table, uint32_t idx) {
    return fastoml_table_value_at((const fastoml_node*)table, idx);
}

static uint32_t fastoml_serialize_node_array_size_cb(const void* array) {
    return fastoml_array_size((const fastoml_node*)array);
}

static const void* fastoml_serialize_node_array_at_cb(const void* array, uint32_t idx) {
    return fastoml_array_at((const fastoml_node*)array, idx);
}

static fastoml_status fastoml_serialize_node_as_bool_cb(const void* n, int* out_value) {
    return fastoml_node_as_bool((const fastoml_node*)n, out_value);
}

static fastoml_status fastoml_serialize_node_as_int_cb(const void* n, int64_t* out_value) {
    return fastoml_node_as_int((const fastoml_node*)n, out_value);
}

static fastoml_status fastoml_serialize_node_as_float_cb(const void* n, double* out_value) {
    return fastoml_node_as_float((const fastoml_node*)n, out_value);
}

static fastoml_status fastoml_serialize_node_as_slice_cb(const void* n, fastoml_slice* out_value) {
    return fastoml_node_as_slice((const fastoml_node*)n, out_value);
}

static fastoml_node_kind fastoml_serialize_value_kindof_cb(const void* n) {
    const fastoml_value* v = (const fastoml_value*)n;
    return v ? v->kind : 0;
}

static uint32_t fastoml_serialize_value_table_size_cb(const void* table) {
    const fastoml_value* v = (const fastoml_value*)table;
    if (!v || v->kind != FASTOML_NODE_TABLE)
        return 0u;
    return v->as.table.len;
}

static fastoml_slice fastoml_serialize_value_table_key_at_cb(const void* table, uint32_t idx) {
    const fastoml_value* v = (const fastoml_value*)table;
    fastoml_slice s;
    s.ptr = NULL;
    s.len = 0u;
    if (!v || v->kind != FASTOML_NODE_TABLE)
        return s;
    if (idx >= v->as.table.len)
        return s;
    return v->as.table.items[idx].key;
}

static const void* fastoml_serialize_value_table_value_at_cb(const void* table, uint32_t idx) {
    const fastoml_value* v = (const fastoml_value*)table;
    if (!v || v->kind != FASTOML_NODE_TABLE)
        return NULL;
    if (idx >= v->as.table.len)
        return NULL;
    return v->as.table.items[idx].value;
}

static uint32_t fastoml_serialize_value_array_size_cb(const void* array) {
    const fastoml_value* v = (const fastoml_value*)array;
    if (!v || v->kind != FASTOML_NODE_ARRAY)
        return 0u;
    return v->as.array.len;
}

static const void* fastoml_serialize_value_array_at_cb(const void* array, uint32_t idx) {
    const fastoml_value* v = (const fastoml_value*)array;
    if (!v || v->kind != FASTOML_NODE_ARRAY)
        return NULL;
    if (idx >= v->as.array.len)
        return NULL;
    return v->as.array.items[idx];
}

static fastoml_status fastoml_serialize_value_as_bool_cb(const void* n, int* out_value) {
    const fastoml_value* v = (const fastoml_value*)n;
    if (!v || v->kind != FASTOML_NODE_BOOL)
        return FASTOML_ERR_TYPE;
    if (out_value)
        *out_value = v->as.b;
    return FASTOML_OK;
}

static fastoml_status fastoml_serialize_value_as_int_cb(const void* n, int64_t* out_value) {
    const fastoml_value* v = (const fastoml_value*)n;
    if (!v || v->kind != FASTOML_NODE_INT)
        return FASTOML_ERR_TYPE;
    if (out_value)
        *out_value = v->as.i64;
    return FASTOML_OK;
}

static fastoml_status fastoml_serialize_value_as_float_cb(const void* n, double* out_value) {
    const fastoml_value* v = (const fastoml_value*)n;
    if (!v || v->kind != FASTOML_NODE_FLOAT)
        return FASTOML_ERR_TYPE;
    if (out_value)
        *out_value = v->as.f64;
    return FASTOML_OK;
}

static fastoml_status fastoml_serialize_value_as_slice_cb(const void* n, fastoml_slice* out_value) {
    const fastoml_value* v = (const fastoml_value*)n;
    if (!v)
        return FASTOML_ERR_TYPE;
    if (v->kind == FASTOML_NODE_STRING) {
        if (out_value)
            *out_value = v->as.str.view;
        return FASTOML_OK;
    }
    if (v->kind == FASTOML_NODE_DATETIME || v->kind == FASTOML_NODE_DATE || v->kind == FASTOML_NODE_TIME) {
        if (out_value)
            *out_value = v->as.datetime.raw;
        return FASTOML_OK;
    }
    return FASTOML_ERR_TYPE;
}

static const fastoml_serialize_view FASTOML_NODE_SERIALIZE_VIEW = {
    &fastoml_serialize_node_kindof_cb,
    &fastoml_serialize_node_table_size_cb,
    &fastoml_serialize_node_table_key_at_cb,
    &fastoml_serialize_node_table_value_at_cb,
    &fastoml_serialize_node_array_size_cb,
    &fastoml_serialize_node_array_at_cb,
    &fastoml_serialize_node_as_bool_cb,
    &fastoml_serialize_node_as_int_cb,
    &fastoml_serialize_node_as_float_cb,
    &fastoml_serialize_node_as_slice_cb};

static const fastoml_serialize_view FASTOML_VALUE_SERIALIZE_VIEW = {
    &fastoml_serialize_value_kindof_cb,
    &fastoml_serialize_value_table_size_cb,
    &fastoml_serialize_value_table_key_at_cb,
    &fastoml_serialize_value_table_value_at_cb,
    &fastoml_serialize_value_array_size_cb,
    &fastoml_serialize_value_array_at_cb,
    &fastoml_serialize_value_as_bool_cb,
    &fastoml_serialize_value_as_int_cb,
    &fastoml_serialize_value_as_float_cb,
    &fastoml_serialize_value_as_slice_cb};

static fastoml_status fastoml_serialize_write(fastoml_serialize_state* s, const char* data, size_t len) {
    if (len == 0u) {
        return FASTOML_OK;
    }
    if (!s->write_fn) {
        return FASTOML_ERR_TYPE;
    }
    return s->write_fn(s->write_ctx, data, len);
}

static fastoml_status fastoml_serialize_write_char(fastoml_serialize_state* s, char c) {
    return fastoml_serialize_write(s, &c, 1u);
}

static fastoml_status fastoml_serialize_start_line(fastoml_serialize_state* s) {
    fastoml_status st;
    if (s->line_count > 0u) {
        st = fastoml_serialize_write_char(s, '\n');
        if (st != FASTOML_OK) {
            return st;
        }
    }
    s->line_count += 1u;
    return FASTOML_OK;
}

static fastoml_status fastoml_serialize_blank_line(fastoml_serialize_state* s) {
    if (s->line_count == 0u) {
        return FASTOML_OK;
    }
    return fastoml_serialize_start_line(s);
}

static fastoml_status fastoml_serialize_write_u00xx(fastoml_serialize_state* s, unsigned char c) {
    static const char HEX[] = "0123456789ABCDEF";
    char out[6];
    out[0] = '\\';
    out[1] = 'u';
    out[2] = '0';
    out[3] = '0';
    out[4] = HEX[(c >> 4) & 0x0Fu];
    out[5] = HEX[c & 0x0Fu];
    return fastoml_serialize_write(s, out, sizeof(out));
}

static fastoml_status fastoml_serialize_write_escaped_basic(fastoml_serialize_state* s, fastoml_slice text) {
    size_t i = 0u;
    size_t run = 0u;
    while (i < text.len) {
        const unsigned char c = (unsigned char)text.ptr[i];
        const char* esc = NULL;
        size_t esc_len = 0u;
        if (c == '"') {
            esc = "\\\"";
            esc_len = 2u;
        } else if (c == '\\') {
            esc = "\\\\";
            esc_len = 2u;
        } else if (c == '\b') {
            esc = "\\b";
            esc_len = 2u;
        } else if (c == '\t') {
            esc = "\\t";
            esc_len = 2u;
        } else if (c == '\n') {
            esc = "\\n";
            esc_len = 2u;
        } else if (c == '\f') {
            esc = "\\f";
            esc_len = 2u;
        } else if (c == '\r') {
            esc = "\\r";
            esc_len = 2u;
        } else if (c == 0x1Bu) {
            esc = "\\e";
            esc_len = 2u;
        } else if (c < 0x20u || c == 0x7Fu) {
            fastoml_status st;
            if (i > run) {
                st = fastoml_serialize_write(s, text.ptr + run, i - run);
                if (st != FASTOML_OK) {
                    return st;
                }
            }
            st = fastoml_serialize_write_u00xx(s, c);
            if (st != FASTOML_OK) {
                return st;
            }
            ++i;
            run = i;
            continue;
        }

        if (esc) {
            fastoml_status st;
            if (i > run) {
                st = fastoml_serialize_write(s, text.ptr + run, i - run);
                if (st != FASTOML_OK) {
                    return st;
                }
            }
            st = fastoml_serialize_write(s, esc, esc_len);
            if (st != FASTOML_OK) {
                return st;
            }
            ++i;
            run = i;
            continue;
        }
        ++i;
    }
    if (i > run) {
        return fastoml_serialize_write(s, text.ptr + run, i - run);
    }
    return FASTOML_OK;
}

static fastoml_status fastoml_serialize_write_basic_string(fastoml_serialize_state* s, fastoml_slice text) {
    fastoml_status st = fastoml_serialize_write_char(s, '"');
    if (st != FASTOML_OK) {
        return st;
    }
    st = fastoml_serialize_write_escaped_basic(s, text);
    if (st != FASTOML_OK) {
        return st;
    }
    return fastoml_serialize_write_char(s, '"');
}

static int fastoml_serialize_key_is_bare(fastoml_slice key) {
    uint32_t i;
    if (key.len == 0u || !key.ptr) {
        return 0;
    }
    i = 0u;
    while (i < key.len) {
        if (!fastoml_char_is_bare_key((unsigned char)key.ptr[i])) {
            return 0;
        }
        ++i;
    }
    return 1;
}

static fastoml_status fastoml_serialize_write_key(fastoml_serialize_state* s, fastoml_slice key) {
    if (fastoml_serialize_key_is_bare(key)) {
        return fastoml_serialize_write(s, key.ptr, key.len);
    }
    return fastoml_serialize_write_basic_string(s, key);
}

static fastoml_status fastoml_serialize_write_path(fastoml_serialize_state* s) {
    uint32_t i = 0u;
    while (i < s->path_len) {
        fastoml_status st;
        if (i > 0u) {
            st = fastoml_serialize_write_char(s, '.');
            if (st != FASTOML_OK) {
                return st;
            }
        }
        st = fastoml_serialize_write_key(s, s->path[i]);
        if (st != FASTOML_OK) {
            return st;
        }
        ++i;
    }
    return FASTOML_OK;
}

static fastoml_status fastoml_serialize_path_push(fastoml_serialize_state* s, fastoml_slice key) {
    if (s->path_len >= FASTOML_SERIALIZE_PATH_LIMIT) {
        return FASTOML_ERR_DEPTH;
    }
    s->path[s->path_len++] = key;
    return FASTOML_OK;
}

static void fastoml_serialize_path_pop(fastoml_serialize_state* s) {
    if (s->path_len > 0u) {
        s->path_len -= 1u;
    }
}

static int fastoml_serialize_is_array_of_tables(fastoml_serialize_state* s, const void* n) {
    uint32_t i;
    const fastoml_serialize_view* v = s->view;
    const uint32_t len = v->array_size(n);
    if (v->kindof(n) != FASTOML_NODE_ARRAY || len == 0u) {
        return 0;
    }
    i = 0u;
    while (i < len) {
        const void* item = v->array_at(n, i);
        if (!item || v->kindof(item) != FASTOML_NODE_TABLE) {
            return 0;
        }
        ++i;
    }
    return 1;
}

static fastoml_status fastoml_serialize_inline_value(fastoml_serialize_state* s, const void* n, uint32_t depth);

static fastoml_status fastoml_serialize_inline_array(fastoml_serialize_state* s, const void* array, uint32_t depth) {
    const fastoml_serialize_view* v = s->view;
    const uint32_t len = v->array_size(array);
    uint32_t i = 0u;
    fastoml_status st = fastoml_serialize_write_char(s, '[');
    if (st != FASTOML_OK) {
        return st;
    }
    while (i < len) {
        if (i > 0u) {
            st = fastoml_serialize_write(s, ", ", 2u);
            if (st != FASTOML_OK) {
                return st;
            }
        }
        st = fastoml_serialize_inline_value(s, v->array_at(array, i), depth + 1u);
        if (st != FASTOML_OK) {
            return st;
        }
        ++i;
    }
    return fastoml_serialize_write_char(s, ']');
}

static fastoml_status fastoml_serialize_inline_table(fastoml_serialize_state* s, const void* table, uint32_t depth) {
    const fastoml_serialize_view* v = s->view;
    const uint32_t len = v->table_size(table);
    uint32_t i = 0u;
    fastoml_status st = fastoml_serialize_write_char(s, '{');
    if (st != FASTOML_OK) {
        return st;
    }
    while (i < len) {
        const fastoml_slice key = v->table_key_at(table, i);
        const void* value = v->table_value_at(table, i);
        if (i > 0u) {
            st = fastoml_serialize_write(s, ", ", 2u);
            if (st != FASTOML_OK) {
                return st;
            }
        }
        st = fastoml_serialize_write_key(s, key);
        if (st != FASTOML_OK) {
            return st;
        }
        st = fastoml_serialize_write(s, " = ", 3u);
        if (st != FASTOML_OK) {
            return st;
        }
        st = fastoml_serialize_inline_value(s, value, depth + 1u);
        if (st != FASTOML_OK) {
            return st;
        }
        ++i;
    }
    return fastoml_serialize_write_char(s, '}');
}

static fastoml_status fastoml_serialize_inline_float(fastoml_serialize_state* s, double value) {
    char buf[64];
    int n;
    size_t i;
    int needs_decimal = 1;
    if (!isfinite(value)) {
        if (isnan(value)) {
            return fastoml_serialize_write(s, signbit(value) ? "-nan" : "nan", signbit(value) ? 4u : 3u);
        }
        return fastoml_serialize_write(s, signbit(value) ? "-inf" : "inf", signbit(value) ? 4u : 3u);
    }
    n = snprintf(buf, sizeof(buf), "%.17g", value);
    if (n <= 0 || (size_t)n >= sizeof(buf)) {
        return FASTOML_ERR_OVERFLOW;
    }
    for (i = 0u; i < (size_t)n; ++i) {
        if (buf[i] == ',') {
            buf[i] = '.';
        }
        if (buf[i] == '.' || buf[i] == 'e' || buf[i] == 'E') {
            needs_decimal = 0;
        }
    }
    if (needs_decimal) {
        if ((size_t)n + 2u >= sizeof(buf)) {
            return FASTOML_ERR_OVERFLOW;
        }
        buf[n++] = '.';
        buf[n++] = '0';
    }
    return fastoml_serialize_write(s, buf, (size_t)n);
}

static fastoml_status fastoml_serialize_inline_value(fastoml_serialize_state* s, const void* n, uint32_t depth) {
    const fastoml_serialize_view* v = s->view;
    fastoml_slice sv;
    int bv;
    int64_t iv;
    double fv;
    if (!n) {
        return FASTOML_ERR_TYPE;
    }
    if (depth > s->depth_limit) {
        return FASTOML_ERR_DEPTH;
    }
    switch (v->kindof(n)) {
    case FASTOML_NODE_TABLE:
        return fastoml_serialize_inline_table(s, n, depth + 1u);
    case FASTOML_NODE_ARRAY:
        return fastoml_serialize_inline_array(s, n, depth + 1u);
    case FASTOML_NODE_STRING:
        if (v->as_slice(n, &sv) != FASTOML_OK) {
            return FASTOML_ERR_TYPE;
        }
        return fastoml_serialize_write_basic_string(s, sv);
    case FASTOML_NODE_INT: {
        char out[32];
        int len;
        if (v->as_int(n, &iv) != FASTOML_OK) {
            return FASTOML_ERR_TYPE;
        }
        len = snprintf(out, sizeof(out), "%" PRId64, iv);
        if (len <= 0 || (size_t)len >= sizeof(out)) {
            return FASTOML_ERR_OVERFLOW;
        }
        return fastoml_serialize_write(s, out, (size_t)len);
    }
    case FASTOML_NODE_FLOAT:
        if (v->as_float(n, &fv) != FASTOML_OK) {
            return FASTOML_ERR_TYPE;
        }
        return fastoml_serialize_inline_float(s, fv);
    case FASTOML_NODE_BOOL:
        if (v->as_bool(n, &bv) != FASTOML_OK) {
            return FASTOML_ERR_TYPE;
        }
        return fastoml_serialize_write(s, bv ? "true" : "false", bv ? 4u : 5u);
    case FASTOML_NODE_DATETIME:
    case FASTOML_NODE_DATE:
    case FASTOML_NODE_TIME:
        if (v->as_slice(n, &sv) != FASTOML_OK) {
            return FASTOML_ERR_TYPE;
        }
        return fastoml_serialize_write(s, sv.ptr, sv.len);
    default:
        return FASTOML_ERR_TYPE;
    }
}

static fastoml_status fastoml_serialize_emit_header_line(fastoml_serialize_state* s, int array_header) {
    fastoml_status st;
    st = fastoml_serialize_start_line(s);
    if (st != FASTOML_OK) {
        return st;
    }
    st = fastoml_serialize_write(s, array_header ? "[[" : "[", array_header ? 2u : 1u);
    if (st != FASTOML_OK) {
        return st;
    }
    st = fastoml_serialize_write_path(s);
    if (st != FASTOML_OK) {
        return st;
    }
    return fastoml_serialize_write(s, array_header ? "]]" : "]", array_header ? 2u : 1u);
}

static fastoml_status fastoml_serialize_emit_table(fastoml_serialize_state* s, const void* table, uint32_t depth, int header_kind) {
    const fastoml_serialize_view* v = s->view;
    const uint32_t len = v->table_size(table);
    uint32_t i;
    int wrote_scalar = 0;
    int wrote_section = 0;

    if (!table || v->kindof(table) != FASTOML_NODE_TABLE) {
        return FASTOML_ERR_TYPE;
    }
    if (depth > s->depth_limit) {
        return FASTOML_ERR_DEPTH;
    }
    if (header_kind == 1) {
        fastoml_status st = fastoml_serialize_emit_header_line(s, 0);
        if (st != FASTOML_OK) {
            return st;
        }
    } else if (header_kind == 2) {
        fastoml_status st = fastoml_serialize_emit_header_line(s, 1);
        if (st != FASTOML_OK) {
            return st;
        }
    }

    i = 0u;
    while (i < len) {
        const fastoml_slice key = v->table_key_at(table, i);
        const void* value = v->table_value_at(table, i);
        const fastoml_node_kind kind = v->kindof(value);
        fastoml_status st;
        if (kind == FASTOML_NODE_TABLE || (kind == FASTOML_NODE_ARRAY && fastoml_serialize_is_array_of_tables(s, value))) {
            ++i;
            continue;
        }
        st = fastoml_serialize_start_line(s);
        if (st != FASTOML_OK) {
            return st;
        }
        st = fastoml_serialize_write_key(s, key);
        if (st != FASTOML_OK) {
            return st;
        }
        st = fastoml_serialize_write(s, " = ", 3u);
        if (st != FASTOML_OK) {
            return st;
        }
        st = fastoml_serialize_inline_value(s, value, depth + 1u);
        if (st != FASTOML_OK) {
            return st;
        }
        wrote_scalar = 1;
        ++i;
    }

    i = 0u;
    while (i < len) {
        const fastoml_slice key = v->table_key_at(table, i);
        const void* value = v->table_value_at(table, i);
        const fastoml_node_kind kind = v->kindof(value);
        fastoml_status st;
        if (kind != FASTOML_NODE_TABLE && !(kind == FASTOML_NODE_ARRAY && fastoml_serialize_is_array_of_tables(s, value))) {
            ++i;
            continue;
        }
        if (wrote_scalar || wrote_section) {
            st = fastoml_serialize_blank_line(s);
            if (st != FASTOML_OK) {
                return st;
            }
        }
        st = fastoml_serialize_path_push(s, key);
        if (st != FASTOML_OK) {
            return st;
        }
        if (kind == FASTOML_NODE_TABLE) {
            st = fastoml_serialize_emit_table(s, value, depth + 1u, 1);
            if (st != FASTOML_OK) {
                fastoml_serialize_path_pop(s);
                return st;
            }
            wrote_section = 1;
        } else {
            uint32_t j = 0u;
            const uint32_t arr_len = v->array_size(value);
            while (j < arr_len) {
                const void* item = v->array_at(value, j);
                if (v->kindof(item) != FASTOML_NODE_TABLE) {
                    fastoml_serialize_path_pop(s);
                    return FASTOML_ERR_TYPE;
                }
                if (wrote_section || j > 0u) {
                    st = fastoml_serialize_blank_line(s);
                    if (st != FASTOML_OK) {
                        fastoml_serialize_path_pop(s);
                        return st;
                    }
                }
                st = fastoml_serialize_emit_table(s, item, depth + 1u, 2);
                if (st != FASTOML_OK) {
                    fastoml_serialize_path_pop(s);
                    return st;
                }
                wrote_section = 1;
                ++j;
            }
        }
        fastoml_serialize_path_pop(s);
        ++i;
    }

    return FASTOML_OK;
}

void fastoml_serialize_options_default(fastoml_serialize_options* out) {
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->flags = FASTOML_SERIALIZE_FINAL_NEWLINE;
}

static fastoml_status fastoml_serialize_internal(
    const void* root,
    const fastoml_serialize_view* view,
    const fastoml_serialize_options* opt,
    fastoml_write_fn write_fn,
    void* write_ctx,
    uint32_t depth_limit) {
    fastoml_serialize_state state;
    fastoml_serialize_options options;
    fastoml_status st;
    if (!root || !view || !write_fn) {
        return FASTOML_ERR_TYPE;
    }
    fastoml_serialize_options_default(&options);
    if (opt) {
        options = *opt;
    }
    if (view->kindof(root) != FASTOML_NODE_TABLE) {
        return FASTOML_ERR_TYPE;
    }

    memset(&state, 0, sizeof(state));
    state.view = view;
    state.write_fn = write_fn;
    state.write_ctx = write_ctx;
    state.flags = options.flags;
    state.depth_limit = depth_limit ? depth_limit : FASTOML_SERIALIZE_DEPTH_LIMIT;

    st = fastoml_serialize_emit_table(&state, root, 0u, 0);
    if (st != FASTOML_OK) {
        return st;
    }
    if ((state.flags & FASTOML_SERIALIZE_FINAL_NEWLINE) != 0u && state.line_count > 0u) {
        st = fastoml_serialize_write_char(&state, '\n');
        if (st != FASTOML_OK) {
            return st;
        }
    }
    return FASTOML_OK;
}

typedef struct fastoml_count_sink {
    size_t len;
} fastoml_count_sink;

typedef struct fastoml_buffer_sink {
    char* out;
    size_t len;
} fastoml_buffer_sink;

static fastoml_status fastoml_count_sink_write(void* ctx, const char* data, size_t len) {
    fastoml_count_sink* s = (fastoml_count_sink*)ctx;
    (void)data;
    if (!s) {
        return FASTOML_ERR_TYPE;
    }
    if (len > SIZE_MAX - s->len) {
        return FASTOML_ERR_OVERFLOW;
    }
    s->len += len;
    return FASTOML_OK;
}

static fastoml_status fastoml_buffer_sink_write(void* ctx, const char* data, size_t len) {
    fastoml_buffer_sink* s = (fastoml_buffer_sink*)ctx;
    if (!s || (!s->out && len > 0u)) {
        return FASTOML_ERR_TYPE;
    }
    if (len > 0u) {
        memcpy(s->out + s->len, data, len);
        s->len += len;
    }
    return FASTOML_OK;
}

fastoml_status fastoml_serialize_to_sink(
    const fastoml_value* root,
    const fastoml_serialize_options* opt,
    fastoml_write_fn write_fn,
    void* write_ctx) {
    if (!root || !root->owner || root->epoch != root->owner->epoch) {
        return FASTOML_ERR_TYPE;
    }
    const uint32_t depth_limit = (root && root->owner) ? root->owner->opt.max_depth : FASTOML_SERIALIZE_DEPTH_LIMIT;
    return fastoml_serialize_internal(root, &FASTOML_VALUE_SERIALIZE_VIEW, opt, write_fn, write_ctx, depth_limit);
}

fastoml_status fastoml_serialize_to_buffer(
    const fastoml_value* root,
    const fastoml_serialize_options* opt,
    char* out,
    size_t out_cap,
    size_t* out_len) {
    fastoml_status st;
    fastoml_count_sink count;
    fastoml_buffer_sink sink;
    uint32_t depth_limit;
    if (!out_len) {
        return FASTOML_ERR_TYPE;
    }
    if (!root || !root->owner || root->epoch != root->owner->epoch) {
        return FASTOML_ERR_TYPE;
    }
    depth_limit = root->owner->opt.max_depth;
    memset(&count, 0, sizeof(count));
    st = fastoml_serialize_internal(root, &FASTOML_VALUE_SERIALIZE_VIEW, opt, &fastoml_count_sink_write, &count, depth_limit);
    if (st != FASTOML_OK) {
        return st;
    }
    *out_len = count.len;
    if (!out || out_cap == 0u) {
        return FASTOML_OK;
    }
    if (out_cap <= count.len) {
        return FASTOML_ERR_OVERFLOW;
    }
    sink.out = out;
    sink.len = 0u;
    st = fastoml_serialize_internal(root, &FASTOML_VALUE_SERIALIZE_VIEW, opt, &fastoml_buffer_sink_write, &sink, depth_limit);
    if (st != FASTOML_OK) {
        return st;
    }
    out[sink.len] = '\0';
    return FASTOML_OK;
}

fastoml_status fastoml_serialize_node_to_sink(
    const fastoml_node* root,
    const fastoml_serialize_options* opt,
    fastoml_write_fn write_fn,
    void* write_ctx) {
    return fastoml_serialize_internal(root, &FASTOML_NODE_SERIALIZE_VIEW, opt, write_fn, write_ctx, FASTOML_SERIALIZE_DEPTH_LIMIT);
}

fastoml_status fastoml_serialize_node_to_buffer(
    const fastoml_node* root,
    const fastoml_serialize_options* opt,
    char* out,
    size_t out_cap,
    size_t* out_len) {
    fastoml_status st;
    fastoml_count_sink count;
    fastoml_buffer_sink sink;
    if (!out_len) {
        return FASTOML_ERR_TYPE;
    }
    memset(&count, 0, sizeof(count));
    st = fastoml_serialize_internal(root, &FASTOML_NODE_SERIALIZE_VIEW, opt, &fastoml_count_sink_write, &count, FASTOML_SERIALIZE_DEPTH_LIMIT);
    if (st != FASTOML_OK) {
        return st;
    }
    *out_len = count.len;
    if (!out || out_cap == 0u) {
        return FASTOML_OK;
    }
    if (out_cap <= count.len) {
        return FASTOML_ERR_OVERFLOW;
    }
    sink.out = out;
    sink.len = 0u;
    st = fastoml_serialize_internal(root, &FASTOML_NODE_SERIALIZE_VIEW, opt, &fastoml_buffer_sink_write, &sink, FASTOML_SERIALIZE_DEPTH_LIMIT);
    if (st != FASTOML_OK) {
        return st;
    }
    out[sink.len] = '\0';
    return FASTOML_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* FASTOML_IMPLEMENTATION */

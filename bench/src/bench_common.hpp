#pragma once

#include <benchmark/benchmark.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fastoml::bench {

struct InputCase {
    std::string id;
    std::string file_name;
    std::string toml;
    bool expect_success;
};

inline std::string read_file_or_throw(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        throw std::runtime_error("failed to open input file: " + path.string());
    }
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

inline std::filesystem::path resolve_input_dir() {
    const std::vector<std::filesystem::path> candidates = {
        std::filesystem::current_path() / "input",
#ifdef FASTOML_BENCH_SOURCE_DIR
        std::filesystem::path(FASTOML_BENCH_SOURCE_DIR) / "input",
#endif
    };

    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate) && std::filesystem::is_directory(candidate)) {
            return candidate;
        }
    }

    std::string msg = "input directory not found. tried:";
    for (const auto& candidate : candidates) {
        msg += " " + candidate.string();
    }
    throw std::runtime_error(msg);
}

inline std::vector<InputCase> load_default_input_cases() {
    struct Spec {
        const char* id;
        const char* file_name;
        bool expect_success;
    };

    const Spec specs[] = {
        {"parse_small", "small.toml", true},
        {"parse_medium", "medium.toml", true},
        {"parse_large", "large.toml", true},
        {"parse_invalid", "invalid_syntax.toml", false},
    };

    const auto input_dir = resolve_input_dir();

    std::vector<InputCase> inputs;
    inputs.reserve(sizeof(specs) / sizeof(specs[0]));
    for (const auto& spec : specs) {
        InputCase input;
        input.id = spec.id;
        input.file_name = spec.file_name;
        input.expect_success = spec.expect_success;
        input.toml = read_file_or_throw(input_dir / spec.file_name);
        inputs.push_back(std::move(input));
    }
    return inputs;
}

inline int64_t bytes_processed(const benchmark::State& state, const std::string_view input) {
    return static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(input.size());
}

} // namespace fastoml::bench

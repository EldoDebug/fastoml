#include "bench_interfaces.hpp"

#include <benchmark/benchmark.h>

#include <string_view>

#include <toml++/toml.hpp>

namespace fastoml::bench {
namespace {

template <typename Parsed>
bool parse_failed(const Parsed& parsed) {
    if constexpr (requires { parsed.error(); } && requires { static_cast<bool>(parsed); }) {
        return !static_cast<bool>(parsed);
    }
    return false;
}

bool parse_tomlplusplus(std::string_view input) {
    try {
        auto value = toml::parse(input);
        if (parse_failed(value)) {
            return false;
        }
        benchmark::DoNotOptimize(value);
        return true;
    } catch (...) {
        return false;
    }
}

void run_parse_case(benchmark::State& state, const InputCase& input) {
    bool mismatch = false;
    for (auto _ : state) {
        (void)_;
        const bool ok = parse_tomlplusplus(input.toml);
        if (ok != input.expect_success) {
            mismatch = true;
            break;
        }
    }

    if (mismatch) {
        state.SkipWithError("toml++ parse result did not match expected validity");
    } else {
        state.SetBytesProcessed(bytes_processed(state, input.toml));
    }
}

} // namespace

void register_tomlplusplus_benchmarks(const std::vector<InputCase>& inputs) {
    for (const auto& input : inputs) {
        const std::string name = "toml++/" + input.id;
        benchmark::RegisterBenchmark(name.c_str(), [input](benchmark::State& state) {
            run_parse_case(state, input);
        });
    }
}

} // namespace fastoml::bench

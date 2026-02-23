#include "bench_interfaces.hpp"

#include <benchmark/benchmark.h>

#include <string>
#include <string_view>
#include <vector>

#include <toml.hpp>

namespace fastoml::bench {
namespace {

bool parse_toml11(std::string_view input) {
    try {
        std::vector<unsigned char> bytes(input.begin(), input.end());
        auto value = toml::parse(std::move(bytes), "in-memory.toml");
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
        const bool ok = parse_toml11(input.toml);
        if (ok != input.expect_success) {
            mismatch = true;
            break;
        }
    }

    if (mismatch) {
        state.SkipWithError("toml11 parse result did not match expected validity");
    } else {
        state.SetBytesProcessed(bytes_processed(state, input.toml));
    }
}

} // namespace

void register_toml11_benchmarks(const std::vector<InputCase>& inputs) {
    for (const auto& input : inputs) {
        const std::string name = "toml11/" + input.id;
        benchmark::RegisterBenchmark(name.c_str(), [input](benchmark::State& state) {
            run_parse_case(state, input);
        });
    }
}

} // namespace fastoml::bench

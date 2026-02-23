#include "bench_interfaces.hpp"

#include <benchmark/benchmark.h>

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        const auto inputs = fastoml::bench::load_default_input_cases();
        fastoml::bench::register_fastoml_benchmarks(inputs);
#if FASTOML_BENCH_COMPARE_TOML11
        fastoml::bench::register_toml11_benchmarks(inputs);
#endif
#if FASTOML_BENCH_COMPARE_TOMLPLUSPLUS
        fastoml::bench::register_tomlplusplus_benchmarks(inputs);
#endif
    } catch (const std::exception& ex) {
        std::cerr << "failed to initialize benchmarks: " << ex.what() << '\n';
        return 1;
    }

    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
        return 1;
    }
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

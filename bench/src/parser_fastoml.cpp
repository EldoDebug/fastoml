#include "bench_interfaces.hpp"

#include <benchmark/benchmark.h>

#include "fastoml.h"

namespace fastoml::bench {
namespace {

bool parse_fastoml(fastoml_parser* parser, std::string_view input) {
    const fastoml_document* doc = nullptr;
    fastoml_error err{};
    const fastoml_status status = fastoml_parse(parser, input.data(), input.size(), &doc, &err);
    benchmark::DoNotOptimize(doc);
    benchmark::DoNotOptimize(err);
    return status == FASTOML_OK;
}

void run_parse_case(benchmark::State& state, const InputCase& input) {
    fastoml_options options{};
    fastoml_options_default(&options);
    bool mismatch = false;
    for (auto _ : state) {
        (void)_;
        fastoml_parser* parser = fastoml_parser_create(&options);
        if (parser == nullptr) {
            state.SkipWithError("fastoml_parser_create failed");
            return;
        }
        const bool ok = parse_fastoml(parser, input.toml);
        fastoml_parser_destroy(parser);
        if (ok != input.expect_success) {
            mismatch = true;
            break;
        }
    }

    if (mismatch) {
        state.SkipWithError("fastoml parse result did not match expected validity");
    } else {
        state.SetBytesProcessed(bytes_processed(state, input.toml));
    }
}

} // namespace

void register_fastoml_benchmarks(const std::vector<InputCase>& inputs) {
    for (const auto& input : inputs) {
        const std::string name = "fastoml/" + input.id;
        benchmark::RegisterBenchmark(name.c_str(), [input](benchmark::State& state) {
            run_parse_case(state, input);
        });
    }
}

} // namespace fastoml::bench

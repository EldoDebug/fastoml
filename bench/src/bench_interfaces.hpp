#pragma once

#include "bench_common.hpp"

namespace fastoml::bench {

void register_fastoml_benchmarks(const std::vector<InputCase>& inputs);

#if FASTOML_BENCH_COMPARE_TOML11
void register_toml11_benchmarks(const std::vector<InputCase>& inputs);
#endif

#if FASTOML_BENCH_COMPARE_TOMLPLUSPLUS
void register_tomlplusplus_benchmarks(const std::vector<InputCase>& inputs);
#endif

} // namespace fastoml::bench

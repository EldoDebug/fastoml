cmake_minimum_required(VERSION 3.20)

project(fastoml LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(FASTOML_BUILD_EXAMPLES "Build fastoml examples" ON)
option(FASTOML_BUILD_TESTS "Build tests" ON)
option(FASTOML_BENCH "Build benchmarks" OFF)
option(FASTOML_BENCH_COMPARE_TOML11 "Enable toml11 benchmark" ON)
option(FASTOML_BENCH_COMPARE_TOMLPLUSPLUS "Enable toml++ benchmark" ON)
set(FASTOML_BENCH_REPETITIONS "10" CACHE STRING "Benchmark repetitions")
set(FASTOML_BENCH_WARMUP_SEC "0.1" CACHE STRING "Benchmark warmup seconds")
set(FASTOML_BENCH_OUTPUT_JSON "bench-results.json" CACHE STRING "Benchmark JSON output filename")

add_library(fastoml INTERFACE)
add_library(fastoml::fastoml ALIAS fastoml)
target_include_directories(fastoml INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

if(FASTOML_BUILD_EXAMPLES)
  add_subdirectory(example)
endif()

if(FASTOML_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(FASTOML_BENCH)
  add_subdirectory(bench)
endif()

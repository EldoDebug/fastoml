include(FetchContent)

set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  googlebenchmark
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG eddb0241389718a23a42db6af5f0164b6e0139af # v1.9.4
  GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(googlebenchmark)

if(FASTOML_BENCH_COMPARE_TOML11)
  FetchContent_Declare(
    toml11
    GIT_REPOSITORY https://github.com/ToruNiina/toml11.git
    GIT_TAG be08ba2be2a964edcdb3d3e3ea8d100abc26f286 # v4.4.0
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(toml11)
endif()

if(FASTOML_BENCH_COMPARE_TOMLPLUSPLUS)
  set(TOMLPLUSPLUS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(TOMLPLUSPLUS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG 30172438cee64926dc41fdd9c11fb3ba5b2ba9de # v3.4.0
    GIT_SHALLOW TRUE
  )
  FetchContent_MakeAvailable(tomlplusplus)
endif()

add_executable(fastoml_bench_parse
  src/parse_bench.cpp
  src/parser_fastoml.cpp
  src/fastoml_impl.c
  src/bench_common.hpp
  src/bench_interfaces.hpp
)

if(FASTOML_BENCH_COMPARE_TOML11)
  target_sources(fastoml_bench_parse PRIVATE src/parser_toml11.cpp)
endif()

if(FASTOML_BENCH_COMPARE_TOMLPLUSPLUS)
  target_sources(fastoml_bench_parse PRIVATE src/parser_tomlplusplus.cpp)
endif()

target_include_directories(fastoml_bench_parse PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(fastoml_bench_parse PRIVATE
  benchmark::benchmark
  fastoml::fastoml
)

if(FASTOML_BENCH_COMPARE_TOML11)
  target_link_libraries(fastoml_bench_parse PRIVATE toml11::toml11)
endif()

if(FASTOML_BENCH_COMPARE_TOMLPLUSPLUS)
  target_link_libraries(fastoml_bench_parse PRIVATE tomlplusplus::tomlplusplus)
endif()

target_compile_definitions(fastoml_bench_parse PRIVATE
  FASTOML_BENCH_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
  FASTOML_BENCH_COMPARE_TOML11=$<IF:$<BOOL:${FASTOML_BENCH_COMPARE_TOML11}>,1,0>
  FASTOML_BENCH_COMPARE_TOMLPLUSPLUS=$<IF:$<BOOL:${FASTOML_BENCH_COMPARE_TOMLPLUSPLUS}>,1,0>
)

set(FASTOML_BENCH_RUNTIME_INPUT_DIR "$<TARGET_FILE_DIR:fastoml_bench_parse>/input")
add_custom_command(
  TARGET fastoml_bench_parse
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "${FASTOML_BENCH_RUNTIME_INPUT_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/input"
          "${FASTOML_BENCH_RUNTIME_INPUT_DIR}"
)

set(FASTOML_BENCH_RESULTS_DIR "${CMAKE_BINARY_DIR}/bench-results")
add_custom_target(fastoml_bench_run
  COMMAND ${CMAKE_COMMAND} -E make_directory "${FASTOML_BENCH_RESULTS_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          "${CMAKE_CURRENT_SOURCE_DIR}/input"
          "${FASTOML_BENCH_RUNTIME_INPUT_DIR}"
  COMMAND $<TARGET_FILE:fastoml_bench_parse>
          --benchmark_repetitions=${FASTOML_BENCH_REPETITIONS}
          --benchmark_min_warmup_time=${FASTOML_BENCH_WARMUP_SEC}
          --benchmark_report_aggregates_only=true
          --benchmark_out=${FASTOML_BENCH_RESULTS_DIR}/${FASTOML_BENCH_OUTPUT_JSON}
          --benchmark_out_format=json
  DEPENDS fastoml_bench_parse
  WORKING_DIRECTORY "$<TARGET_FILE_DIR:fastoml_bench_parse>"
  USES_TERMINAL
)

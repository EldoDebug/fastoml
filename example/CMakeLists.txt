add_library(fastoml_example_impl OBJECT src/fastoml_impl.c)
target_link_libraries(fastoml_example_impl PRIVATE fastoml::fastoml)

add_executable(fastoml_example_io
  src/main.c
  $<TARGET_OBJECTS:fastoml_example_impl>
)
target_link_libraries(fastoml_example_io PRIVATE fastoml::fastoml)

set(FASTOML_EXAMPLE_SAMPLE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/sample/sample.toml")
set(FASTOML_EXAMPLE_SAMPLE_DST_DIR "${CMAKE_CURRENT_BINARY_DIR}/sample")

add_custom_command(
  TARGET fastoml_example_io
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory "${FASTOML_EXAMPLE_SAMPLE_DST_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${FASTOML_EXAMPLE_SAMPLE_SRC}"
          "${FASTOML_EXAMPLE_SAMPLE_DST_DIR}/sample.toml"
)

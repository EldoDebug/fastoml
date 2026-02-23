add_executable(fastoml_test_rw_values
  test_rw_values.c
)
target_link_libraries(fastoml_test_rw_values PRIVATE fastoml::fastoml)

add_test(NAME rw_values COMMAND fastoml_test_rw_values)
set_tests_properties(rw_values PROPERTIES LABELS "unit")

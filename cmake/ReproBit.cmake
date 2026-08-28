include_guard(GLOBAL)

function(_reprobit_target_source_path target source output)
  get_target_property(source_directory "${target}" SOURCE_DIR)
  if(IS_ABSOLUTE "${source}")
    get_filename_component(absolute "${source}" ABSOLUTE)
  else()
    get_filename_component(absolute "${source}" ABSOLUTE
                           BASE_DIR "${source_directory}")
  endif()
  set(${output} "${absolute}" PARENT_SCOPE)
endfunction()

# Insert one freshly generated source at an exact, checked target seat. INDEX
# is zero based. AFTER and BEFORE name the existing lexical neighbours when
# present; an empty neighbour admits only the corresponding list boundary.
# The function is deliberately data-only: generation happens in the Python
# adapter, which supplies the content receipt checked here.
function(reprobit_insert_generated_source)
  cmake_parse_arguments(
    PARSE_ARGV 0 RB "" "TARGET;SOURCE;INDEX;AFTER;BEFORE;LANGUAGE;SHA256;SIZE" ""
  )
  if(RB_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR
      "reprobit_insert_generated_source: unknown arguments: ${RB_UNPARSED_ARGUMENTS}")
  endif()
  foreach(required TARGET SOURCE INDEX LANGUAGE SHA256 SIZE)
    if(NOT DEFINED RB_${required} OR "${RB_${required}}" STREQUAL "")
      message(FATAL_ERROR
        "reprobit_insert_generated_source: ${required} is required")
    endif()
  endforeach()
  if(NOT TARGET "${RB_TARGET}")
    message(FATAL_ERROR
      "reprobit_insert_generated_source: no CMake target named ${RB_TARGET}")
  endif()
  if(NOT "${RB_INDEX}" MATCHES "^(0|[1-9][0-9]*)$")
    message(FATAL_ERROR
      "reprobit_insert_generated_source: INDEX must be non-negative")
  endif()
  string(LENGTH "${RB_SHA256}" sha256_length)
  if(NOT sha256_length EQUAL 64 OR
     NOT "${RB_SHA256}" MATCHES "^[0-9a-f]+$" OR
     NOT "${RB_SIZE}" MATCHES "^(0|[1-9][0-9]*)$")
    message(FATAL_ERROR
      "reprobit_insert_generated_source: invalid content receipt")
  endif()

  _reprobit_target_source_path("${RB_TARGET}" "${RB_SOURCE}" source)
  get_filename_component(project_source "${PROJECT_SOURCE_DIR}" ABSOLUTE)
  file(RELATIVE_PATH project_relative "${project_source}" "${source}")
  if(IS_ABSOLUTE "${project_relative}" OR
     "${project_relative}" MATCHES "^(\.\./|\.\.\\\\|\.\.$)")
    message(FATAL_ERROR
      "reprobit_insert_generated_source: source escapes PROJECT_SOURCE_DIR")
  endif()
  if(NOT EXISTS "${source}" OR IS_DIRECTORY "${source}" OR IS_SYMLINK "${source}")
    message(FATAL_ERROR
      "reprobit_insert_generated_source: source is absent, non-regular, or redirected: ${source}")
  endif()
  file(SHA256 "${source}" actual_sha256)
  file(SIZE "${source}" actual_size)
  if(NOT "${actual_sha256}" STREQUAL "${RB_SHA256}" OR
     NOT "${actual_size}" STREQUAL "${RB_SIZE}")
    message(FATAL_ERROR
      "reprobit_insert_generated_source: source content receipt differs: ${source}")
  endif()

  get_target_property(sources "${RB_TARGET}" SOURCES)
  if(sources MATCHES "-NOTFOUND$")
    set(sources)
  endif()
  list(LENGTH sources source_count)
  if(RB_INDEX GREATER source_count)
    message(FATAL_ERROR
      "reprobit_insert_generated_source: INDEX is outside ${RB_TARGET}")
  endif()
  foreach(existing IN LISTS sources)
    _reprobit_target_source_path("${RB_TARGET}" "${existing}" existing_absolute)
    if("${existing_absolute}" STREQUAL "${source}")
      message(FATAL_ERROR
        "reprobit_insert_generated_source: source already belongs to ${RB_TARGET}")
    endif()
  endforeach()

  if(DEFINED RB_AFTER AND NOT "${RB_AFTER}" STREQUAL "")
    if(RB_INDEX EQUAL 0)
      message(FATAL_ERROR
        "reprobit_insert_generated_source: first seat cannot have AFTER")
    endif()
    math(EXPR after_index "${RB_INDEX} - 1")
    list(GET sources ${after_index} actual_after)
    _reprobit_target_source_path("${RB_TARGET}" "${actual_after}" actual_after)
    _reprobit_target_source_path("${RB_TARGET}" "${RB_AFTER}" expected_after)
    if(NOT "${actual_after}" STREQUAL "${expected_after}")
      message(FATAL_ERROR
        "reprobit_insert_generated_source: AFTER neighbour differs")
    endif()
  endif()

  if(DEFINED RB_BEFORE AND NOT "${RB_BEFORE}" STREQUAL "")
    if(RB_INDEX EQUAL source_count)
      message(FATAL_ERROR
        "reprobit_insert_generated_source: final seat cannot have BEFORE")
    endif()
    list(GET sources ${RB_INDEX} actual_before)
    _reprobit_target_source_path("${RB_TARGET}" "${actual_before}" actual_before)
    _reprobit_target_source_path("${RB_TARGET}" "${RB_BEFORE}" expected_before)
    if(NOT "${actual_before}" STREQUAL "${expected_before}")
      message(FATAL_ERROR
        "reprobit_insert_generated_source: BEFORE neighbour differs: "
        "actual=${actual_before}; expected=${expected_before}; index=${RB_INDEX}")
    endif()
  endif()
  if(source_count GREATER 0 AND
     (NOT DEFINED RB_AFTER OR "${RB_AFTER}" STREQUAL "") AND
     (NOT DEFINED RB_BEFORE OR "${RB_BEFORE}" STREQUAL ""))
    message(FATAL_ERROR
      "reprobit_insert_generated_source: a non-empty target requires a neighbour pin")
  endif()

  list(INSERT sources ${RB_INDEX} "${source}")
  set_property(TARGET "${RB_TARGET}" PROPERTY SOURCES ${sources})
  set_property(SOURCE "${source}" TARGET_DIRECTORY "${RB_TARGET}"
               PROPERTY GENERATED TRUE)
  set_property(SOURCE "${source}" TARGET_DIRECTORY "${RB_TARGET}"
               PROPERTY LANGUAGE "${RB_LANGUAGE}")
endfunction()

# Insert an existing link item at one exact seat. This is separate from
# reprobit_add_link_admission: the latter records a produced object for the
# exported proof plan, while this function applies a project graph intervention.
function(reprobit_insert_link_item)
  cmake_parse_arguments(PARSE_ARGV 0 RB "" "TARGET;ITEM;INDEX;AFTER;BEFORE" "")
  if(RB_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR
      "reprobit_insert_link_item: unknown arguments: ${RB_UNPARSED_ARGUMENTS}")
  endif()
  foreach(required TARGET ITEM INDEX)
    if(NOT DEFINED RB_${required} OR "${RB_${required}}" STREQUAL "")
      message(FATAL_ERROR "reprobit_insert_link_item: ${required} is required")
    endif()
  endforeach()
  if(NOT TARGET "${RB_TARGET}" OR
     NOT "${RB_INDEX}" MATCHES "^(0|[1-9][0-9]*)$")
    message(FATAL_ERROR "reprobit_insert_link_item: invalid target or INDEX")
  endif()
  get_target_property(items "${RB_TARGET}" LINK_LIBRARIES)
  if(items MATCHES "-NOTFOUND$")
    set(items)
  endif()
  list(FIND items "${RB_ITEM}" duplicate)
  if(NOT duplicate EQUAL -1)
    message(FATAL_ERROR "reprobit_insert_link_item: ITEM is already linked")
  endif()
  list(LENGTH items item_count)
  if(RB_INDEX GREATER item_count)
    message(FATAL_ERROR "reprobit_insert_link_item: INDEX is outside the link list")
  endif()
  if(RB_INDEX EQUAL 0)
    if(DEFINED RB_AFTER AND NOT "${RB_AFTER}" STREQUAL "")
      message(FATAL_ERROR "reprobit_insert_link_item: first seat cannot have AFTER")
    endif()
  else()
    math(EXPR after_index "${RB_INDEX} - 1")
    list(GET items ${after_index} actual_after)
    if(NOT DEFINED RB_AFTER OR NOT "${actual_after}" STREQUAL "${RB_AFTER}")
      message(FATAL_ERROR "reprobit_insert_link_item: AFTER neighbour differs")
    endif()
  endif()
  if(RB_INDEX EQUAL item_count)
    if(DEFINED RB_BEFORE AND NOT "${RB_BEFORE}" STREQUAL "")
      message(FATAL_ERROR "reprobit_insert_link_item: final seat cannot have BEFORE")
    endif()
  else()
    list(GET items ${RB_INDEX} actual_before)
    if(NOT DEFINED RB_BEFORE OR NOT "${actual_before}" STREQUAL "${RB_BEFORE}")
      message(FATAL_ERROR "reprobit_insert_link_item: BEFORE neighbour differs")
    endif()
  endif()
  list(INSERT items ${RB_INDEX} "${RB_ITEM}")
  set_property(TARGET "${RB_TARGET}" PROPERTY LINK_LIBRARIES ${items})
endfunction()

# Register one target for a generated ReproBit target plan. OUTPUT may contain
# generator expressions. PDB is optional because it is not meaningful for every
# compiler or target type.
function(reprobit_register_target)
  cmake_parse_arguments(PARSE_ARGV 0 RB "" "TARGET;ARTIFACT_ID;OUTPUT;PDB" "")
  if(RB_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR "reprobit_register_target: unknown arguments: ${RB_UNPARSED_ARGUMENTS}")
  endif()
  foreach(required TARGET ARTIFACT_ID)
    if(NOT RB_${required})
      message(FATAL_ERROR "reprobit_register_target: ${required} is required")
    endif()
  endforeach()
  if(NOT TARGET "${RB_TARGET}")
    message(FATAL_ERROR "reprobit_register_target: no CMake target named ${RB_TARGET}")
  endif()
  if(NOT RB_OUTPUT)
    set(RB_OUTPUT "$<TARGET_FILE:${RB_TARGET}>")
  endif()
  get_property(existing GLOBAL PROPERTY REPROBIT_REGISTERED_TARGETS)
  if("${RB_TARGET}" IN_LIST existing)
    message(FATAL_ERROR "reprobit_register_target: ${RB_TARGET} was already registered")
  endif()
  set_property(GLOBAL APPEND PROPERTY REPROBIT_REGISTERED_TARGETS "${RB_TARGET}")
  set_property(TARGET "${RB_TARGET}" PROPERTY REPROBIT_ARTIFACT_ID "${RB_ARTIFACT_ID}")
  set_property(TARGET "${RB_TARGET}" PROPERTY REPROBIT_OUTPUT "${RB_OUTPUT}")
  set_property(TARGET "${RB_TARGET}" PROPERTY REPROBIT_PDB "${RB_PDB}")
endfunction()

# Record a complete, typed link admission. Exactly zero or one seat selector may
# be supplied. The generated plan retains every field, including the selectors
# and expected symbol.
function(reprobit_add_link_admission)
  cmake_parse_arguments(
    PARSE_ARGV 0 RB ""
    "ID;TARGET;ARTIFACT_ID;OBJECT_PATH;INSERTION_INDEX;BEFORE;AFTER;EXPECTED_SYMBOL" ""
  )
  if(RB_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR "reprobit_add_link_admission: unknown arguments: ${RB_UNPARSED_ARGUMENTS}")
  endif()
  foreach(required ID TARGET ARTIFACT_ID OBJECT_PATH)
    if(NOT RB_${required})
      message(FATAL_ERROR "reprobit_add_link_admission: ${required} is required")
    endif()
  endforeach()
  set(selector_count 0)
  foreach(selector INSERTION_INDEX BEFORE AFTER)
    if(DEFINED RB_${selector} AND NOT "${RB_${selector}}" STREQUAL "")
      math(EXPR selector_count "${selector_count} + 1")
    endif()
  endforeach()
  if(selector_count GREATER 1)
    message(FATAL_ERROR "reprobit_add_link_admission: use only one seat selector")
  endif()
  if(DEFINED RB_INSERTION_INDEX AND NOT "${RB_INSERTION_INDEX}" MATCHES "^[0-9]+$")
    message(FATAL_ERROR "reprobit_add_link_admission: INSERTION_INDEX must be non-negative")
  endif()
  get_property(existing GLOBAL PROPERTY REPROBIT_LINK_ADMISSION_IDS)
  if("${RB_ID}" IN_LIST existing)
    message(FATAL_ERROR "reprobit_add_link_admission: duplicate id ${RB_ID}")
  endif()
  set_property(GLOBAL APPEND PROPERTY REPROBIT_LINK_ADMISSION_IDS "${RB_ID}")
  foreach(field TARGET ARTIFACT_ID OBJECT_PATH INSERTION_INDEX BEFORE AFTER EXPECTED_SYMBOL)
    set_property(GLOBAL PROPERTY "REPROBIT_ADMISSION_${RB_ID}_${field}" "${RB_${field}}")
  endforeach()
endfunction()

function(_reprobit_json_string output value)
  string(REPLACE "\\" "\\\\" escaped "${value}")
  string(REPLACE "\"" "\\\"" escaped "${escaped}")
  string(REPLACE "\n" "\\n" escaped "${escaped}")
  string(REPLACE "\r" "\\r" escaped "${escaped}")
  string(REPLACE "\t" "\\t" escaped "${escaped}")
  set(${output} "\"${escaped}\"" PARENT_SCOPE)
endfunction()

function(_reprobit_json_optional_string output value)
  if("${value}" STREQUAL "")
    set(${output} "null" PARENT_SCOPE)
  else()
    _reprobit_json_string(quoted "${value}")
    set(${output} "${quoted}" PARENT_SCOPE)
  endif()
endfunction()

# Write target metadata at generate time so generator expressions name the
# actual selected artifacts. On a multi-config generator OUTPUT should normally
# include $<CONFIG> to avoid configurations sharing one generated file.
function(reprobit_write_plan)
  cmake_parse_arguments(PARSE_ARGV 0 RB "" "OUTPUT" "")
  if(RB_UNPARSED_ARGUMENTS)
    message(FATAL_ERROR "reprobit_write_plan: unknown arguments: ${RB_UNPARSED_ARGUMENTS}")
  endif()
  if(NOT RB_OUTPUT)
    message(FATAL_ERROR "reprobit_write_plan: OUTPUT is required")
  endif()

  get_property(targets GLOBAL PROPERTY REPROBIT_REGISTERED_TARGETS)
  set(target_json "")
  foreach(target IN LISTS targets)
    get_property(artifact_id TARGET "${target}" PROPERTY REPROBIT_ARTIFACT_ID)
    get_property(output TARGET "${target}" PROPERTY REPROBIT_OUTPUT)
    get_property(pdb TARGET "${target}" PROPERTY REPROBIT_PDB)
    _reprobit_json_string(q_target "${target}")
    _reprobit_json_string(q_artifact "${artifact_id}")
    _reprobit_json_string(q_output "${output}")
    _reprobit_json_optional_string(q_pdb "${pdb}")
    if(target_json)
      string(APPEND target_json ",")
    endif()
    string(APPEND target_json
      "{\"name\":${q_target},\"artifact_id\":${q_artifact},\"output\":${q_output},\"pdb\":${q_pdb}}"
    )
  endforeach()

  get_property(admission_ids GLOBAL PROPERTY REPROBIT_LINK_ADMISSION_IDS)
  set(admission_json "")
  foreach(id IN LISTS admission_ids)
    foreach(field TARGET ARTIFACT_ID OBJECT_PATH INSERTION_INDEX BEFORE AFTER EXPECTED_SYMBOL)
      get_property(value GLOBAL PROPERTY "REPROBIT_ADMISSION_${id}_${field}")
      set("value_${field}" "${value}")
    endforeach()
    _reprobit_json_string(q_id "${id}")
    _reprobit_json_string(q_target "${value_TARGET}")
    _reprobit_json_string(q_artifact "${value_ARTIFACT_ID}")
    _reprobit_json_string(q_object "${value_OBJECT_PATH}")
    if("${value_INSERTION_INDEX}" STREQUAL "")
      set(q_index "null")
    else()
      set(q_index "${value_INSERTION_INDEX}")
    endif()
    _reprobit_json_optional_string(q_before "${value_BEFORE}")
    _reprobit_json_optional_string(q_after "${value_AFTER}")
    _reprobit_json_optional_string(q_symbol "${value_EXPECTED_SYMBOL}")
    if(admission_json)
      string(APPEND admission_json ",")
    endif()
    string(APPEND admission_json
      "{\"id\":${q_id},\"target\":${q_target},\"artifact_id\":${q_artifact},"
      "\"object_path\":${q_object},\"insertion_index\":${q_index},"
      "\"before\":${q_before},\"after\":${q_after},\"expected_symbol\":${q_symbol}}"
    )
  endforeach()

  set(content
    "{\"schema_version\":1,\"targets\":[${target_json}],\"link_admissions\":[${admission_json}]}\n"
  )
  file(GENERATE OUTPUT "${RB_OUTPUT}" CONTENT "${content}")
endfunction()

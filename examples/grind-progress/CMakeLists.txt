cmake_minimum_required(VERSION 3.20)
project(reprobit_grind_progress CXX)

set(CMAKE_CXX_FLAGS "")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/Zi /O2 /Ob1")
set(CMAKE_EXE_LINKER_FLAGS "")
set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "")
set(CMAKE_CXX_STANDARD_LIBRARIES "")

add_executable(grind_progress transform_one.cpp transform_two.cpp)
target_include_directories(grind_progress PRIVATE .)
target_link_options(
  grind_progress
  PRIVATE /nodefaultlib /entry:transform_one /include:_transform_two /subsystem:console
)
set_target_properties(grind_progress PROPERTIES OUTPUT_NAME grind-progress)

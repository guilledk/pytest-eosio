cmake_minimum_required(VERSION 3.8)
project(python_bindings)


set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_subdirectory(libs/pybind11)

add_library(py_eosio MODULE python_bindings.cpp)

find_package(Boost REQUIRED COMPONENTS 
    date_time
    filesystem
    system
    chrono
    iostreams
    unit_test_framework)

target_include_directories(
    py_eosio
    PUBLIC
    ${Boost_INCLUDE_DIRS}
    "../fc/include"
    "../chain/include"
    "../testing/include"
    "../wasm-jit/Include"
    "../chainbase/include"
    "../softfloat/source/include")

target_link_libraries(
    py_eosio
    PUBLIC
    pybind11::module pybind11::lto
    eosio_chain
    fc
    ${ROCKSDB_SHARED_LIB}
    ${Boost_LIBRARIES})


pybind11_extension(py_eosio)
pybind11_strip(py_eosio)

set_target_properties(py_eosio PROPERTIES CXX_VISIBILITY_PRESET "hidden"
                                         CUDA_VISIBILITY_PRESET "hidden")

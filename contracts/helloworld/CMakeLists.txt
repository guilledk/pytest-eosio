cmake_minimum_required(VERSION 3.5)
project(hello_world VERSION 0.1.0)
set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)
include(EosioWasmToolchain)

add_contract(helloworld helloworld helloworld.cpp)

file(GLOB custom_includes ${CUSTOM_INCLUDES_DIR}/*)
target_include_directories(helloworld PUBLIC ${custom_includes})

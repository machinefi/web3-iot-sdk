cmake_minimum_required(VERSION 3.10)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src SRCS)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src/iotex SRCS_IOTEX)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src/port SRCS_PORT)

add_library(iotex_psa_layer ${SRCS} ${SRCS_IOTEX} ${SRCS_PORT})

target_include_directories(iotex_psa_layer
PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

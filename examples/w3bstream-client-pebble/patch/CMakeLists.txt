
zephyr_include_directories(.
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src  SRCS)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src/iotex SRCS_IOTEX)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src/port SRCS_PORT)

target_sources(app PRIVATE ${SRCS} ${SRCS_IOTEX} ${SRCS_PORT})

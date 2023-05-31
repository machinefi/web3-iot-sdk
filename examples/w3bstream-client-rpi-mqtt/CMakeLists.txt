cmake_minimum_required(VERSION 3.15)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/ext/nanopb/extra)
find_package(Mosquitto REQUIRED)
find_package(Nanopb REQUIRED)

nanopb_generate_cpp(PROTO_SRCS PROTO_HDRS package.proto)

set(SOURCES 
    main.cpp
    ${PROTO_SRCS} ${PROTO_HDRS}
)

add_executable(w3bstream-client-rpi-mqtt ${SOURCES})

target_include_directories(w3bstream-client-rpi-mqtt
    PRIVATE ${MOSQUITTO_INCLUDE_DIR}
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    PRIVATE ${NANOPB_INCLUDE_DIRS}
    PRIVATE ext
)

target_link_libraries(w3bstream-client-rpi-mqtt
    PRIVATE ${MOSQUITTO_LIBRARIES}
    PRIVATE ws_iot_sdk
)

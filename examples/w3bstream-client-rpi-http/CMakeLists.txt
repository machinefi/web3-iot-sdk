cmake_minimum_required(VERSION 3.15)

find_package(Python REQUIRED Development)

set(SOURCES 
    main.cpp
)

add_executable(example-w3bstream-client-rpi-http ${SOURCES})

target_link_libraries(example-w3bstream-client-rpi-http
    PRIVATE ws_iot_sdk
    PRIVATE curl
)

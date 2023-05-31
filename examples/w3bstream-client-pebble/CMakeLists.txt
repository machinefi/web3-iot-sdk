#
# Copyright (c) 2018 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

cmake_minimum_required(VERSION 3.8.2)

set(spm_CONF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/spm.conf)


set(PM_STATIC_YML_FILE
  ${CMAKE_CURRENT_SOURCE_DIR}/configuration/${BOARD}/pm_static.yml
  )

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(asset_tracker)
zephyr_compile_definitions(PROJECT_NAME=${PROJECT_NAME})
zephyr_compile_definitions(_POSIX_C_SOURCE=200809L)

# NORDIC SDK APP START
target_sources(app PRIVATE src/main.c)
# Modem
target_sources(app PRIVATE src/modem/modem_helper.c)
# MQTT
target_sources(app PRIVATE src/mqtt/mqtt.c)
# Protbuf
target_sources(app PRIVATE src/nanopb/pb_encode.c)
target_sources(app PRIVATE src/nanopb/pb_decode.c)
target_sources(app PRIVATE src/nanopb/pb_common.c)
target_sources(app PRIVATE src/nanopb/package.pb.c)
# Signature 
target_sources(app PRIVATE src/sign/ecdsa.c)
target_sources(app PRIVATE src/sign/LowerS.c)
zephyr_include_directories(src)

# Include application events and configuration headers
zephyr_library_include_directories(
  src/nanopb
  src/mqtt
  src/wsiotsdk/include
  )

add_subdirectory(../../component/layer subproject/iotex_psa_layer)

# CMake 3.10: Ubuntu 20.04.
# https://cliutils.gitlab.io/modern-cmake/chapters/intro/dodonot.html
cmake_minimum_required(VERSION 3.16) 

include(CMakePrintHelpers)

# Print the toolchain to assist with debugging
cmake_print_variables(CMAKE_CXX_COMPILER)
cmake_print_variables(CMAKE_C_COMPILER)
cmake_print_variables(CMAKE_LINKER)
cmake_print_variables(CMAKE_HOST_SYSTEM_NAME)
cmake_print_variables(CMAKE_SYSTEM_NAME)

project(
  WSIoTSDK
  VERSION 1.0
  LANGUAGES C CXX)

# If you set any CMAKE_ variables, that can go here.
# (But usually don't do this, except maybe for C++ standard)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

# Find packages go here.


# Option declarations go here
set(CRYPTO_IMPL "MbedTLS" CACHE STRING "Crypto implementation")
option(BUILD_IOTEX_F "Build IoTeX Firmware library" ON)
option(BUILD_PSA_TEST_SUITE "Build PSA test suite" OFF)
option(BUILD_PSA_LAYER "Build PSA LAYER" OFF)
option(GIT_SUBMODULE_UPDATE "Update/initialize submodules during build" ON)
option(BUILD_EXAMPLE_WEBSTREAM_RPI_HTTP "Build example: Raspberry Pi w3bstream client using HTTP" OFF)
option(BUILD_EXAMPLE_WEBSTREAM_RPI_MQTT "Build example: Raspberry Pi w3bstream client using MQTT" OFF)

# Print the configuration options to assist with debugging
cmake_print_variables(CRYPTO_IMPL)
cmake_print_variables(BUILD_IOTEX_F)
cmake_print_variables(BUILD_PSA_TEST_SUITE)
cmake_print_variables(BUILD_PSA_LAYER)
cmake_print_variables(BUILD_EXAMPLE_WEBSTREAM_RPI_HTTP)
cmake_print_variables(BUILD_EXAMPLE_WEBSTREAM_RPI_MQTT)
cmake_print_variables(GIT_SUBMODULE_UPDATE)

# Initialize and update the git submodules
if(GIT_SUBMODULE_UPDATE)
  find_package(Git QUIET)
  if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
      message(STATUS "Updating git submodules")
      execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                      RESULT_VARIABLE GIT_SUBMOD_RESULT)
      if(NOT GIT_SUBMOD_RESULT EQUAL "0")
          message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
      endif()
  endif()
endif()

# Create the IoTeX interface target
# The components of the SDK configured by the user will be linked to the ws_iot_sdk target and expose any required include directories
# The executable using the SDK should simply link the ws_iot_sdk target. Eg: target_link_libraries(user_target PRIVATE ws_iot_sdk)
add_library(ws_iot_sdk INTERFACE)

# Conditionally build each of the components based on the cmake configuration options selected
# Add required meta-definitions so any code that requires it an know what components are enabled
if(CRYPTO_IMPL STREQUAL "MbedTLS")
  add_subdirectory(component/crypto/mbedtls)
  add_definitions(-DCRYPTO_IMPLEMENTATION="MbedTLS")
  add_definitions(-DCRYPTO_IMPLEMENTATION_MBEDTLS)
endif()

if(CRYPTO_IMPL STREQUAL "TinyCrypt")
  add_subdirectory(component/crypto/tinycrypt)
  add_definitions(-DCRYPTO_IMPLEMENTATION="TinyCrypt")
  add_definitions(-DCRYPTO_IMPLEMENTATION_TINYCRYPT)
  add_definitions(-DTFM_CRYPTO_KEY_DERIVATION_MODULE_DISABLED)
endif()

if(BUILD_IOTEX_F)
  add_subdirectory(component/services/iotex-f)
  target_link_libraries(ws_iot_sdk
    INTERFACE iotex_tf
  )
  target_include_directories(ws_iot_sdk 
    INTERFACE include
    )
endif()

if(BUILD_PSA_TEST_SUITE)
  SET(TARGET "tgt_dev_apis_stdc")
  SET(SUITE "CRYPTO")
  SET(TOOLCHAIN "HOST_GCC")
  SET(PSA_INCLUDE_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/include;${CMAKE_CURRENT_SOURCE_DIR}/include/psa")
  SET(PSA_CRYPTO_LIB_FILENAME "ws_iot_sdk")
  # SET(VERBOSE 5)
  add_subdirectory(test/iotex-psa/api-tests)
endif()

if(BUILD_PSA_LAYER)
  add_subdirectory(component/layer)
endif()




# Conditionally build examples based on the cmake configuration options selected

if (BUILD_EXAMPLE_WEBSTREAM_RPI_HTTP)
  add_subdirectory(examples/w3bstream-client-rpi-http)
endif()

if (BUILD_EXAMPLE_WEBSTREAM_RPI_MQTT)
  add_subdirectory(examples/w3bstream-client-rpi-mqtt)
endif()

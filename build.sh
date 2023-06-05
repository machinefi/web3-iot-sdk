#!/bin/bash

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    --example)
      example_name="$2"
      shift # past argument
      shift # past value
      ;;
    *) 
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

mkdir build-out

# Verify example name
if [[ -z $example_name ]]; then
  echo "example name not specified. Usage: ./build.sh --example <http/mqtt>"
  exit 1
fi

# Verify example name is valid
if [[ $example_name != "http" && $example_name != "mqtt" ]]; then
  echo "Invalid example name. Please choose either 'http' or 'mqtt'."
  exit 1
fi

# Run CMake configure and build
if [[ $example_name == "http" ]]; then
    echo "Building HTTP example"
    cmake -DBUILD_EXAMPLE_WEBSTREAM_RPI_HTTP=ON -DGIT_SUBMODULE_UPDATE=ON -S ./ -B ./build-out
    cmake --build build-out --target example-w3bstream-client-rpi-http
    cp ./build-out/examples/w3bstream-client-rpi-http/example-w3bstream-client-rpi-http w3bstream-example
fi

if [[ $example_name == "mqtt" ]]; then
    echo "Building MQTT example"
    cmake -DBUILD_EXAMPLE_WEBSTREAM_RPI_MQTT=ON -DGIT_SUBMODULE_UPDATE=ON -S ./ -B ./build-out
    cmake --build build-out --target example-w3bstream-client-rpi-mqtt
    cp ./build-out/examples/w3bstream-client-rpi-mqtt/example-w3bstream-client-rpi-mqtt w3bstream-example
fi

exit 0
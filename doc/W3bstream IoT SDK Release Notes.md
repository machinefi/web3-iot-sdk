# W3bstream IoT SDK v1.0.0 Release Notes

The W3bstream IoT SDK (_WSIoTSDK_ for short) is an open source project developed and maintained by IoTeX. The primary goal of _WSIoTSDK_ is to connect a wide range of IoT devices (e.g., smart sensors, smart watches, car dongles, etc.) and community-driven development boards (e.g., Raspberry Pi, Arduino, ESP32, etc.) to a network of decentralized W3bStream nodes for unlocking emerging trillion-dollar machine economy. _WSIoTSDK_ is an essential component of the IoTeX's W3bStream framework.

## Summary of latest changes

- Added support for Raspberry Pi 4B and Pebble Tracker.
- Added support for compiling and testing on Windows, Linux and MacOS.
- Added support for cmake cross-platform tools.
- Added support for flexible configuration.

| Note                                                         |
| ------------------------------------------------------------ |
| See the changelog and readme files in the component repositories for a detailed description of changes. |

## Components

| Component          | version |
| ------------------ | ------- |
| mbedtls            | 3.2.1   |
| trusted-firmware-m | 1.6.0   |



## Supported boards

- Raspberry Pi 4B
- Pebble Tracker (Nordic's nRF9160 SiP)
- Linux
- OS X - limited support

## Changelog

The following sections provide detailed lists of changes.

### Cryptographic

- Integrated trusted-firmware-m (TF-M) and mbedtls components for secure world and non-secure world
- Added iotex-firmware component for single nonsecure zone
- Added PSA abstraction layer for Pebble Tracker

### Sample Files

- Added header file **iotex_layer_config_default.h** in layer/include/example directory.
- Added header file **iotex_layer_config_pebble.h** in layer/include/example directory.
- Added porting file **psa_crypto_porting_for_mbedtls_default.c** in layer/src/example directory.
- Added porting file **psa_crypto_porting_for_pebble.c** in layer/src/example directory.

### PSA Cryptography API

- Added support PSA Cryptographic API 1.1

### Test

- Integrated PSA Certified APIs Architecture Test Suite

### Documentation

- Created documentation **iotex_sdk_getting_started.rst** in doc/ directory.
- Created documentation **iotex_sdk_bug_list.rst** in doc directory.
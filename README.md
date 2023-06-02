# Web3 IoT SDK

The Web3 IoT SDK (_Web3IoTSDK_ for short) is an open source project developed and maintained by IoTeX. The primary goal of _Web3IoTSDK_ is to connect a wide range of IoT devices (e.g., smart sensors, smart watches, car dongles, etc.) and community-driven development boards (e.g., Raspberry Pi, Arduino, ESP32, etc.) to Web3 applications, thereby enabling developers to unlock emerging trillion-dollar machine economy. Moreover, _Web3IoTSDK_ is also an essential component of the IoTeX's [W3bstream](https://w3bstream.com/) framework for connecting smart devices to smart contracts.    

## Technical Goals

_Web3IoTSDK_ is designed with the following technical objectives in mind:

* **Openness**: _Web3IoTSDK_ is completely open-source and contributions from IoT communities are highly encouraged.
* **Trustworthiness**: _Web3IoTSDK_ is implemented by following industry-standard security best practices and recommended application programming interfaces (APIs).
* **Modularity**: _Web3IoTSDK_ is designed using a modular architecture, allowing for flexible extensions and customization to accommodate a wide range of IoT devices with varying processing capabilities.
* **Enterprise Readiness**: _Web3IoTSDK_ is designed to meet the stringent performance and certification requirements of enterprise applications with respect to integration.

## Business Goals

_Web3IoTSDK_ is designed by keeping the following business objectives in mind:

* _Web3IoTSDK_ is going to enable small and medium size IoT device manufacturers and solution providers to join the Web3 evolution and unlock new business opportunities.
* _Web3IoTSDK_ is going to facilitate IoT developers to build innovative Web3 applications for emerging machine economy.
* _Web3IoTSDK_ is going to pave the way for adoption by large IoT businesses and and ultimately drive Web3-based digital transformation.

## Technical Framework

![image](https://github.com/machinefi/web3-iot-sdk/blob/main/doc/img/Overview.png)

The design of _Web3IoTSDK_ follows a layered approach, comprising of five layers, from top to bottom: the DIDComm messaging layer, the identity and credential layer, the cryptographic service layer, the cryptographic primitive layer, and the root of trust layer. Each layer consists of multiple components in the _Web3IoTSDK_, enabling developers to customize the SDK flexibly to meet hardware constraints and application requirements.

The five components in the cryptographic service layer and cryptographic primitive layer are shown below and each component may contain a number of sub-components.  

![image](https://github.com/machinefi/web3-iot-sdk/blob/main/doc/img/SDK.png)

* Cryptographic Services：These sub-components that realize services such as key management, secure storage, audit logging, etc.

* Cryptographic Primitives：These sub-components contain cryptography libraries suitable for various embedded devices.

* PSA Abstraction Layer (PSA_AL)：This sub-layer provides the PSA abstraction and API-level support.

* Hardware Abstraction Layer (HAL)：This sub-layer provides hardware abstraction for various embedded platforms.

* Support Components (pink area)：These sub-components provide functionalities for configuration, compilation and testing of the entire SDK.

In practice, developers are able to customize _Web3IoTSDK_ to meet their requirements by selecting proper sub-components from one or multiple components above. Note that each sub-component in the above figure is marked with a color and sub-components with the same color could be used as a specific customization of _Web3IoTSDK_. Here we provide some customization examples below.

  1. Iotex Firmware + MbedTLS + Hardware Acceleration: This combination is suitable for embedded platforms that do not support TrustZone&reg;, e.g., Raspberry Pi. In this mode, users can use the complete PSA APIs to implement cryptographic operations.  

  2. TF-M + MbedTLS + Hardware CryptoLib: This combination is suitable for Cortex-M  series MCUs with TrustZone&reg; support (e.g., Cortex-M23/M33/M55).  

  3. Iotex Firmware + TinyCrypt: This combination is suitable for embedded platforms with highly constrained hardware resoruces (e.g., low-end Arduino boards). In this case, users need to customize _Web3IoTSDK_ for addressing specific hardware resource challenges.

In _Web3IoTSDK_, the componnets in the PSA abstraction layer (PSA_AL) are shown in the figure below.

![image](https://github.com/machinefi/web3-iot-sdk/blob/main/doc/img/PAL.png)

_Web3IoTSDK_ has been designed to be modular and easily expandable through the use of different cryptographic libraries. To facilitate this, the cryptographic functions used in the SDK have been encapsulated in a cryptographic module. All interaction with the cryptographic module should be done via the industry standardised PSA API. This allows for decoupling bewteen the crypto backend and the rest of the components of the SDK.  
Currently the only supported cryptographic library by Iotex Firmware is MbedTLS 3.2.1. However, other libraries are planned to be supported in the near future, such as TinyCrypt. In the case of TinyCrypt, the library will need to be integrated with the SDK through a PSA abstraction layer. IoTeX will provide this PSA abstraction layer.
Theoretically, any other cryptographic library could be integrated with _Web3IoTSDK_, as long as a PSA abstraction layer is provided for it. If any third party contributors are willing to port other libraries to _Web3IoTSDK_, their contribution will be highly appreciated..

## Key Product Features

### Unified Framework

_Web3IoTSDK_ provides a unified code implementation and standardized interface abstraction. As a result, developers only need to call the standard PSA APIs when using _Web3IoTSDK_ for performing cryptographic operations, thereby significantly reducing the maintenance costs for interacting with various cryptographic libraries. Moreover, _Web3IoTSDK_ supports multiple operating systems such as Windows, Linux, and macOS, which facilitates developers to complete fast development and integration.

### Flexible Configuration

The design and development of _Web3IoTSDK_ adopt a "layer-component-subcomponent" methodology in which communications among components are based on standard interfaces. Such an approach effectiely reduces coupling between layers and components and enables developers to choose sub-components via configuration files to meet the requirements of various applications and development environments.

### High Reliability

The rich sub-components in _Web3IoTSDK_ are popular open-source software and the updates of which are maintained by IoTeX. Hence developers do not need to update those sub-components separately and just recompile _Web3IoTSDK_ to get the latest version. Moreover, _Web3IoTSDK_ provides complete test cases for PSA APIs and integrates PSA Certified APIs Architecture Test Suite for testing on multiple operating system platforms and embedded devices.

## File Structure

The following figure is an example of the current _Web3IoTSDK_ file structure:

| Directory | Sub directory | Description                                  |
| :-------- | ------------- | ---------------------------------------------|
| component | crypto        | The cryptographic primitive sub-component    |
|           | layer         | The code for the Pebble Tracker PSA abstraction layer       |
|           | services      | The cryptographic service sub-component      |
| doc       |               | The documentation of _WSIoTSDK_             |
| include   |               | The user facing header files   |
| test      |               | The complete PSA API test routines           |
| examples  |               | _WSIoTSDK_ usage examples         |

## Quick Start

### Prerequisites

_WSIoTSDK_ provides a reference implementation of the ARM Platform Security Architecture API.  
It is assumed that the reader is familiar with the specification, that can be found at [Platform Security Architecture Resources](https://developer.arm.com/architectures/security-architectures/platform-security-architecture).

### Set up the build environment

Iotex SDK officially supports a limited set of build environments and setups. In this context, official support means that the
environments listed below are actively used by team members and active developers, hence users should be able to recreate the same
configurations by following the instructions described below.  
In case of problems, the Iotex SDK team provides support only for these environments, but building in other environments can still be possible.  

The following environments are supported:

#### Docker container (Ubuntu 22.04)

Install the VSCode [Remote: Dev containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers).  
Open the repository inside VSCode and click the "Open Workspace in Container" pop up that appears. More info on using dev containers in VSCode in the [VSCode documentation](https://code.visualstudio.com/docs/devcontainers/containers#_open-an-existing-workspace-in-a-container).  

#### Linux (Ubuntu 18.04 or 22.04)

Run the following command to install the required dependencies:  

```bash
sudo apt-get install -y cmake git curl wget build-essential libssl-dev python3
```

#### Windows 11 x64

Install the following dependencies:  

* Git client: <https://git-scm.com/download/win>
* CMake: <https://cmake.org/download/>
* MinGW32: <https://sourceforge.net/projects/mingw-w64/files/>
* Python3 and pip (included by default): <https://www.python.org/downloads/>

### Get the source code

Run the following command to clone the repository:  

```bash
git clone https://github.com/machinefi/web3-iot-sdk.git
```

### Build

The build process is managed by CMake. The build can be customized by passing CMake options.  
Below is a description of the most common ones. For a full list of CMake options see the main [CMakeLists.txt](https://github.com/machinefi/web3-iot-sdk/blob/main/CMakeLists.txt):

* **CRYPTO_IMPL:** the crypto library to use. Possible values: "MbedTLS" or "TinyCrypt". Defaults to "MbedTLS".  Note that TinyCrypt is not supported yet.
* **BUILD_IOTEX_F:** build the Iotex Firmware component. Defaults to ON.
* **BUILD_PSA_TEST_SUITE:** build the PSA Architecture test suite. Defaults to OFF.
* **BUILD_EXAMPLE_DEVICE_REGISTRATION:** build the device registration example. Defaults to OFF.
* **GIT_SUBMODULE_UPDATE:**  download or update any dependencies specified as submodules. Defaults to ON.

For example, if you want to build the SDK using Iotex Firmware + MbedTLS * PSA test suite, you can run the following commands:  

```bash
# Configure the build components and place the output in ./build-out
cmake -DGIT_SUBMODULE_UPDATE=ON -DBUILD_IOTEX_F=ON -DCRYPTO_IMPL="MbedTLS" -DBUILD_PSA_TEST_SUITE=ON -S ./ -B ./build-out
# Compile all targets
cmake --build build-out --target all
```

Once the build finishes, you can run the tests executable using the following command:  

```bash
./build-out/test/iotex-psa/api-tests/psa-arch-tests-crypto
```

You should see output similar to the one below:  

```bash
...
******************************************

TEST: 260 | DESCRIPTION: Testing crypto AEAD APIs | UT: psa_aead_abort
[Info] Executing tests from non-secure
[Check 1] Test psa_aead_abort - Encrypt - CCM - AES
[Check 2] Test psa_aead_abort - Encrypt - GCM - AES
[Check 3] Test psa_aead_abort - Decrypt - CCM - AES
[Check 4] Test psa_aead_abort - Decrypt - GCM - AES
[Check 5] Test psa_aead_abort with all initializations

TEST RESULT: PASSED

******************************************

......

************ Crypto Suite Report **********
TOTAL TESTS     : 63
TOTAL PASSED    : 61
TOTAL SIM ERROR : 0
TOTAL FAILED    : 0
TOTAL SKIPPED   : 2
******************************************
```

### Examples

Examples to demonstrate the usage of the SDK can be found at [examples](https://github.com/machinefi/web3-iot-sdk/tree/main/examples). Each example contains a README file with usage instructions.  

## Development Boards

_Web3IoTSDK_ has been tested and used to build applications on a number of development boards, including 
* [Raspberry Pi](https://github.com/machinefi/web3-iot-sdk/tree/main/examples)
* [Pebble Tracker](https://github.com/machinefi/web3-iot-sdk/tree/main/examples)
* [ESP32](https://github.com/machinefi/w3bstream-client-esp32/) 
* Arduino (coming soon)   

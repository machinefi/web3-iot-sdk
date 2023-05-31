# Pebble Connection devnet Example

This example demonstrates how the Pebble Tracker connects to devnet, signs and uploads data.

## Requirements

### Install Protobuf

* Windows 
Download and install protobuf [here](https://github.com/protocolbuffers/protobuf/releases)

* Linux

```bash
# Make sure the protoc version is v3.6.0+
apt install protobuf-compiler
# Check the protoc version after installation
protoc --version
```

## Configuration source code

  1. Download code:

 * Download the Pebble Tracker source code

[Walk-to-earn Step-by-step Guide for Developers (larksuite.com)](https://iotex.larksuite.com/docs/docusyYoj4NNh481G3zvua3em1d#Ectsgi) 

 * Download w3bstream-client-pebble
      ```bash
      git clone https://github.com/machinefi/web3-iot-sdk.git
      ```
  2. Compile wasm
     
     First you need to install the rust development environment, you can refer to [here](https://datawithrust.com/chapter_2/chapter_2_1.html).

     ```bash
      rustup target add  wasm32-wasi
      cd w3bstream-client-pebble/tools/wasm/pebble_test/
      make

     ```
     The pebble_test.wasm file will be generated in the w3bstream-client-pebble/tools/wasm/pebble_test/target/wasm32-wasi/release directory after compilation.

  3. Create a project in w3bstream devenet

     You can create a project in [w3bstream devnet](https://devnet-staging.w3bstream.com) called "pebble_test" (or any other name). Get topic from w3bstream trigger tab(in the green marker box).Modify the value of the "W3BSTREAM_PUB_DATA_TOPIC" variable in web3-iot-sdk/examples/w3bstream-client-pebble/src/mqtt/mqtt.c file.
     eg.
      ```C
      // Topic of publish data to the w3bstream
      #define  W3BSTREAM_PUB_DATA_TOPIC     "eth_0xf77f8de24194d768012ca1edd15aee0b33d919a1_pebble_test"
      ```
      ![topic](doc/topic.jpg)

  4. Upload  wasm file

     Click "Create Instance" to upload the "pebble_test.wasm" file(in the green marker box) generated in step 2.
     ![upload_wasm](doc/upload_wasm.jpg)


  5. Create device

     Add a device in w3bstream devnet Devices tab, and copy the token to the "W3BSTREAM_DEV_TOKEN" variable in web3-iot-sdk/examples/w3bstream-client-pebble/src/mqtt/mqtt.c file.
     eg.

     ```C
      // token of w3bstream
      #define  W3BSTREAM_DEV_TOKEN   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQYXlsb2FkIjoiOTAyNjczMTQyMjAyODgwOCIsImlzcyI6InczYnN0cmVhbSJ9.-M0umqdSsvA06so-iF6SSrC3yBj6uk1tswOhZ-Z9-cA"
     ```
     ![device](doc/device.jpg)
  
  6. Edit Event Routing
  
     Create "Event Routing"  in the w3bstream devnet "Triggers" page like this (in the green marker box):
     Event Type:  PEBBLE
     handler:  start_pebble

     ![routing](doc/routing.jpg)

  7. Configure mqtt host and port
     
     Get mqtt host and port from w3bstream trigger tab(in the green marker box).

     ![broker](doc/broker.jpg)
     
     Modify "W3BSTREAM_BROKER_HOST" and "W3BSTREAM_BROKER_PORT"  variables in web3-iot-sdk/examples/w3bstream-client-pebble/src/mqtt/mqtt.c file to configure the mqtt host and port.

     ```c
      // mqtt broker  host and port 
      #define  W3BSTREAM_BROKER_HOST     "devnet-staging.w3bstream.com"
      #define  W3BSTREAM_BROKER_PORT        1883
     ```

  8. Configure database

    Create a new table named "pebble" and add two columns named snr and timestamp to the w3bstream devnet data tab and select integer as the data type.

    The page looks like this after the table is created.

   ![data_base_01](doc/data_base_01.png)

   9. Route Cryptographic operations through the IoT SDK

    Replace "pebble-firmware/nrf/samples/spm/src/CryptoCell.c" with  "web3-iot-sdk/examples/w3bstream-client-pebble/patch/CryptoCell.c".

    Replace "web3-iot-sdk/component/layer/CMakeLists.txt" with  "web3-iot-sdk/examples/w3bstream-client-pebble/patch/CMakeLists.txt".


   The 'pebble-firmware' is our custom Nordic-nrf-sdk, downloaded in the first step([Walk-to-earn Step-by-step Guide for Developers (larksuite.com)](https://iotex.larksuite.com/docs/docusyYoj4NNh481G3zvua3em1d#Ectsgi) ) above.


## Compile with VS Code

1. Install **nRF Connect for Code Extension Pack** in VS Code.

2. Access the Welcome page by one of the following:

   - Clicking on the nRF Connect for VS Code icon to the left in VS Code.

   - Open the Welcome Page by clicking Open Welcome page.

   - Using the nRF Connect: Welcome command available in the Command Palette.(Ctrl+Shift+P` or `⇧+⌘+P)

3. Set the default nRF Connect SDK and nRF Connect Toolchain in the Quick Setup feature located on the extension's Welcome page.

   - You can browse to your manual installations using the **Browse...** option.

4. Select **Add an existing application to workspace...**

   - Locate the **Riverrock** folder.

## Add public key to wasm

### Get public key

- Download program to pebble and power it on 
- Connect the pebble debug serial port to the computer
- Get the public key from the serial port log

![routing](doc/pubkey.jpg)


### Copy the public key to wasm

Copy public key(hex string) to the "pebble_pub_key" variable in the web3-iot-sdk/tools/wasm/pebble_test/src/lib.rs file. Recompile pebble_test and upload the pebble_test.wasm file in the w3bstream devnet settings tab. 

```rust
    let pebble_pub_key: &str = "044ea9fa6257aed7800b679cd7087c9a9ed589f57f83923575ce52ecc501d6d6a16d6153bc55d8888aca8fe7bfe612e23b1e95ab034a7ced05f5f2f910e7315ed1";
```

## Running example

Download program to pebble and power it on.Pebble will send data to devnet once every 5s.

Now you can see the uploaded data in the w3bstream data tab.
![data_base_02](doc/data_base_02.png)


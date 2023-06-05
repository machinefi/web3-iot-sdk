# W3bstream IoT SDK MachineFi portal registration example

The program demonstrates how to send data from Raspberry Pi to the w3bstream network. The example can also be run in other Unix like Operating Systems, such as Ubuntu and OS X.  

## Requirements

Ensure your system meets the following requirements before building and runnning the program.  

### Build toolchain

CMake along with gcc or clang is used to build the SDK and examples.  

Run the following command to install the required build toolchain on Raspberry Pi or debian based systems:  

```bash
apt-get install cmake build-essential
```  

Run the following command to install the required build toolchain on OS X:  

```bash
brew install cmake
xcode-select --install
```

## Building this example

Run the following command to clone the repository:  

```bash
git clone https://github.com/machinefi/web3-iot-sdk.git
```

Change directory to the repository root folder:  

```bash
cd web3-iot-sdk
```

Run the cmake configure command and enable the `BUILD_EXAMPLE_WEBSTREAM_RPI_HTTP` and `GIT_SUBMODULE_UPDATE` options. Enabling `GIT_SUBMODULE_UPDATE` ensures the the dependencies are downloaded:  

```bash
cmake -DBUILD_EXAMPLE_WEBSTREAM_RPI_HTTP=ON -DGIT_SUBMODULE_UPDATE=ON -S ./ -B ./build-out
cmake --build build-out --target example-w3bstream-client-rpi-http
```

If everything went correctly, you should see a something along the lines of:  

```bash
[100%] Built target example-w3bstream-client-rpi-http
```

The build output will be placed inside the `build-out` directory.  

## Running this example

Change directory to `build-out` and give execution permission to the executable:  

```bash
cd build-out/examples/w3bstream-client-rpi-http
chmod +x example-w3bstream-client-rpi-http
```

Run the executable with the `-h` output to see a description on how to use it:  

```bash
./w3bstream-client-rpi-http -h
```

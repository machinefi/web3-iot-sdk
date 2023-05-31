#include <algorithm>
#include <cstdio>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <mosquitto.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <time.h>
#include <unistd.h>
#define _BSD_SOURCE
#include <sys/time.h>

#include "package.pb.h"
#include "pb_encode.h"

// Include the main header for the W3bstream IoT SDK.
#include "psa/crypto.h"

// Custom types.
enum ResultCode {
    SUCCESS,
    ERROR,
    ERR_PROTOBUF_ENCODE,
    ERR_MQTT,
    ERR_FILE_READ,
    ERR_PSA,
    ERR_JSON,
};
namespace {

// The publisher token.
std::string w3bstream_token = "";
// The publisher topic
std::string w3bstream_topic = "";

// MQTT details.
const std::string broker_address = "devnet-staging.w3bstream.com";
const int broker_port = 1883;

// Key store details.
std::string keystore_path = "";
std::string private_key_path = "";
std::string public_key_path = "";

// Constants.
const size_t private_key_size = 32;
const size_t private_key_size_bits = private_key_size * 8;
const size_t public_key_size = 65;
const size_t data_buffer_size = 2048;

// Variables to hold global state, etc.
mosquitto *client = nullptr;
psa_key_id_t key_id;
} // namespace

static ResultCode sign_message(psa_key_id_t key_id, const uint8_t msg[], size_t msg_size, uint8_t buf[], size_t buf_size, size_t *signature_len);

static void bin_to_hex_string(char *bin, unsigned int bin_len, char *str) {
    uint8_t hex_map[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    int i;
    for (i = 0; i < bin_len; i++) {
        str[2 * i] = hex_map[bin[i] >> 4];
        str[2 * i + 1] = hex_map[bin[i] & 0x0f];
    }
}

static char *build_message(psa_key_id_t key_id, unsigned int *len) {
    int i;
    uint8_t signature[65] = {0};
    size_t signature_length = 0;
    uint32_t uint_timestamp;
    char random_bin[8];
    struct timeval tv;
    BinaryPackage binary_package = BinaryPackage_init_zero;
    SensorData sensor_data = SensorData_init_zero;
    Event w3bstream_event = Event_init_zero;
    int gyroscope[3] = {-2658, 9, 11};
    int accelerometer[3] = {2658, 3835, 3326};

    strcpy(w3bstream_event.header.event_type, "RASPI");
    strcpy(w3bstream_event.header.token, w3bstream_token.c_str());
    strcpy(w3bstream_event.header.pub_id, "Test");

    /* Snr */
    sensor_data.snr = 95;
    /* Vbat */
    sensor_data.vbat = 332;
    /* GPS */
    sensor_data.latitude = 2000000000;
    sensor_data.longitude = 2000000000;
    /* Env sensor gas */
    sensor_data.gasResistance = 6137;
    /* Env sensor temperature */
    sensor_data.temperature = 3508;
    sensor_data.temperature2 = 3508;
    /* Env sensor pressure */
    sensor_data.pressure = 26274;
    /* Env sensor humidity */
    sensor_data.humidity = 4515;
    /* Env sensor light */
    sensor_data.light = 2035;
    /* Action sensor gyroscope data */
    for (i = 0; i < sizeof(gyroscope) / sizeof(int); i++) {
        sensor_data.gyroscope[i] = (int32_t)(gyroscope[i]);
    }
    /* Action sensor accelerometer */
    for (i = 0; i < sizeof(accelerometer) / sizeof(int); i++) {
        sensor_data.accelerometer[i] = (int32_t)(accelerometer[i]);
    }
    /* Add timestamp */
    gettimeofday(&tv, NULL);
    uint_timestamp = tv.tv_sec;
    w3bstream_event.header.pub_time = uint_timestamp;

    /*  Get random number */
    sensor_data.random[sizeof(sensor_data.random) - 1] = 0;
    psa_status_t status = psa_generate_random((uint8_t *)random_bin, 8);
    bin_to_hex_string(random_bin, sizeof(random_bin), sensor_data.random);
    pb_ostream_t enc_datastream;
    enc_datastream = pb_ostream_from_buffer(binary_package.data.bytes, sizeof(binary_package.data.bytes));
    if (!pb_encode(&enc_datastream, SensorData_fields, &sensor_data)) {
        std::cerr << "Failed to encode sensora:" << PB_GET_ERROR(&enc_datastream) << std::endl;
        return 0;
    }
    pb_byte_t *data = (pb_byte_t *)malloc(data_buffer_size);

    binary_package.data.size = enc_datastream.bytes_written;
    binary_package.data.bytes[enc_datastream.bytes_written] = (char)((uint_timestamp & 0xFF000000) >> 24);
    binary_package.data.bytes[enc_datastream.bytes_written + 1] = (char)((uint_timestamp & 0x00FF0000) >> 16);
    binary_package.data.bytes[enc_datastream.bytes_written + 2] = (char)((uint_timestamp & 0x0000FF00) >> 8);
    binary_package.data.bytes[enc_datastream.bytes_written + 3] = (char)(uint_timestamp & 0x000000FF);
    *(uint32_t *)data = BinaryPackage_PackageType_DATA;
    memcpy((uint8_t *)data + 4, binary_package.data.bytes, enc_datastream.bytes_written + 4);

    std::cout << "Data to be signed :" << std::endl;
    for (int i = 0; i < enc_datastream.bytes_written + 8; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(*(uint8_t *)((uint8_t *)data + i)) << " ";
    }
    std::cout << std::endl;

    int res = sign_message(key_id, (const uint8_t *)data, enc_datastream.bytes_written + 8, signature, sizeof(signature), &signature_length);
    if (res != ResultCode::SUCCESS) {
        return 0;
    }

    std::cout << "Signature :" << std::endl;
    for (int i = 0; i < 64; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(*(uint8_t *)((uint8_t *)signature + i)) << " ";
    }
    std::cout << std::endl;


    std::cout << "binary_package.data.size :" << binary_package.data.size << std::endl;
    memcpy(binary_package.signature, signature, 64);
    binary_package.timestamp = uint_timestamp;
    binary_package.type = BinaryPackage_PackageType_DATA;
    pb_ostream_t enc_packstream;
    enc_packstream = pb_ostream_from_buffer(w3bstream_event.payload.bytes, sizeof(w3bstream_event.payload.bytes));
    if (!pb_encode(&enc_packstream, BinaryPackage_fields, &binary_package)) {
        std::cerr << "Failed to encode binaryage" << std::endl;
        return 0;
    }
    w3bstream_event.payload.size = enc_packstream.bytes_written;
    std::cout << "w3bstream_event.payload.size :" << w3bstream_event.payload.size << std::endl;

    pb_ostream_t stream = pb_ostream_from_buffer(data, data_buffer_size);
    if (!pb_encode(&stream, Event_fields, &w3bstream_event)) {
        std::cerr << "Failed to encode Event: " << PB_GET_ERROR(&stream) << std::endl;
        return 0;
    }
    *len = stream.bytes_written;
    std::cout << "stream.bytes_written :" << stream.bytes_written << std::endl;
    return (char *)data;
}

// Function definitions.
static ResultCode sign_message(psa_key_id_t key_id, const uint8_t msg[], size_t msg_size, uint8_t buf[], size_t buf_size, size_t *signature_len) {
    psa_status_t status = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, msg_size, buf, buf_size, signature_len);
    if (status != PSA_SUCCESS) {
        std::cout << "Failed to sign message: " << status << std::endl;
        return ResultCode::ERR_PSA;
    }

    status = psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, msg_size, buf, *signature_len);
    if (status != PSA_SUCCESS) {
        std::cout << "Failed to sign message: " << status << std::endl;
        return ResultCode::ERR_PSA;
    }
    return ResultCode::SUCCESS;
}

static void mqtt_disconnect_callback(struct mosquitto *mosquitto, void *obj, int rc) {
    std::cout << "Disconnected from mqtt broker" << std::endl;
    // NOTE: reconnection should be retried after a disconnection is detected
    // For the purpose of keeping this example as simple as possible the program
    // simply exits with an error.
    exit(-1);
}

void mqtt_connect_callback(struct mosquitto *mosquitto, void *unused, int result) {
    if (result) {
        std::cerr << "Mqtt connection failed: " << result << std::endl;
        // NOTE: the connection should be retried on failure
        // For the purpose of keeping this example as simple as possible the
        // program simply exits with an error.
        exit(-1);
    }

    std::cout << "MQTT connect successful " << std::endl;
}

static ResultCode mqtt_connect() {
    // Initialize the Mosquitto library.
    int mosquitto_result = mosquitto_lib_init();
    if (mosquitto_result != MOSQ_ERR_SUCCESS) {
        std::cerr << "Error: Unable to create Mosquitto client." << std::endl;
        return ResultCode::ERR_MQTT;
    }

    // Create a new Mosquitto client.
    client = mosquitto_new(nullptr, true, nullptr);
    if (!client) {
        std::cerr << "Error: Failed to create Mosquitto client." << std::endl;
        return ResultCode::ERR_MQTT;
    }

    // Set Mosquitto event callbacks.
    mosquitto_connect_callback_set(client, mqtt_connect_callback);
    mosquitto_disconnect_callback_set(client, mqtt_disconnect_callback);

    // Connect to the broker.
    std::cout << "Connecting to the broker at " << broker_address << " ..." << std::endl;
    mosquitto_result = mosquitto_connect(client, broker_address.c_str(), broker_port, 60);
    if (mosquitto_result != MOSQ_ERR_SUCCESS) {
        std::cerr << "Error: Unable to connect to the broker." << std::endl;
        return ResultCode::ERR_MQTT;
    }

    // Start the mosquitto loop.
    mosquitto_result = mosquitto_loop_start(client);
    if (mosquitto_result != MOSQ_ERR_SUCCESS) {
        std::cerr << "Error: Unable to start mosquitto loop." << std::endl;
        return ResultCode::ERR_MQTT;
    }

    std::cout << "Successfully connnected to the MQTT broker." << std::endl;
    return ResultCode::SUCCESS;
}

static ResultCode generate_key(const char *key_path, const char *public_key_path) {
    std::cout << "Generating a new key." << std::endl;

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
    psa_set_key_bits(&attributes, private_key_size_bits);
    auto status = psa_generate_key(&attributes, &key_id);
    if (status != PSA_SUCCESS) {
        std::cerr << "Failed to generate key: " << status << std::endl;
        return ResultCode::ERR_PSA;
    }

    // Export the private key from the PSA API slot and save it to a file.
    static uint8_t exported_private_key[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(private_key_size_bits)] = {0};
    size_t exported_private_key_len = 0;
    status = psa_export_key(key_id, exported_private_key, sizeof(exported_private_key), &exported_private_key_len);
    if (status != PSA_SUCCESS) {
        std::cerr << "Failed to export private key: " << status << std::endl;
        return ResultCode::ERR_PSA;
    }
    std::cout << "Exported private key: ";
    for (int i = 0; i < exported_private_key_len; i++) {
        printf("%x", exported_private_key[i]);
    }
    std::cout << std::endl;
    std::cout << "Saving private key to " << private_key_path << std::endl;
    int fd = open(private_key_path.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd == -1) {
        std::cout << "Failed to open private key file: " << private_key_path << std::endl;
        return ResultCode::ERR_FILE_READ;
    }
    write(fd, exported_private_key, exported_private_key_len);
    close(fd);

    // Export the public key from the PSA API slot and save it to a file.
    uint8_t exported_public_key[public_key_size] = {0};
    size_t exported_public_key_len = 0;
    status = psa_export_public_key(key_id, exported_public_key, sizeof(exported_public_key), &exported_public_key_len);
    if (status != PSA_SUCCESS) {
        std::cerr << "Failed to export public key: " << status << std::endl;
        return ResultCode::ERR_PSA;
    }
    std::cout << "Exported public key: ";
    for (int i = 0; i < exported_public_key_len; i++) {
        printf("%x", exported_public_key[i]);
    }
    std::cout << std::endl;
    std::cout << "Saving private key to " << public_key_path << std::endl;
    fd = open(public_key_path, O_RDWR | O_CREAT, 0600);
    if (fd == -1) {
        std::cout << "Failed to open public key file: " << public_key_path << std::endl;
        return ResultCode::ERR_FILE_READ;
    }
    write(fd, exported_public_key, exported_public_key_len);
    close(fd);

    std::cout << "Key generated successfully." << std::endl;
    return ResultCode::SUCCESS;
}

static ResultCode import_key(const char *key_path, const char *public_key_path, psa_key_id_t *key_id) {
    int fd = open(key_path, O_RDWR);
    if (fd == -1) {
        ResultCode res = generate_key(key_path, public_key_path);
        if (res != ResultCode::SUCCESS) {
            return res;
        }

        fd = open(key_path, O_RDWR);
        if (fd == -1) {
            std::cout << "Failed to open key file: " << key_path << std::endl;
            return ResultCode::ERR_FILE_READ;
        }
    }

    // Import the key from the file into the PSA API slot.
    uint8_t exported_private_key[private_key_size] = {0};
    size_t exported_private_key_size = read(fd, exported_private_key, 32);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
    psa_set_key_bits(&attributes, private_key_size_bits);
    psa_status_t status = psa_import_key(&attributes, exported_private_key, exported_private_key_size, key_id);
    if (status != PSA_SUCCESS) {
        std::cout << "Failed to import key: " << status << std::endl;
        return ResultCode::ERR_PSA;
    }

    return ResultCode::SUCCESS;
}

int main(int argc, char *argv[]) {
    char *message = NULL;
    char current_path[FILENAME_MAX];

	// Parse the command line args.
    for (int i = 1; i < argc; i++)
	{
        std::string arg = argv[i];
		if (arg == "-t" && i + 1 < argc)
		{
			w3bstream_token = argv[++i];
		}
		if (arg == "-T" && i + 1 < argc)
		{
			w3bstream_topic = argv[++i];
		}
        if (arg == "-h")
		{
			std::cout << "NAME" << std::endl;
			std::cout << "	Web3 IoT SDK example: Raspberry Pi w3bstream client using HTTP." << std::endl;
			std::cout << "SYNOPSIS" << std::endl;
			std::cout << "	send_data [-n project_name] [-t w3bstream_token] [-w wallet_address] " << std::endl;
			std::cout << "DESCRIPTION" << std::endl;
			std::cout << "	This program demonstrates how to use mqtt to send verifiable data from a Raspberry Pi to a w3bstream node." << std::endl;
			std::cout << "USAGE" << std::endl;
			std::cout << "	Run the program specifying the required arguments." << std::endl;
			std::cout << "	The program will periodically send a message to the w3bstream node and print the message and response to stdout." << std::endl << std::endl;
			std::cout << "OPTIONS" << std::endl;
			std::cout << "	-t  w3bstream_token (required)" << std::endl;
			std::cout << "		The publisher token. If not specified, an empty publisher token will be used." << std::endl << std::endl;
			std::cout << "	-T  w3bstream_topic (required)" << std::endl;
			std::cout << "		The publisher topic. If not specified, an empty wallet address will be used." << std::endl << std::endl;
			std::cout << "	-h	Display this help message" << std::endl;
			return 0;
        }
    }
	if (w3bstream_token == "")
	{
		std::cerr << "Publisher token is required." << std::endl;
		return 1;
	}
	if (w3bstream_topic == "")
	{
		std::cerr << "Publisher topic is required." << std::endl;
		return 1;
	}

    getcwd(current_path, sizeof(current_path));
    // Set the path to the keys.
    if (keystore_path == "") {
        // Use the current path if none was specified.
        keystore_path = current_path;
    }
    private_key_path = keystore_path + "/private.key";
    public_key_path = keystore_path + "/public.key";

    // Initialize PSA Crypto.
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        std::cerr << "Failed to initialize PSA crypto library: " << status << std::endl;
        return (-1);
    }

    // Import the key if existent or generate a new key.
    psa_key_id_t key_id;
    ResultCode res = import_key(private_key_path.c_str(), public_key_path.c_str(), &key_id);
    if (res != ResultCode::SUCCESS) {
        std::cerr << "Failed to import key. " << std::endl;
        return 1;
    }

    // Connect to the MQTT server.
    res = mqtt_connect();
    if (res != ResultCode::SUCCESS) {
        std::cerr << "Failed to connect to the mqtt server." << std::endl;
        return -1;
    }

    while (true) {
        unsigned int length = 0;
        message = build_message(key_id, &length);
        int res = mosquitto_publish(client, nullptr, w3bstream_topic.c_str(), length, message, 0, false);
        free(message);
        if (res != MOSQ_ERR_SUCCESS) {
            std::cerr << "Failed to publish status query MQTT message" << std::endl;
            return ResultCode::ERR_MQTT;
        }
        sleep(5);
    }
}

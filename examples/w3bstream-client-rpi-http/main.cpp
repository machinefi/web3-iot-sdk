#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
#include <cstdio>
#include <iomanip>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string>
#include <algorithm>
#include <iostream>
#define _BSD_SOURCE
#include <sys/time.h>
#include <thread>
#include <curl/curl.h>
#include <fstream>


// Include the main header for the W3bstream IoT SDK.
#include "psa/crypto.h"




// Custom types.
enum ResultCode
{
	SUCCESS,
	ERROR,
	ERR_HTTP,
	ERR_CURL,
	ERR_FILE_READ,
	ERR_PSA,
};




// User configuration and constants.
namespace
{
	// Connection details.
	std::string publisher_token = "";           			// The publisher token.
	std::string endpoint = "";  							// The w3bstream endpoint.

    // Key store details.
	std::string keystore_path = "./";						// The path to the key store, where the key pair will be stored.
	std::string private_key_path = keystore_path + "private.key";
	std::string public_key_path = keystore_path + "public.key";

	// Constants.
	const size_t interval = 30;								// The interval for sending data to the server.
	const size_t private_key_size = 32;
	const size_t private_key_size_bits = private_key_size*8;
	const size_t public_key_size = 65;

	// Variables to hold global state, etc.
	psa_key_id_t key_id;									// The PSA API key slot id.
	std::string device_id = "";								// The device id. In our case, the public key.
}




// Function definitions.
static ResultCode sign_message(psa_key_id_t key_id, const uint8_t msg[], size_t msg_size, uint8_t buf[], size_t buf_size, size_t* signature_len)
{    
    psa_status_t status = psa_sign_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, msg_size, buf, buf_size, signature_len);
    if (status != PSA_SUCCESS)
	{
		std::cout << "Failed to sign message: " << status << std::endl;
		return ResultCode::ERR_PSA;
	}
        
    status = psa_verify_message(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, msg_size, buf, *signature_len);
    if (status != PSA_SUCCESS)
	{
		std::cout << "Failed to sign message: " << status << std::endl;
		return ResultCode::ERR_PSA;
	}
	return ResultCode::SUCCESS;
}

static ResultCode generate_key(const char* key_path, const char* public_key_path)
{
	std::cout << "Generating a new key."  << std::endl;

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
	psa_set_key_bits(&attributes, private_key_size_bits);
	auto status = psa_generate_key(&attributes, &key_id);
	if (status != PSA_SUCCESS)
	{
		std::cerr << "Failed to generate key: " << status << std::endl;
		return ResultCode::ERR_PSA;	
	}

	// Export the private key from the PSA API slot and save it to a file.
	static uint8_t exported_private_key[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(private_key_size_bits)] = {0};
	size_t exported_private_key_len = 0;
	status = psa_export_key(key_id, exported_private_key, sizeof(exported_private_key), &exported_private_key_len);
	if (status != PSA_SUCCESS)
	{
		std::cerr << "Failed to export private key: " << status << std::endl;
		return ResultCode::ERR_PSA;	
	}
	std::cout << "Exported private key: ";
	for (int i = 0; i < exported_private_key_len; i++) { printf("%x", exported_private_key[i]); }
	std::cout << std::endl;
	std::cout << "Saving private key to " << private_key_path  << std::endl;
	int fd = open(private_key_path.c_str(), O_RDWR | O_CREAT,0600);
	if(fd == -1)
	{
		std::cout << "Failed to open private key file: " << private_key_path << std::endl;
		return ResultCode::ERR_FILE_READ;
	}
	write(fd, exported_private_key, exported_private_key_len);
	close(fd);

	// Export the public key from the PSA API slot and save it to a file.
	uint8_t exported_public_key[public_key_size] = {0};
	size_t exported_public_key_len = 0;
	status = psa_export_public_key(key_id, exported_public_key, sizeof(exported_public_key), &exported_public_key_len);
	if (status != PSA_SUCCESS)
	{
		std::cerr << "Failed to export public key: " << status << std::endl;
		return ResultCode::ERR_PSA;	
	}
	std::cout << "Exported public key: ";
	for (int i = 0; i < exported_public_key_len; i++) { printf("%x", exported_public_key[i]); }
	std::cout << std::endl;
	std::cout << "Saving private key to " << public_key_path  << std::endl;
	fd = open(public_key_path, O_RDWR | O_CREAT,0600);
	if(fd == -1)
	{
		std::cout << "Failed to open public key file: " << public_key_path << std::endl;
		return ResultCode::ERR_FILE_READ;
	}
	write(fd, exported_public_key, exported_public_key_len);
	close(fd);

	std::cout << "Key generated successfully." << std::endl;
	return ResultCode::SUCCESS;
}

static ResultCode import_key(const char* key_path, const char* public_key_path, psa_key_id_t* key_id)
{
	int fd = open(key_path, O_RDWR);
	if(fd == -1)
	{
		ResultCode res = generate_key(key_path, public_key_path);
		if (res != ResultCode::SUCCESS)
		{
			return res;
		}

		fd = open(key_path, O_RDWR);
		if(fd == -1)
		{
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
	if (status != PSA_SUCCESS)
	{
		std::cout << "Failed to import key: " << status << std::endl;
		return ResultCode::ERR_PSA;
	}

	return ResultCode::SUCCESS;
}

static ResultCode generate_device_id(const char* public_key_file, std::string& device_id)
{
	int fd = open(public_key_file, O_RDONLY);
	if(fd == -1)
	{
		device_id = "";
		std::cerr << "Failed open file " << public_key_file << std::endl;
		return ResultCode::ERR_FILE_READ;
	}
	uint8_t public_key[public_key_size] = {0};
	size_t read_bytes = read(fd, public_key, public_key_size);
	if(read_bytes != public_key_size)
	{
		std::cerr << "Failed to read public key from " << public_key_file << ". File has invalid format." << std::endl;
		return ResultCode::ERR_FILE_READ;
	}

    // Return the public key as a hex string
    std::stringstream ss;
    for (int i = 0; i < public_key_size; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)public_key[i];
    }
    device_id = ss.str();
    
    return ResultCode::SUCCESS;
}

/**
 * @brief Get the current time as a string
 * 
 * @return std::string 
 */
std::string get_time_str()
{
	time_t now = time(0);
	struct tm tstruct;
	char buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%X", &tstruct);
	return buf;
}

/**
 * @brief Publish a message to the network using a POST HTTP request using curl.
 * 
 * @param message 
 * @return ResultCode 
 */
ResultCode publish_message(std::string url, std::string message, std::string bearer_token)
{
	std::cout << get_time_str() << ": Publishing message: " << message << std::endl <<" to " << url << std::endl;
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    if(curl)
	{
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, message.c_str());
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
		headers = curl_slist_append(headers, ("Authorization: Bearer " + bearer_token).c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_TRY);
        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
        {
            std::cerr << "Failed to publish message: " << curl_easy_strerror(res) << std::endl;
            return ResultCode::ERR_HTTP;
        }

        curl_easy_cleanup(curl);
    }
    else
    {
        std::cerr << "Failed to initialize curl" << std::endl << std::endl;
        return ResultCode::ERR_CURL;
    }
	std::cout << std::endl;
    return ResultCode::SUCCESS;
}

/**
 * @brief 
 * Create a payload object with the following format
 * {
 *      "data" :
 *      {
 *        "pin_status" : <number>,
 *        "timestamp" : <string>,
 *      },
 *      "signature" : <string>,
 *      "public_key" : <string>
 * }
 * 
 * @return std::string the payload string
 */
std::string create_payload(int value)
{
	// Convert pin_status to a string
	std::string value_str = std::to_string(value);

    std::string payload = "{";
    std::string data = "";
    std::string signature = "";
    data = "{";
	data += "\"status\":" + value_str;
    data += ",\"timestamp\":" + std::to_string(time(NULL));
    data += "}";

    // Sign the data
    uint8_t buf[64] = {0};
    size_t signature_length = 0;
    ResultCode result = sign_message(key_id, (const uint8_t*)data.c_str(), data.size(), buf, sizeof(buf), &signature_length);
    if(result != ResultCode::SUCCESS)
    {
        std::cerr << "Failed to sign data" << std::endl;
        return "";
    }

    // Convert the signature to a hex string
	std::stringstream ss;
	for (int i = 0; i < signature_length; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
	}
    signature = ss.str();

    payload += "\"data\":" + data + ",";
    payload += "\"signature\": \"" + signature + "\",";
    payload += "\"public_key\":\"" + device_id + "\"";
    payload += "}";

	return payload;
}




int main(int argc, char* argv[])
{
	bool erase_prevoius_keys = false;

	// Parse the command line args.
    for (int i = 1; i < argc; i++)
	{
        std::string arg = argv[i];
        if (arg == "-keystore_path" && i + 1 < argc)
		{
            keystore_path = argv[++i];
        }
        if (arg == "-generate_key")
		{
			erase_prevoius_keys = true;
        }
        if (arg == "-e" && i + 1 < argc)
        {
            endpoint = argv[++i];
        }
		if (arg == "-t" && i + 1 < argc)
		{
			publisher_token = argv[++i];
		}
        if (arg == "-h")
		{
			std::cout << "NAME" << std::endl;
			std::cout << "	W3bstream IoT SDK example: Raspberry Pi quick start." << std::endl;
			std::cout << "SYNOPSIS" << std::endl;
			std::cout << "	example-w3bstream-client-rpi-http [-h] [-t publisher_token] [-keystore_path path] [-generate_key]" << std::endl;
			std::cout << "DESCRIPTION" << std::endl;
			std::cout << "	This program demonstrates how to send verifiable data to a w3bstream node from a Raspberry Pi." << std::endl;
			std::cout << "USAGE" << std::endl;
			std::cout << "	Run the program specifying the required arguments options and any optional arguments." << std::endl;
			std::cout << "	The program will periodically send a message to the w3bstream node and print the message and response to stdout." << std::endl << std::endl;
			std::cout << "	Example:" << std::endl;
			std::cout << "		./example-w3bstream-client-rpi-http -t \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQYXlsb2FkIjoiOTAyNTg1MTIzODM2OTI4MiIsImlzcyI6InczYnN0cmVhbSJ9.mNbURj_JJpn8nh9K_tvIuQv1hFD4QBBftkPasbx6x_0\" -e \"https://devnet-staging-api.w3bstream.com/srv-applet-mgr/v0/event/eth_0xf4888300009314f5c5a0216ddb0968aa79113c04_quick_start\"" << std::endl;
			std::cout << "OPTIONS" << std::endl;
			std::cout << "	-t  publisher_token (required)" << std::endl;
			std::cout << "		The publisher token." << std::endl << std::endl;
            std::cout << "	-e  endpoint (required)" << std::endl;
            std::cout << "		The w3bstream endpoint." << std::endl << std::endl;
			std::cout << "	-keystore_path  path" << std::endl;
			std::cout << "		The directory where the key files are stored. If not specified, the current directory will be used." << std::endl << std::endl;
			std::cout << "	-generate_key" << std::endl;
			std::cout << "		If specified, previous keys will be erased and a new key pair will be generated." << std::endl << std::endl;
			std::cout << "	-h	Display this help message" << std::endl;
			return 0;
        }
    }

	// Verify required arguments are present.
	if (endpoint == "")
	{
		std::cerr << "Endpoint is required." << std::endl;
		return 1;
	}
	if (publisher_token == "")
	{
		std::cerr << "Publisher token is required." << std::endl;
		return 1;
	}

	char current_path[FILENAME_MAX];
	getcwd(current_path, sizeof(current_path));

	// Set the path to the keys.
	if (keystore_path == "")
	{
		// Use the current path if none was specified.
		keystore_path = current_path;
	}
    private_key_path = keystore_path + "/private.key";
	public_key_path = keystore_path + "/public.key";

	// Print the keystore path.
	std::cout << "Keystore path: " << keystore_path << std::endl;

	if (erase_prevoius_keys)
	{
		remove(private_key_path.c_str());
		remove(public_key_path.c_str());
	}

	// Initialize PSA Crypto.
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS)
	{
        std::cerr << "Failed to initialize PSA crypto library: " << status << std::endl;
        return (-1);
    }

	// Import the key if existent, or generate a new key.
	ResultCode res = import_key(private_key_path.c_str(), public_key_path.c_str(), &key_id);
	if (res != ResultCode::SUCCESS)
	{
		std::cerr << "Failed to import key. " << std::endl;
		return 1;
	}

    // Generate the device address from the key.
	// Note, for simplicity the device id is simply the public key.
	res = generate_device_id(public_key_path.c_str(), device_id);
	if (res != ResultCode::SUCCESS)
	{
		std::cerr << "Failed to generate device id. " << std::endl;
		return 1;
	}

	// Main loop:
	// 	- Gets a random value.
	// 	- Publish a message with the value.
	while (true)
	{
		uint64_t last_update_time = time(NULL);
        double value = random();
        std::string message = create_payload(value);

		res = publish_message(endpoint, message, publisher_token);
		if (res != ResultCode::SUCCESS)
		{
			std::cerr << "Failed to publish message. " << std::endl;
		}

		// Wait until the next update.		
		while(time(NULL) - last_update_time < interval)
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}
}

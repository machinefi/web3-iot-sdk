#include <stdio.h>
#include <zephyr.h>
#include <net/socket.h>
#include <power/reboot.h>
#include <logging/log.h>
#include "mqtt.h"
#include "config.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include "package.pb.h"

#define CLOUD_CONNACK_WAIT_DURATION     300 
#define  MQTT_TOPIC_SIZE    100

LOG_MODULE_REGISTER(mqtt, CONFIG_ASSET_TRACKER_LOG_LEVEL);

// mqtt broker  host and port 
#define  W3BSTREAM_BROKER_HOST     "devnet-staging.w3bstream.com"
#define  W3BSTREAM_BROKER_PORT        1883
// Topic of publish data to the w3bstream
#define  W3BSTREAM_PUB_DATA_TOPIC          "eth_0xf77f8de24194d768012ca1edd15aee0b33d919a1_pebble_test"
// token of w3bstream
#define  W3BSTREAM_DEV_TOKEN   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJQYXlsb2FkIjoiOTAyNjczMTQyMjAyODgwOCIsImlzcyI6InczYnN0cmVhbSJ9.-M0umqdSsvA06so-iF6SSrC3yBj6uk1tswOhZ-Z9-cA"


/* Buffers for MQTT client. */
static u8_t rx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];
static u8_t tx_buffer[CONFIG_MQTT_MESSAGE_BUFFER_SIZE];


static void iotex_mqtt_get_topic(u8_t *buf, int len) {
    snprintf(buf, len, W3BSTREAM_PUB_DATA_TOPIC);
}

const uint8_t *iotex_mqtt_get_client_id() {
    static u8_t client_id_buf[20] = { 0 };
    if (client_id_buf[0] == 0) {
        snprintf(client_id_buf, sizeof(client_id_buf), "%s", iotex_modem_get_imei());
    }
    return client_id_buf;
}
/*
 * @brief Resolves the configured hostname and
 * initializes the MQTT broker structure
 */
static void broker_init(const char *hostname, struct sockaddr_storage *storage) {
    int err;
    struct addrinfo *addr;
    struct addrinfo *result;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    err = getaddrinfo(hostname, NULL, &hints, &result);
    if (err) {
        LOG_ERR("ERROR: getaddrinfo failed %d\n", err);
        return;
    }
    addr = result;
    err = -ENOENT;
    while (addr != NULL) {
        /* IPv4 Address. */
        if (addr->ai_addrlen == sizeof(struct sockaddr_in)) {
            struct sockaddr_in *broker = ((struct sockaddr_in *)storage);

            broker->sin_family = AF_INET;
            broker->sin_port = htons(W3BSTREAM_BROKER_PORT);
            broker->sin_addr.s_addr = ((struct sockaddr_in *)addr->ai_addr)->sin_addr.s_addr;

            LOG_INF("IPv4 Address 0x%08x\n", broker->sin_addr.s_addr);
            break;
        } else if (addr->ai_addrlen == sizeof(struct sockaddr_in6)) {
            /* IPv6 Address. */
            struct sockaddr_in6 *broker = ((struct sockaddr_in6 *)storage);
            memcpy(broker->sin6_addr.s6_addr,((struct sockaddr_in6 *)addr->ai_addr)->sin6_addr.s6_addr,sizeof(struct in6_addr));
            broker->sin6_family = AF_INET6;
            broker->sin6_port = htons(W3BSTREAM_BROKER_PORT);

            LOG_INF("IPv6 Address");
            break;
        } else {
            LOG_ERR("error: ai_addrlen = %u should be %u or %u\n",(unsigned int)addr->ai_addrlen,(unsigned int)sizeof(struct sockaddr_in),(unsigned int)sizeof(struct sockaddr_in6));
        }

        addr = addr->ai_next;
        break;
    }

    /* Free the address. */
    freeaddrinfo(result);
}

/**@brief MQTT client event handler */
static void mqtt_evt_handler(struct mqtt_client *const c, const struct mqtt_evt *evt) {
    int err;
    uint8_t revTopic[100];
    uint32_t status;

    switch (evt->type) {
        case MQTT_EVT_CONNACK:
            LOG_INF("mqtt connected");
            break;
        case MQTT_EVT_DISCONNECT:
            LOG_INF("mqtt  disconnect");
            break;
        case MQTT_EVT_PUBACK:
            LOG_INF("[%s:%d] SUBACK packet id: %u\n", __func__, __LINE__, evt->param.suback.message_id);
            break;
        default:
            LOG_INF("[%s:%d] default: %d\n", __func__, __LINE__, evt->type);
            break;
    }
}

int iotex_mqtt_publish_data(struct mqtt_client *client, enum mqtt_qos qos, char *data, int len) {
    struct mqtt_publish_param param;
    u8_t pub_topic[MQTT_TOPIC_SIZE];
    uint8_t *topic = NULL;
    iotex_mqtt_get_topic(pub_topic, sizeof(pub_topic));
    LOG_INF("pub topic : %s \n", pub_topic);
    param.message.topic.qos = qos;
    param.message.topic.topic.utf8 = pub_topic;
    param.message.topic.topic.size = strlen(param.message.topic.topic.utf8);
    param.message.payload.data = data;
    param.message.payload.len = len;
    param.message_id = safeRandom(); /* sys_rand32_get(); */
    param.dup_flag = 0U;
    param.retain_flag = 0U;
    return mqtt_publish(client, &param);
}

/**@brief Initialize the MQTT client structure */
int iotex_mqtt_client_init(struct mqtt_client *client, struct pollfd *fds) {
    int err;
    static struct sockaddr_storage broker_storage;
    const uint8_t *client_id = iotex_mqtt_get_client_id();
    static sec_tag_t sec_tag_list[] = { CONFIG_CLOUD_CERT_SEC_TAG };
    struct mqtt_sec_config *tls_config = &(client->transport).tls.config;

    mqtt_client_init(client);
    /* Load mqtt data channel configure */
    broker_init(W3BSTREAM_BROKER_HOST, &broker_storage);
    LOG_INF("client_id: %s\n", client_id);
    /* MQTT client configuration */
    client->broker = &broker_storage;
    client->evt_cb = mqtt_evt_handler;
    client->client_id.utf8 = client_id;
    client->client_id.size = strlen(client_id);
    client->password = NULL;
    client->user_name = NULL;
    client->protocol_version = MQTT_VERSION_3_1_1;
    client->unacked_ping = 100;
    /* MQTT buffers configuration */
    client->rx_buf = rx_buffer;
    client->rx_buf_size = sizeof(rx_buffer);
    client->tx_buf = tx_buffer;
    client->tx_buf_size = sizeof(tx_buffer);
    /* MQTT transport configuration */
    if(W3BSTREAM_BROKER_PORT == 1883)
        client->transport.type = MQTT_TRANSPORT_NON_SECURE;
    else
        client->transport.type = MQTT_TRANSPORT_SECURE;
    LOG_INF("mqtt connection type:%d,port:%d, host:%s\n", client->transport.type, W3BSTREAM_BROKER_PORT,W3BSTREAM_BROKER_HOST);
    tls_config->peer_verify = 2;
    tls_config->cipher_list = NULL;
    tls_config->cipher_count = 0;
    tls_config->sec_tag_count = ARRAY_SIZE(sec_tag_list);
    tls_config->sec_tag_list = sec_tag_list;
    tls_config->hostname = W3BSTREAM_BROKER_HOST;

    if ((err = mqtt_connect(client)) != 0) {
        return err;
    }
    /* Initialize the file descriptor structure used by poll */
    fds->fd = client->transport.tls.sock;
    fds->events = POLLIN;
    return 0;
}


int SensorPackage(uint8_t *buffer)
{
	int i;
	char esdaSign[65];
	char jsStr[130];
	int sinLen;
	uint32_t uint_timestamp;
    int gyroscope[3] = {-2658, 9, 11};
    int accelerometer[3] = {2658, 3835, 3326};
    const char *modem_tm_str = NULL;
	/* char random[17]; */
	BinPackage binpack = BinPackage_init_zero;
	SensorData sensordat = SensorData_init_zero;
	Event ws_event = Event_init_zero;

	strcpy(ws_event.header.event_type, "PEBBLE");
	strcpy(ws_event.header.token, W3BSTREAM_DEV_TOKEN);
	strcpy(ws_event.header.pub_id, "Test_Pebble_00001");

	/*  Initialize buffer */
	memset(buffer, 0, DATA_BUFFER_SIZE);
    /* Snr */
    sensordat.snr = 95;
    /* Vbat */
    sensordat.vbat = 332;
    /* GPS */
    sensordat.latitude = 2000000000;
    sensordat.longitude = 2000000000;
    /* Env sensor gas */
    sensordat.gasResistance = 6137;
    /* Env sensor temperature */
    sensordat.temperature = 3508;
    sensordat.temperature2 = 3508;
    /* Env sensor pressure */
    sensordat.pressure = 26274;
    /* Env sensor humidity */
    sensordat.humidity = 4515;
    /* Env sensor light */
    sensordat.light = 2035;
    /* Action sensor gyroscope data */
    for (i = 0; i < sizeof(gyroscope) / sizeof(int); i++) {
        sensordat.gyroscope[i] = (int32_t)(gyroscope[i]);
    }
    /* Action sensor accelerometer */
    for (i = 0; i < sizeof(accelerometer) / sizeof(int); i++) {
        sensordat.accelerometer[i] = (int32_t)(accelerometer[i]);
    }

	/* Add timestamp */
	//uint_timestamp = getSysTimestamp_s();
    modem_tm_str = iotex_modem_get_clock(NULL);
    if(modem_tm_str != NULL){
        uint_timestamp = atoi(modem_tm_str);
    }
	ws_event.header.pub_time = uint_timestamp;
	/*  get random number */
	__disable_irq();
	GenRandom(sensordat.random);
	__enable_irq();
	sensordat.random[sizeof(sensordat.random) - 1] = 0;

	pb_ostream_t enc_datastream = pb_ostream_from_buffer(binpack.data.bytes, sizeof(binpack.data.bytes));
	if (!pb_encode(&enc_datastream, SensorData_fields, &sensordat)) {
		LOG_ERR("pb encode error in %s [%s]\n", __func__,
			PB_GET_ERROR(&enc_datastream));
		return 0;
	}
	binpack.data.size = enc_datastream.bytes_written;
	binpack.data.bytes[enc_datastream.bytes_written] =(char)((uint_timestamp & 0xFF000000) >> 24);
	binpack.data.bytes[enc_datastream.bytes_written + 1] =(char)((uint_timestamp & 0x00FF0000) >> 16);
	binpack.data.bytes[enc_datastream.bytes_written + 2] =(char)((uint_timestamp & 0x0000FF00) >> 8);
	binpack.data.bytes[enc_datastream.bytes_written + 3] =(char)(uint_timestamp & 0x000000FF);
	*(uint32_t *)buffer = BinPackage_PackageType_DATA;
	memcpy(buffer + 4, binpack.data.bytes,enc_datastream.bytes_written + 4);
	doESDASign(buffer, enc_datastream.bytes_written + 8, esdaSign, &sinLen);
	LOG_INF("sinLen:%d\n", sinLen);
	memcpy(binpack.signature, esdaSign, 64);
	binpack.timestamp = uint_timestamp;
	binpack.type = BinPackage_PackageType_DATA;

	pb_ostream_t enc_packstream = pb_ostream_from_buffer(ws_event.payload.bytes, sizeof(ws_event.payload.bytes));
	if (!pb_encode(&enc_packstream, BinPackage_fields, &binpack)) {
		LOG_ERR("pb encode error in %s [%s]\n", __func__,
			PB_GET_ERROR(&enc_packstream));
		return 0;
	}

	ws_event.payload.size = enc_packstream.bytes_written;
	LOG_INF("event payload size: %d\n", ws_event.payload.size);

	pb_ostream_t stream = pb_ostream_from_buffer(buffer, DATA_BUFFER_SIZE);
	if (!pb_encode(&stream, Event_fields, &ws_event)) {
		LOG_ERR("pb encode error in %s [%s]\n", __func__,
			PB_GET_ERROR(&stream));
		return 0;
	}

	LOG_INF("stream.bytes_written:%d\n", stream.bytes_written);


	return stream.bytes_written;
}

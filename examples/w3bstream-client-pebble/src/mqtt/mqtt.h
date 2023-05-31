#ifndef  _IOTEX_MQTT_H_
#define  _IOTEX_MQTT_H_

#include <net/mqtt.h>
#include <net/cloud.h>
#include <zephyr.h>
#include <net/socket.h>

#define DATA_BUFFER_SIZE    2048


int iotex_mqtt_client_init(struct mqtt_client *client, struct pollfd *fds);
int iotex_mqtt_publish_data(struct mqtt_client *client, enum mqtt_qos qos, char *data, int  len);


int SensorPackage(uint8_t *buffer);


#endif

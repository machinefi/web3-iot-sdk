#include <zephyr.h>
#include <kernel_structs.h>
#include <stdio.h>
#include <string.h>
#include <console/console.h>
#include <power/reboot.h>
#include <logging/log_ctrl.h>
#include <modem/bsdlib.h>
#include <bsd.h>
#include <modem/lte_lc.h>
#include <modem/modem_info.h>
#include <net/cloud.h>
#include <net/socket.h>
#include <net/nrf_cloud.h>
#include "mqtt/mqtt.h"


LOG_MODULE_REGISTER(w3bstream_client_pebble, CONFIG_ASSET_TRACKER_LOG_LEVEL);

#if defined(CONFIG_BSD_LIBRARY) && !defined(CONFIG_LTE_LINK_CONTROL)
#error "Missing CONFIG_LTE_LINK_CONTROL"
#endif /* if defined(CONFIG_BSD_LIBRARY) && !defined(CONFIG_LTE_LINK_CONTROL) */

#if defined(CONFIG_BSD_LIBRARY) && defined(CONFIG_LTE_AUTO_INIT_AND_CONNECT) && defined(CONFIG_NRF_CLOUD_PROVISION_CERTIFICATES)
#error "PROVISION_CERTIFICATES \
    requires CONFIG_LTE_AUTO_INIT_AND_CONNECT to be disabled!"
#endif /* if defined(CONFIG_BSD_LIBRARY) && defined(CONFIG_LTE_AUTO_INIT_AND_CONNECT) && defined(CONFIG_NRF_CLOUD_PROVISION_CERTIFICATES) */

#define SUCCESS_OR_BREAK(rc) { if (rc != 0) { return ; } }



/* File descriptor */
static struct pollfd fds;
/* MQTT Broker details. */
static struct mqtt_client client;


enum error_type {
    ERROR_CLOUD,
    ERROR_BSD_RECOVERABLE,
    ERROR_LTE_LC,
    ERROR_SYSTEM_FAULT
};
static char mqttPubBuf[DATA_BUFFER_SIZE];
const char reconnectReminder[][4] = {
    "",
    "1st",
    "2nd",
    "3rd"
};


/*  Upload sensor data regularly */
static void periodic_publish_sensors_data(void) {
    int rc;
    if (rc = SensorPackage(mqttPubBuf)) {
        LOG_INF("start mqtt_publish_devicedata : %d bytes \n", rc);
        rc = iotex_mqtt_publish_data(&client, 0, mqttPubBuf, rc);
        LOG_INF("mqtt_publish_devicedata: %d \n", rc);
    } else {
        LOG_ERR("mqtt package error ! \n");
    }
}

/**@brief Configures modem to provide LTE link. Blocks until link is
 * successfully established.
 */
static void modem_configure(void) {
    if (IS_ENABLED(CONFIG_LTE_AUTO_INIT_AND_CONNECT)) {
        /* Do nothing, modem is already turned on
         * and connected.
         */
    } else {
        int err;

        LOG_INF("Connecting to LTE network. ");
        LOG_INF("This may take several minutes.\n");  
        err = lte_lc_psm_req(true);
        if (err) {
            LOG_ERR("lte_lc_psm_req erro:%d\n", err);
        }
        /* ui_led_set_pattern(UI_LTE_CONNECTING); */
        /* ui_led_deactive(LTE_CONNECT_MASK,1); */
        err = lte_lc_init_and_connect();
        if (err) {
            lte_lc_deinit();
            LOG_INF("modem fallback\n");
            err = lte_lc_init_and_connect();
            if (err) {
                LOG_ERR("LTE link could not be established, system will reboot.\n");
                sys_reboot(0);
            }
        }        
        LOG_INF("Connected to LTE network\n");
    }
}

void handle_bsdlib_init_ret(void) {
    int ret = bsdlib_get_init_ret();

    /* Handle return values relating to modem firmware update */
    switch (ret) {
    case MODEM_DFU_RESULT_OK:
        LOG_INF("MODEM UPDATE OK. Will run new firmware");
        sys_reboot(SYS_REBOOT_COLD);
        break;
    case MODEM_DFU_RESULT_UUID_ERROR:
    case MODEM_DFU_RESULT_AUTH_ERROR:
        LOG_ERR("MODEM UPDATE ERROR %d. Will run old firmware", ret);
        sys_reboot(SYS_REBOOT_COLD);
        break;
    case MODEM_DFU_RESULT_HARDWARE_ERROR:
    case MODEM_DFU_RESULT_INTERNAL_ERROR:
        LOG_ERR("MODEM UPDATE FATAL ERROR %d. Modem failiure", ret);
        sys_reboot(SYS_REBOOT_COLD);
        break;
    default:
        break;
    }
}


void main(void) {
    int err = 0, errCounts = 3, upload_period = 0;

    /*   init ECDSA */
    InitLowsCalc();
    if (initECDSA_sep256r()) {
        LOG_ERR("initECDSA_sep256r error\n");
        return;
    }
    if (startup_check_ecc_key()) {
        LOG_ERR("check ecc key error\n");
        LOG_ERR("system will not startup\n");
        return;
    }
    iotexImportKey();

    /*  LTE-M / NB-IOT network attach */
    modem_configure();
    handle_bsdlib_init_ret();

    // retry 3 times to connect to the broker
    while(errCounts && (err = iotex_mqtt_client_init(&client, &fds))){
        LOG_ERR("**** %s reconnection ****\n",reconnectReminder[errCounts]);
        errCounts--;
    }
    // cannot connect to broker, reboot device
    if(err){
        LOG_ERR("ERROR: mqtt_connect %d, rebooting...\n", err);
        k_sleep(K_MSEC(500));
        sys_reboot(0);
    }
    // publish data every 30s
    while (true) {
        err = poll(&fds, 1, 5000);
        if (err < 0) {
            LOG_ERR("ERROR: poll %d\n", errno);
            break;
        }
        if ((fds.revents & POLLIN) == POLLIN) {
            err = mqtt_input(&client);
            if (err != 0) {
                LOG_ERR("ERROR: mqtt_input %d\n", err);
                break;
            }
        }
        if ((fds.revents & POLLERR) == POLLERR) {
            LOG_ERR("POLLERR\n");
            err = -1;
            break;
        }
        if ((fds.revents & POLLNVAL) == POLLNVAL) {
            LOG_ERR("POLLNVAL\n");
            err = -2;
            break;
        }
        err = mqtt_live(&client);
        if (err != 0 && err != -EAGAIN) {
            LOG_ERR("ERROR: mqtt_live %d\n", err);
            break;
        }
        if(upload_period == 0){
            periodic_publish_sensors_data();
            upload_period++;
        }
        else {
            upload_period++;
            if(upload_period == 6)
                upload_period = 0;
        }
    }
    /* connect_to_cloud(0); */
    LOG_INF("Disconnecting MQTT client...\n");
    err = mqtt_disconnect(&client);
    if (err) {
        LOG_ERR("Could not disconnect MQTT client. Error: %d\n", err);
    }
    sys_reboot(0);
}

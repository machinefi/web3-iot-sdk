#ifndef _IOTEX_MODEM_H_
#define _IOTEX_MODEM_H_

#define MODEM_IMEI_LEN 15
#define TIMESTAMP_STR_LEN 50

/* define  mqtt tls cert */
#define  CERT_START_SEC   4
/*  default asia */
#define ASIA_PACIFIC_CERT_SEC   CERT_START_SEC
#define ASIA_PACIFIC_KEY_SEC    (CERT_START_SEC+1)  /* 5 */
/*  pacific */
#define EUROPE_FRANKFURT_CERT_SEC   (CERT_START_SEC+2)
#define EUROPE_FRANKFURT_KEY_SEC    (CERT_START_SEC+3)  
/*  middle_east */
#define MIDDLE_EAST_CERT_SEC   (CERT_START_SEC+4)
#define MIDDLE_EAST_KEY_SEC    (CERT_START_SEC+5)  
/*  north_america */
#define NORTH_AMERICA_CERT_SEC   (CERT_START_SEC+6)
#define NORTH_AMERICA_KEY_SEC    (CERT_START_SEC+7)  
/*  south america */
#define SOUTH_AMERICA_CERT_SEC   (CERT_START_SEC+8)
#define SOUTH_AMERICA_KEY_SEC    (CERT_START_SEC+9) 
/*  root CA */
#define AWS_ROOT_CA             (CERT_START_SEC+10) 

/*  define  ECC_KEY  SEC */
#define  ECC_KEY_SEC          (CERT_START_SEC+11)   /*  private + public */

/*  define  system parameters */
#define   PEBBLE_SYS_PARAM_SEC   (CERT_START_SEC+12)
/*  Device serial number */
#define   PEBBLE_DEVICE_SN        (CERT_START_SEC+13)
/*  mqtt cert index */
#define   MQTT_CERT_INDEX          (CERT_START_SEC+14)
/*  modem  startup mode , LTE-M or  NB-IOT */
#define   MODEM_MODE_SEL          (CERT_START_SEC+15)

typedef struct {
    char data[TIMESTAMP_STR_LEN];
} __attribute__((packed)) iotex_st_timestamp;

const char *iotex_modem_get_imei();
const char *iotex_modem_get_clock(iotex_st_timestamp *stamp);

#endif /* _IOTEX_MODEM_H_ */
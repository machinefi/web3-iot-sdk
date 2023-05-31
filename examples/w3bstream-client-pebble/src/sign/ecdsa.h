#ifndef    __ESDA_H__
#define    __ESDA_H__

int initECDSA_sep256r(void);
int doESDA_sep256r_Sign(char *inbuf, uint32_t len, char *buf, int* sinlen);
int GenRandom(char *out);
int startup_check_ecc_key(void);
void InitLowsCalc(void);
int doESDASign(char *inbuf, uint32_t len, char *buf, int* sinlen);
int safeRandom(void);
uint16_t CRC16(uint8_t *data, size_t len);


#endif
#include <stdio.h>
#include <string.h>
#include <zephyr.h>
#include "ecdsa.h"
#include <drivers/entropy.h>
#include <sys/util.h>
#include <toolchain/common.h>
#include <logging/log.h>
#include "ecdsa.h"
#include "modem/modem_helper.h"

#include "svc/crypto.h"


LOG_MODULE_REGISTER(ecdsa, CONFIG_ASSET_TRACKER_LOG_LEVEL);

#define   AES_KMU_SLOT              2
#define      TEST_VERFY_SIGNATURE    
#define TV_NAME(name) name " -- [" __FILE__ ":" STRINGIFY(__LINE__) "]"
#define  CHECK_RESULT(exp_res,chk) \
        do \
        { \
            if(chk != exp_res){ \
                LOG_ERR("In function %s, line:%d, error_code:0x%04X \n", __func__,__LINE__,chk);\ 
            } \       
        } while (0)
#define ECDSA_MAX_INPUT_SIZE (64)
#define ECPARAMS    MBEDTLS_ECP_DP_SECP256R1
#define PUBKEY_BUF_ADDRESS(a)  (a+80)
#define PUBKEY_STRIP_HEAD(a)   (a+81)
#define  KEY_BLOCK_SIZE 190
#define   MODEM_READ_HEAD_LEN    200    
#define   KEY_STR_BUF_SIZE        329
#define   MODEM_READ_BUF_SIZE    (KEY_STR_BUF_SIZE+MODEM_READ_HEAD_LEN)
#define   KEY_STR_LEN    (KEY_STR_BUF_SIZE-1)
#define      PRIV_STR_BUF_SIZE        133
#define   PRIV_STR_LEN           (PRIV_STR_BUF_SIZE-1)
#define   PUB_STR_BUF_SIZE        197
#define  KEY_HEX_SIZE        184
#define  PRIV_HEX_SIZE        66
#define  PUB_HEX_SIZE        (KEY_HEX_SIZE - PRIV_HEX_SIZE)
#define  PUB_HEX_ADDR(a)    (a+PRIV_HEX_SIZE)
#define  PUB_STR_ADDR(a)    (a+PRIV_STR_LEN)
#define  COM_PUB_STR_ADD(a)  (a+PRIV_STR_LEN+130)
#define  UNCOM_PUB_STR_ADD(a) (a+PRIV_STR_LEN)

psa_key_id_t prikey_id;
psa_key_id_t pubkey_id;


int get_ecc_key(void) {
    uint8_t *pbuf;
    char buf[MODEM_READ_BUF_SIZE];

    memset(buf, 0, sizeof(buf));
    pbuf = ReadDataFromModem(ECC_KEY_SEC, buf, MODEM_READ_BUF_SIZE);
    if (pbuf)
        return updateKey(pbuf);
    else
        return 1;
}

int startup_check_ecc_key(void) {
    return get_ecc_key() ? -4 : 0;
}

int doESDASign(char *inbuf, uint32_t len, char *buf, int *sinlen) {

    int ret = 0, hash_length = 0;
    char sha256_output[32] = {0};

    ret = psa_sign_message( prikey_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), inbuf, len, buf, 65,  sinlen);
    if(ret)
        goto exit;
    ret = psa_verify_message( pubkey_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), inbuf, len, buf, *sinlen);
    if(ret)
        goto exit;

    LowsCalc(buf + 32, buf + 32);

exit:
    return ret;
}


int safeRandom(void) {
    int  rand;
    __disable_irq();
    rand = iotex_random();
    __enable_irq();
    return rand;
}

int iotexImportKey(void)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    int ret = 0;
    unsigned char prikey[32] = {0};
    unsigned char pubkey[65] = {0};

    ret = getKeyWithBin(prikey, pubkey);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        LOG_ERR("Failed to initialize PSA Crypto\n");
        return (-1);
    }

    /* Set key attributes */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1));
    psa_set_key_bits(&attributes, 256);

    /* Import the key */
    status = psa_import_key(&attributes, prikey, 32, &prikey_id);
    if (status != PSA_SUCCESS) {
        LOG_ERR("Failed to import pri key err %d\n", status);
        return (-1);
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1));

    status = psa_import_key(&attributes, pubkey, 65, &pubkey_id);
    if (status != PSA_SUCCESS) {
        LOG_ERR("Failed to import pub key err %d\n", status);
        return (-1);
    }
    printf("Pebble public key: ");
    for(int i =0; i < 65; i++)
    {
        printf("%02x", pubkey[i]);
    }
    printf("\n");

    return 0;
}


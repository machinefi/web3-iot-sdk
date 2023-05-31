#include "common.h"

#include "iotex/platform.h"

#if defined(IOTEX_PSA_CRYPTO_C)

#if defined(IOTEX_PSA_CRYPTO_CONFIG)
#include "check_crypto_config.h"
#endif

#include "svc/crypto.h"
#include "svc/crypto_values.h"

#include "crypto/psa_crypto_all.h"
#include "iotex/iotex_crypto_all.h"

#include "crypto/psa_crypto_random_impl.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "iotex/platform.h"
#if !defined(IOTEX_PLATFORM_C)
#define iotex_calloc calloc
#define iotex_free   free
#endif

#include "mbedtls/aes.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/camellia.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ccm.h"
#include "mbedtls/cmac.h"
#include "mbedtls/des.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md5.h"
#include "mbedtls/md.h"
//#include "../md_wrap.h"
#include "mbedtls/pk.h"
//#include "../pk_wrap.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ecdsa.h"



/****************************************************************/
/* Global data, support functions and library management */
/****************************************************************/
#define ECP_VALIDATE_RET( cond )    \
    IOTEX_INTERNAL_VALIDATE_RET( cond, IOTEX_ERR_ECP_BAD_INPUT_DATA )
#define ECP_VALIDATE( cond )        \
    IOTEX_INTERNAL_VALIDATE( cond )

#define ECP_CURVE25519_KEY_SIZE 32
#define ECP_CURVE448_KEY_SIZE   56

/****************************************************************/
/* MD */
/****************************************************************/

inline iotex_md_type_t iotex_md_get_type( const iotex_md_info_t *md_info )
{
    return (iotex_md_type_t)0;
}

/****************************************************************/
/* MD5 */
/****************************************************************/

/****************************************************************/
/* SHA256 */
/****************************************************************/        
inline void iotex_sha256_init( iotex_sha256_context *ctx )
{
    mbedtls_sha256_init( (mbedtls_sha256_context *)ctx );    
}

inline void iotex_sha256_free( iotex_sha256_context *ctx )
{
    mbedtls_sha256_free( (mbedtls_sha256_context *)ctx );
}

inline int iotex_sha256_starts( iotex_sha256_context *ctx, int is224 )
{
    return mbedtls_sha256_starts_ret( (mbedtls_sha256_context *)ctx, is224 );
}

inline int iotex_sha256_update( iotex_sha256_context *ctx, const unsigned char *input, size_t ilen )
{
    return mbedtls_sha256_update_ret( (mbedtls_sha256_context *)ctx, input, ilen );
}

inline int iotex_sha256_finish( iotex_sha256_context *ctx, unsigned char *output )
{
    return mbedtls_sha256_finish_ret( (mbedtls_sha256_context *)ctx, output );
}

/****************************************************************/
/* SHA512 */
/****************************************************************/

/****************************************************************/
/* RIPEMD160 */
/****************************************************************/

/****************************************************************/
/* MAC */
/****************************************************************/

/****************************************************************/
/* Asymmetric cryptography */
/****************************************************************/

/****************************************************************/
/* CIPHER */
/****************************************************************/

/****************************************************************/
/* AES */
/****************************************************************/

/****************************************************************/
/* RSA */
/****************************************************************/

/****************************************************************/
/* BIGNUM */
/****************************************************************/
inline void iotex_mpi_init( iotex_mpi *X )
{
    mbedtls_mpi_init( (mbedtls_mpi *)X );
}

inline int iotex_mpi_write_binary( const iotex_mpi *X, unsigned char *buf, size_t buflen )
{
    return mbedtls_mpi_write_binary( (mbedtls_mpi *)X, buf, buflen );
}

inline int iotex_mpi_read_binary( iotex_mpi *X, const unsigned char *buf, size_t buflen )
{
    return mbedtls_mpi_read_binary( (mbedtls_mpi *)X, buf, buflen );
}

inline void iotex_mpi_free( iotex_mpi *X )
{
    mbedtls_mpi_free( (mbedtls_mpi *)X );
}

/****************************************************************/
/* PK */
/****************************************************************/

/****************************************************************/
/* ECP */
/****************************************************************/
inline void iotex_ecp_keypair_init( iotex_ecp_keypair *key )
{
    mbedtls_ecp_keypair_init( (mbedtls_ecp_keypair *)key );
}

inline int iotex_ecp_group_load( iotex_ecp_group *grp, iotex_ecp_group_id id )
{
    return mbedtls_ecp_group_load( (mbedtls_ecp_group *)grp, (mbedtls_ecp_group_id) id );
}

inline int iotex_ecp_read_key( iotex_ecp_group_id grp_id, iotex_ecp_keypair *key,
                          const unsigned char *buf, size_t buflen )
{
#if ECDSA_VERIFY_USE_STR    
    unsigned char sebuf[65] = {0}; 
    int ret = -1;
    if (getPrikeyWithStr(sebuf))
        goto exit;

    printf("pri key DUMP str:\n");
    for (int i = 0; i < 65; i++)
    {
        printf("%x ", sebuf[i]);
    }
    printf("\n"); 

    ret =  mbedtls_mpi_read_string(&key->d, 16, sebuf);
    if(ret)
        goto exit;
    mbedtls_ecp_check_privkey( &key->grp, &key->d );
    if(ret)
        goto exit;

exit:
    printf("iotex_ecp_read_key ret %d\n", ret);
    return ret;
#else
    return mbedtls_ecp_read_key( (mbedtls_ecp_group_id) grp_id, (mbedtls_ecp_keypair *)key, buf, buflen );
#endif

}

inline void iotex_ecp_keypair_free( iotex_ecp_keypair *key )
{
    mbedtls_ecp_keypair_free( (mbedtls_ecp_keypair *)key );
}

inline int iotex_ecp_point_read_binary( const iotex_ecp_group *grp,
                                   iotex_ecp_point *pt,
                                   const unsigned char *buf, size_t ilen )
{
#if ECDSA_VERIFY_USE_STR    
    unsigned char qx[65] = {0};   
    unsigned char qy[65] = {0};

    int ret = -1;
    ret = getPubkeyWithStr(qx, qy);
    printf("getPubkeyWithStr ret %x\n", ret);

    printf("qx:\n");
    for(int i = 0; i < 65; i++)
    {
        printf("%x ", qx[i]);
    }
    printf("\n");

    printf("qx:\n");
    for(int i = 0; i < 65; i++)
    {
        printf("%x ", qy[i]);
    }
    printf("\n");

    return mbedtls_ecp_point_read_string((mbedtls_ecp_point *)pt, 16, qx, qy);

#else
    return mbedtls_ecp_point_read_binary( (const mbedtls_ecp_group *)grp, (mbedtls_ecp_point *)pt, buf, ilen );
#endif
}

inline int iotex_ecp_check_pubkey( const iotex_ecp_group *grp,
                              const iotex_ecp_point *pt )
{
    return mbedtls_ecp_check_pubkey( (const mbedtls_ecp_group *)grp, (const mbedtls_ecp_point *)pt );
}

int iotex_ecp_write_key( iotex_ecp_keypair *key,
                           unsigned char *buf, size_t buflen )
{
    int ret = IOTEX_ERR_ECP_FEATURE_UNAVAILABLE;

    ECP_VALIDATE_RET( key != NULL );
    ECP_VALIDATE_RET( buf != NULL );

#if defined(IOTEX_ECP_MONTGOMERY_ENABLED)
    if( mbedtls_ecp_get_type( &key->grp ) == IOTEX_ECP_TYPE_MONTGOMERY )
    {
        printf("IS MONTGOMERY\n");
        if( key->grp.id == IOTEX_ECP_DP_CURVE25519 )
        {
            if( buflen < ECP_CURVE25519_KEY_SIZE )
                return( IOTEX_ERR_ECP_BUFFER_TOO_SMALL );

        }
        else if( key->grp.id == MBEDTLS_ECP_DP_CURVE448 )
        {
            if( buflen < ECP_CURVE448_KEY_SIZE )
                return( IOTEX_ERR_ECP_BUFFER_TOO_SMALL );
        }
        IOTEX_MPI_CHK( mbedtls_mpi_write_binary_le( &key->d, buf, buflen ) );
    }
#endif
#if defined(IOTEX_ECP_SHORT_WEIERSTRASS_ENABLED)
    if( mbedtls_ecp_get_type( &key->grp ) == IOTEX_ECP_TYPE_SHORT_WEIERSTRASS )
    {
        printf("IS SHORT_WEIERSTRASS\n");
        IOTEX_MPI_CHK( mbedtls_mpi_write_binary( &key->d, buf, buflen ) );
    }

#endif
cleanup:
    printf("iotex_ecp_write_key ret %x\n", ret);
    return( ret );
}

inline int iotex_ecp_is_zero( iotex_ecp_point *pt )
{
    return mbedtls_ecp_is_zero( (mbedtls_ecp_point *)pt );;
}

inline int iotex_ecp_mul( iotex_ecp_group *grp, iotex_ecp_point *R,
             const iotex_mpi *m, const iotex_ecp_point *P,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return mbedtls_ecp_mul( (mbedtls_ecp_group *)grp, (mbedtls_ecp_point *)R, (const mbedtls_mpi *)m, (const mbedtls_ecp_point *)P, f_rng, p_rng );
}

inline int iotex_ecp_point_write_binary( const iotex_ecp_group *grp,
                                    const iotex_ecp_point *P,
                                    int format, size_t *olen,
                                    unsigned char *buf, size_t buflen )
{
    return mbedtls_ecp_point_write_binary( (const mbedtls_ecp_group *)grp, (const mbedtls_ecp_point *)P, format, olen, buf, buflen );;
}

/****************************************************************/
/* ECDSA */
/****************************************************************/

inline int iotex_ecdsa_sign( iotex_ecp_group *grp, iotex_mpi *r, iotex_mpi *s,
                const iotex_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return mbedtls_ecdsa_sign(grp, r, s, d, buf, blen, f_rng, p_rng);
}

inline int iotex_ecdsa_verify( iotex_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const iotex_ecp_point *Q, const iotex_mpi *r,
                          const iotex_mpi *s)
{
    return mbedtls_ecdsa_verify( (mbedtls_ecp_group *)grp, buf, blen, (mbedtls_ecp_point *)Q, (mbedtls_mpi *)r, (mbedtls_mpi *)s);    
}

/****************************************************************/
/* Random generation */
/****************************************************************/
#if defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG)
psa_status_t iotex_psa_external_get_random(iotex_psa_external_random_context_t *context,
              uint8_t *output, size_t output_size, size_t *output_length)
{ 
    iotex_get_random(output, output_size);

    *output_length = output_size;

    return( PSA_SUCCESS );
}
#else
int iotex_hardware_poll( void *data, unsigned char *output, size_t len, size_t *olen )
{
    return iotex_entroy_get(output, len, olen);      
}
#endif /* !defined(IOTEX_PSA_CRYPTO_EXTERNAL_RNG) */

/****************************************************************/
/* Module setup */
/****************************************************************/


/****************************************************************/
/* Platform Util */
/****************************************************************/

#if !defined(IOTEX_PLATFORM_ZEROIZE_ALT)

static void * (* const volatile memset_func)( void *, int, size_t ) = memset;

void iotex_platform_zeroize( void *buf, size_t len )
{
    if( len > 0 )
        memset_func( buf, 0, len );
}
#endif /* IOTEX_PLATFORM_ZEROIZE_ALT */

#endif /* IOTEX_PSA_CRYPTO_C */

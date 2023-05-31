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
/* AES */
/****************************************************************/

inline void iotex_aes_init( iotex_aes_context *ctx )
{
    mbedtls_aes_init( (mbedtls_aes_context *)ctx );
}

inline void iotex_aes_free( iotex_aes_context *ctx )
{
    mbedtls_aes_free( (mbedtls_aes_context *)ctx );
}

#if defined(IOTEX_CIPHER_MODE_XTS)
inline void iotex_aes_xts_init( iotex_aes_xts_context *ctx )
{
    mbedtls_aes_xts_init( (mbedtls_aes_xts_context *)ctx );
}

inline void iotex_aes_xts_free( iotex_aes_xts_context *ctx )
{
    mbedtls_aes_xts_free( (mbedtls_aes_xts_context *)ctx );
}
#endif /* IOTEX_CIPHER_MODE_XTS */

inline int iotex_aes_setkey_enc( iotex_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    return mbedtls_aes_setkey_enc( (mbedtls_aes_context *)ctx, key, keybits );
}

inline int iotex_aes_setkey_dec( iotex_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
    return mbedtls_aes_setkey_dec( (mbedtls_aes_context *)ctx, key, keybits );
}

#if defined(IOTEX_CIPHER_MODE_XTS)
inline int iotex_aes_xts_setkey_enc( iotex_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits )
{
    return mbedtls_aes_xts_setkey_enc( (mbedtls_aes_xts_context *)ctx, key, keybits );
}

inline int iotex_aes_xts_setkey_dec( iotex_aes_xts_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits )
{
    return mbedtls_aes_xts_setkey_dec( (mbedtls_aes_xts_context *)ctx, key, keybits );
}
#endif /* IOTEX_CIPHER_MODE_XTS */

inline int iotex_aes_crypt_ecb( iotex_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
    return mbedtls_aes_crypt_ecb( (mbedtls_aes_context *)ctx, mode, input, output );
}

#if defined(IOTEX_CIPHER_MODE_CBC)
inline int iotex_aes_crypt_cbc( iotex_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    return mbedtls_aes_crypt_cbc( (mbedtls_aes_context *)ctx, mode, length, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_XTS)
inline int iotex_aes_crypt_xts( iotex_aes_xts_context *ctx,
                           int mode,
                           size_t length,
                           const unsigned char data_unit[16],
                           const unsigned char *input,
                           unsigned char *output )
{
    return mbedtls_aes_crypt_xts( (mbedtls_aes_xts_context *)ctx, mode, length, data_unit, input, output );
}
#endif /* IOTEX_CIPHER_MODE_XTS */

#if defined(IOTEX_CIPHER_MODE_CFB)
inline int iotex_aes_crypt_cfb128( iotex_aes_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    return mbedtls_aes_crypt_cfb128( (mbedtls_aes_context *)ctx, mode, length, iv_off, iv, input, output );
}

inline int iotex_aes_crypt_cfb8( iotex_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    return mbedtls_aes_crypt_cfb8( (mbedtls_aes_context *)ctx, mode, length, iv, input, output );
}
#endif /*IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_OFB)
inline int iotex_aes_crypt_ofb( iotex_aes_context *ctx,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    return mbedtls_aes_crypt_ofb( (mbedtls_aes_context *)ctx, length, iv_off, iv, input, output );
}

#endif /* IOTEX_CIPHER_MODE_OFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
inline int iotex_aes_crypt_ctr( iotex_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    return iotex_aes_crypt_ctr( (mbedtls_aes_context *)ctx, length, nc_off, nonce_counter, stream_block, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CTR */

inline int iotex_internal_aes_encrypt( iotex_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    return mbedtls_internal_aes_encrypt( (mbedtls_aes_context *)ctx, input, output );
}

inline int iotex_internal_aes_decrypt( iotex_aes_context *ctx,
                                  const unsigned char input[16],
                                  unsigned char output[16] )
{
    return mbedtls_internal_aes_decrypt( (mbedtls_aes_context *)ctx, input, output );
}

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
inline void iotex_md5_free( iotex_md5_context *ctx )
{
    mbedtls_md5_init( (mbedtls_md5_context *)ctx );    
}

inline void iotex_md5_clone( iotex_md5_context *dst, const iotex_md5_context *src )
{
    mbedtls_md5_clone( (mbedtls_md5_context *)dst, (mbedtls_md5_context *)src );
}

inline int iotex_md5_starts( iotex_md5_context *ctx )
{
    return mbedtls_md5_starts_ret( (mbedtls_md5_context *)ctx );
}

inline int iotex_md5_update( iotex_md5_context *ctx, const unsigned char *input, size_t ilen )
{
    return mbedtls_md5_update_ret( (mbedtls_md5_context *)ctx, input, ilen );
}

inline int iotex_md5_finish( iotex_md5_context *ctx, unsigned char output[16] )
{
    return mbedtls_md5_finish_ret( (mbedtls_md5_context *)ctx, output );
}

inline int iotex_md5( const unsigned char *input, size_t ilen, unsigned char output[16] )
{
    return mbedtls_md5_ret( input, ilen, output[16] );
}

/****************************************************************/
/* SHA1 */
/****************************************************************/
inline void iotex_sha1_init( iotex_sha1_context *ctx )
{
    mbedtls_sha1_init( (mbedtls_sha1_context *)ctx );
}
 
inline void iotex_sha1_free( iotex_sha1_context *ctx )
{
    mbedtls_sha1_free( (mbedtls_sha1_context *)ctx );
}

inline void iotex_sha1_clone( iotex_sha1_context *dst, const iotex_sha1_context *src )
{
    mbedtls_sha1_clone( (mbedtls_sha1_context *)dst, (mbedtls_sha1_context *)src );
}

inline int iotex_sha1_starts( iotex_sha1_context *ctx )
{
    return mbedtls_sha1_starts_ret( (mbedtls_sha1_context *)ctx );
}

inline int iotex_sha1_update( iotex_sha1_context *ctx, const unsigned char *input, size_t ilen )
{
    return mbedtls_sha1_update_ret( (mbedtls_sha1_context *)ctx, input, ilen );
}

inline int iotex_sha1_finish( iotex_sha1_context *ctx, unsigned char output[20] )
{
    return mbedtls_sha1_finish_ret( (mbedtls_sha1_context *)ctx, output );
}

inline int iotex_sha1( const unsigned char *input, size_t ilen, unsigned char output[20] )
{
    return mbedtls_sha1_ret( input, ilen, output );
}

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

inline void iotex_sha256_clone( iotex_sha256_context *dst, const iotex_sha256_context *src )
{
    mbedtls_sha256_clone( (mbedtls_sha256_context *)dst, (mbedtls_sha256_context *)src );
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

inline int iotex_sha256( const unsigned char *input, size_t ilen, unsigned char *output, int is224 )
{
    return mbedtls_sha256_ret( input, ilen, output, is224 );
}

/****************************************************************/
/* SHA512 */
/****************************************************************/
inline void iotex_sha512_init( iotex_sha512_context *ctx )
{
    mbedtls_sha512_init( (mbedtls_sha512_context *)ctx );
}

inline void iotex_sha512_free( iotex_sha512_context *ctx )
{
    mbedtls_sha512_free( (mbedtls_sha512_context *)ctx );
}

inline void iotex_sha512_clone( iotex_sha512_context *dst, const iotex_sha512_context *src )
{
    mbedtls_sha512_clone( (mbedtls_sha512_context *)dst, (mbedtls_sha512_context *)src );
}

inline int iotex_sha512_starts( iotex_sha512_context *ctx, int is384 )
{
    return mbedtls_sha512_starts_ret( (mbedtls_sha512_context *)ctx, is384 );
}

inline int iotex_sha512_update( iotex_sha512_context *ctx, const unsigned char *input, size_t ilen )
{
    return mbedtls_sha512_update_ret( (mbedtls_sha512_context *)ctx, input, ilen );
}

inline int iotex_sha512_finish( iotex_sha512_context *ctx, unsigned char *output )
{
    return mbedtls_sha512_finish_ret( (mbedtls_sha512_context *)ctx, output );
}

inline int iotex_sha512( const unsigned char *input, size_t ilen, unsigned char *output, int is384 )
{
    return mbedtls_sha512_ret( input, ilen, output, is384 );
}

/****************************************************************/
/* RIPEMD160 */
/****************************************************************/
inline void iotex_ripemd160_init( iotex_ripemd160_context *ctx )
{
    mbedtls_ripemd160_init( (mbedtls_ripemd160_context *)ctx );
}

inline void iotex_ripemd160_free( iotex_ripemd160_context *ctx )
{
    mbedtls_ripemd160_free( (mbedtls_ripemd160_context *)ctx );
}

inline void iotex_ripemd160_clone( iotex_ripemd160_context *dst, const iotex_ripemd160_context *src )
{
    mbedtls_ripemd160_clone( (mbedtls_ripemd160_context *)dst, (const mbedtls_ripemd160_context *)src );
}

inline int iotex_ripemd160_starts( iotex_ripemd160_context *ctx )
{
    return mbedtls_ripemd160_starts_ret( (mbedtls_ripemd160_context *)ctx );
}

inline int iotex_ripemd160_update( iotex_ripemd160_context *ctx, const unsigned char *input, size_t ilen )
{
    return mbedtls_ripemd160_update_ret( (mbedtls_ripemd160_context *)ctx, input, ilen );
}

inline int iotex_ripemd160_finish( iotex_ripemd160_context *ctx, unsigned char output[20] )
{
    return mbedtls_ripemd160_finish_ret( (mbedtls_ripemd160_context *)ctx, output );
}

inline int iotex_ripemd160( const unsigned char *input, size_t ilen, unsigned char output[20] )
{
    return mbedtls_ripemd160_ret( input, ilen, output );
}

/****************************************************************/
/* MAC */
/****************************************************************/
inline int iotex_cipher_cmac_starts( iotex_cipher_context_t *ctx,
                                const unsigned char *key, size_t keybits )
{
    return mbedtls_cipher_cmac_starts( (mbedtls_cipher_context_t *)ctx, key, keybits );
}

inline int iotex_cipher_cmac_update( iotex_cipher_context_t *ctx,
                                const unsigned char *input, size_t ilen )
{
    return mbedtls_cipher_cmac_update( (mbedtls_cipher_context_t *)ctx, input, ilen );
}

inline int iotex_cipher_cmac_finish( iotex_cipher_context_t *ctx,
                                unsigned char *output )
{
    return mbedtls_cipher_cmac_finish( (mbedtls_cipher_context_t *)ctx, output );
}                                

inline int iotex_cipher_cmac_reset( iotex_cipher_context_t *ctx )
{
    return mbedtls_cipher_cmac_reset( (mbedtls_cipher_context_t *)ctx );
}

inline int iotex_cipher_cmac( const iotex_cipher_info_t *cipher_info,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output )
{
    return mbedtls_cipher_cmac( (mbedtls_cipher_info_t *)cipher_info, key, keylen, input, ilen, output );
}

#if defined(IOTEX_AES_C)
inline int iotex_aes_cmac_prf_128( const unsigned char *key, size_t key_len,
                              const unsigned char *input, size_t in_len,
                              unsigned char output[16] )
{
    return mbedtls_aes_cmac_prf_128( key, key_len, input, in_len, output );
}
#endif /* IOTEX_AES_C */

/****************************************************************/
/* CAMELLIA */
/****************************************************************/

inline void iotex_camellia_init( iotex_camellia_context *ctx )
{
    mbedtls_camellia_init( (mbedtls_camellia_context *)ctx );
}

inline void iotex_camellia_free( iotex_camellia_context *ctx )
{
    mbedtls_camellia_free( (mbedtls_camellia_context *)ctx );
}

inline int iotex_camellia_setkey_enc( iotex_camellia_context *ctx,
                                 const unsigned char *key,
                                 unsigned int keybits )
{
    return mbedtls_camellia_setkey_enc( (mbedtls_camellia_context *)ctx, key, keybits );
}

inline int iotex_camellia_setkey_dec( iotex_camellia_context *ctx,
                                 const unsigned char *key,
                                 unsigned int keybits )
{
    return mbedtls_camellia_setkey_dec( (mbedtls_camellia_context *)ctx, key, keybits );
}

inline int iotex_camellia_crypt_ecb( iotex_camellia_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
    return mbedtls_camellia_crypt_ecb( (mbedtls_camellia_context *)ctx, mode, input, output );
}

#if defined(IOTEX_CIPHER_MODE_CBC)
inline int iotex_camellia_crypt_cbc( iotex_camellia_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output )
{
    return mbedtls_camellia_crypt_cbc( (mbedtls_camellia_context *)ctx, mode, length, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_CFB)
inline int iotex_camellia_crypt_cfb128( iotex_camellia_context *ctx,
                       int mode,
                       size_t length,
                       size_t *iv_off,
                       unsigned char iv[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    return mbedtls_camellia_crypt_cfb128( (mbedtls_camellia_context *)ctx, mode, length, iv_off, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
inline int iotex_camellia_crypt_ctr( iotex_camellia_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    return mbedtls_camellia_crypt_ctr( (mbedtls_camellia_context *)ctx, length, nc_off, nonce_counter, stream_block, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CTR */

/****************************************************************/
/* CIPHER */
/****************************************************************/

inline const int *iotex_cipher_list( void )
{
    return mbedtls_cipher_list();
}

inline const iotex_cipher_info_t *iotex_cipher_info_from_string( const char *cipher_name )
{
    return (iotex_cipher_info_t *)(mbedtls_cipher_info_from_string(cipher_name));
}

inline const iotex_cipher_info_t *iotex_cipher_info_from_type( const iotex_cipher_type_t cipher_type )
{
    return (iotex_cipher_info_t *)(mbedtls_cipher_info_from_type( (mbedtls_cipher_type_t)cipher_type));
}

inline const iotex_cipher_info_t *iotex_cipher_info_from_values(const iotex_cipher_id_t cipher_id, int key_bitlen, const iotex_cipher_mode_t mode ) 
{
    return (iotex_cipher_info_t *) mbedtls_cipher_info_from_values( (mbedtls_cipher_id_t) cipher_id, key_bitlen, (mbedtls_cipher_mode_t) mode );
}

inline void iotex_cipher_init( iotex_cipher_context_t *ctx )
{
    mbedtls_cipher_init( (mbedtls_cipher_context_t *)ctx );
}

inline void iotex_cipher_free( iotex_cipher_context_t *ctx )
{
    mbedtls_cipher_free( (mbedtls_cipher_context_t *)ctx );
}

inline int iotex_cipher_setup( iotex_cipher_context_t *ctx, const iotex_cipher_info_t *cipher_info )
{
    return mbedtls_cipher_setup( (mbedtls_cipher_context_t *)ctx, (mbedtls_cipher_info_t *)cipher_info );
}

inline int iotex_cipher_setkey( iotex_cipher_context_t *ctx, const unsigned char *key, int key_bitlen, const iotex_operation_t operation )
{
    return mbedtls_cipher_setkey( (mbedtls_cipher_context_t *)ctx, key, key_bitlen, (mbedtls_operation_t) operation );
}

#if defined(IOTEX_CIPHER_MODE_WITH_PADDING)
inline int iotex_cipher_set_padding_mode( iotex_cipher_context_t *ctx, iotex_cipher_padding_t mode )
{
    return mbedtls_cipher_set_padding_mode( (mbedtls_cipher_context_t *)ctx, (mbedtls_cipher_padding_t) mode );
}
#endif /* IOTEX_CIPHER_MODE_WITH_PADDING */

inline int iotex_cipher_set_iv( iotex_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len )
{
    return mbedtls_cipher_set_iv( (mbedtls_cipher_context_t *)ctx, iv, iv_len );
}

inline int iotex_cipher_reset( iotex_cipher_context_t *ctx )
{
    return mbedtls_cipher_reset( (mbedtls_cipher_context_t *)ctx );
}

#if defined(IOTEX_GCM_C) || defined(IOTEX_CHACHAPOLY_C)
inline int iotex_cipher_update_ad( iotex_cipher_context_t *ctx, const unsigned char *ad, size_t ad_len )
{
    return mbedtls_cipher_update_ad( (mbedtls_cipher_context_t *)ctx, ad, ad_len );
}
#endif /* IOTEX_GCM_C || IOTEX_CHACHAPOLY_C */

inline int iotex_cipher_update( iotex_cipher_context_t *ctx, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen )
{
    return mbedtls_cipher_update( (mbedtls_cipher_context_t *)ctx, input, ilen, output, olen );
}

inline int iotex_cipher_finish( iotex_cipher_context_t *ctx, unsigned char *output, size_t *olen )
{
    return mbedtls_cipher_finish( (mbedtls_cipher_context_t *)ctx, output, olen );
}

#if defined(IOTEX_GCM_C) || defined(IOTEX_CHACHAPOLY_C)
inline int iotex_cipher_write_tag( iotex_cipher_context_t *ctx, unsigned char *tag, size_t tag_len )
{
    return mbedtls_cipher_write_tag( (mbedtls_cipher_context_t *)ctx, tag, tag_len );
}

inline int iotex_cipher_check_tag( iotex_cipher_context_t *ctx, const unsigned char *tag, size_t tag_len )
{
    return mbedtls_cipher_check_tag( (mbedtls_cipher_context_t *)ctx, tag, tag_len );
}
#endif /* IOTEX_GCM_C || IOTEX_CHACHAPOLY_C */

inline int iotex_cipher_crypt( iotex_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen )
{
    return mbedtls_cipher_crypt( (mbedtls_cipher_context_t *)ctx,  iv, iv_len, input, ilen, output, olen );
}

#if defined(IOTEX_CIPHER_MODE_AEAD) || defined(IOTEX_NIST_KW_C)
inline int iotex_cipher_auth_encrypt_ext( iotex_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t output_len, size_t *olen, size_t tag_len )
{
    return mbedtls_cipher_auth_encrypt_ext( (mbedtls_cipher_context_t *)ctx, iv, iv_len, ad, ad_len, input, ilen, output, output_len, olen, tag_len);

}

inline int iotex_cipher_auth_decrypt_ext( iotex_cipher_context_t *ctx, const unsigned char *iv, size_t iv_len, const unsigned char *ad, size_t ad_len, const unsigned char *input, size_t ilen, unsigned char *output, size_t output_len, size_t *olen, size_t tag_len )
{
    return mbedtls_cipher_auth_decrypt_ext( (mbedtls_cipher_context_t *)ctx, iv, iv_len, ad, ad_len, input, ilen, output, output_len, olen, tag_len );
}
#endif

/****************************************************************/
/* AES */
/****************************************************************/
inline void iotex_aes_init( iotex_aes_context *ctx )
{
    mbedtls_aes_init( (mbedtls_aes_context *)ctx );
}

inline void iotex_aes_free( iotex_aes_context *ctx )
{
    mbedtls_aes_free( (mbedtls_aes_context *)ctx );
}

#if defined(IOTEX_CIPHER_MODE_XTS)
inline void iotex_aes_xts_init( iotex_aes_xts_context *ctx )
{
    mbedtls_aes_xts_init( (mbedtls_aes_xts_context *)ctx );
}

inline void iotex_aes_xts_free( iotex_aes_xts_context *ctx )
{
    mbedtls_aes_xts_free( (mbedtls_aes_xts_context *)ctx );
}
#endif /* IOTEX_CIPHER_MODE_XTS */

inline int iotex_aes_setkey_enc( iotex_aes_context *ctx, const unsigned char *key, unsigned int keybits )
{
    return mbedtls_aes_setkey_enc( (mbedtls_aes_context *)ctx, key, keybits );
}

inline int iotex_aes_setkey_dec( iotex_aes_context *ctx, const unsigned char *key, unsigned int keybits )
{
    return mbedtls_aes_setkey_dec( (mbedtls_aes_context *)ctx, key, keybits );
}

#if defined(IOTEX_CIPHER_MODE_XTS)
inline int iotex_aes_xts_setkey_enc( iotex_aes_xts_context *ctx, const unsigned char *key, unsigned int keybits )
{
    return mbedtls_aes_xts_setkey_enc( (mbedtls_aes_xts_context *)ctx, key, keybits );
}

inline int iotex_aes_xts_setkey_dec( iotex_aes_xts_context *ctx, const unsigned char *key, unsigned int keybits )
{
   return mbedtls_aes_xts_setkey_dec( (mbedtls_aes_xts_context *)ctx, key, keybits );
}
#endif /* IOTEX_CIPHER_MODE_XTS */

inline int iotex_aes_crypt_ecb( iotex_aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16] )
{
    return mbedtls_aes_crypt_ecb( (mbedtls_aes_context *)ctx, mode, input, output );
}

#if defined(IOTEX_CIPHER_MODE_CBC)
inline int iotex_aes_crypt_cbc( iotex_aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_cbc( (mbedtls_aes_context *)ctx, mode, length, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CBC */

#if defined(IOTEX_CIPHER_MODE_XTS)
inline int iotex_aes_crypt_xts( iotex_aes_xts_context *ctx, int mode, size_t length, const unsigned char data_unit[16], const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_xts( (mbedtls_aes_xts_context *)ctx, mode, length, data_unit, input, output );
}
#endif /* IOTEX_CIPHER_MODE_XTS */

#if defined(IOTEX_CIPHER_MODE_CFB)
inline int iotex_aes_crypt_cfb128( iotex_aes_context *ctx, int mode, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_cfb128( (mbedtls_aes_context *)ctx, mode, length, iv_off, iv, input, output );
}

inline int iotex_aes_crypt_cfb8( iotex_aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_cfb8( (mbedtls_aes_context *)ctx, mode, length, iv, input, output );
}
#endif /*IOTEX_CIPHER_MODE_CFB */

#if defined(IOTEX_CIPHER_MODE_OFB)
int iotex_aes_crypt_ofb( iotex_aes_context *ctx, size_t length, size_t *iv_off, unsigned char iv[16], const unsigned char *input, unsigned char *output )
{
    return mbedtls_aes_crypt_ofb( (mbedtls_aes_context *)ctx, length, iv_off, iv, input, output );
}
#endif /* IOTEX_CIPHER_MODE_OFB */

#if defined(IOTEX_CIPHER_MODE_CTR)
inline int iotex_aes_crypt_ctr( iotex_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
    return mbedtls_aes_crypt_ctr( (mbedtls_aes_context *)ctx, length, nc_off, nonce_counter, stream_block, input, output );
}
#endif /* IOTEX_CIPHER_MODE_CTR */

inline int iotex_internal_aes_encrypt( iotex_aes_context *ctx, const unsigned char input[16], unsigned char output[16] )
{
    return mbedtls_internal_aes_encrypt( (mbedtls_aes_context *)ctx, input, output );
}

inline int iotex_internal_aes_decrypt( iotex_aes_context *ctx, const unsigned char input[16], unsigned char output[16] )
{
    return mbedtls_internal_aes_decrypt( (mbedtls_aes_context *)ctx, input, output );
}

/****************************************************************/
/* RSA */
/****************************************************************/
inline void iotex_rsa_init( iotex_rsa_context *ctx )
{
    mbedtls_rsa_init( (mbedtls_rsa_context *)ctx );
}

inline int iotex_rsa_set_padding( iotex_rsa_context *ctx, int padding,
                             iotex_md_type_t hash_id )
{     
    return mbedtls_rsa_set_padding((mbedtls_rsa_context *)ctx, padding, hash_id );
}

inline int iotex_rsa_import( iotex_rsa_context *ctx,
                        const iotex_mpi *N,
                        const iotex_mpi *P, const iotex_mpi *Q,
                        const iotex_mpi *D, const iotex_mpi *E )
{
    return mbedtls_rsa_import( (mbedtls_rsa_context *)ctx, (mbedtls_mpi *)N, (mbedtls_mpi *)P, (mbedtls_mpi *)Q, (mbedtls_mpi *)D, (mbedtls_mpi *)E );
}

inline int iotex_rsa_import_raw( iotex_rsa_context *ctx,
                            unsigned char const *N, size_t N_len,
                            unsigned char const *P, size_t P_len,
                            unsigned char const *Q, size_t Q_len,
                            unsigned char const *D, size_t D_len,
                            unsigned char const *E, size_t E_len )
{
    return mbedtls_rsa_import_raw( (mbedtls_rsa_context *)ctx, N, N_len, P, P_len, Q, Q_len, D, D_len, E, E_len );
}

inline int iotex_rsa_complete( iotex_rsa_context *ctx )
{
    return mbedtls_rsa_complete( (mbedtls_rsa_context *)ctx );
}

inline int iotex_rsa_export( const iotex_rsa_context *ctx,
                        iotex_mpi *N, iotex_mpi *P, iotex_mpi *Q,
                        iotex_mpi *D, iotex_mpi *E )
{
    return mbedtls_rsa_export( (mbedtls_rsa_context *)ctx,
                        (mbedtls_mpi *)N, (mbedtls_mpi *)P, (mbedtls_mpi *)Q, (mbedtls_mpi *)D, (mbedtls_mpi *)E );
}

inline int iotex_rsa_export_raw( const iotex_rsa_context *ctx,
                            unsigned char *N, size_t N_len,
                            unsigned char *P, size_t P_len,
                            unsigned char *Q, size_t Q_len,
                            unsigned char *D, size_t D_len,
                            unsigned char *E, size_t E_len )
{
    return mbedtls_rsa_export_raw( (mbedtls_rsa_context *)ctx, N, N_len, P, P_len, Q, Q_len, D, D_len, E, E_len );
}

inline int iotex_rsa_export_crt( const iotex_rsa_context *ctx,
                            iotex_mpi *DP, iotex_mpi *DQ, iotex_mpi *QP )
{
    return mbedtls_rsa_export_crt( (mbedtls_rsa_context *)ctx,
                            (mbedtls_mpi *)DP, (mbedtls_mpi *)DQ, (mbedtls_mpi *)QP );
}

inline size_t iotex_rsa_get_len( const iotex_rsa_context *ctx )
{
    return mbedtls_rsa_get_len( (mbedtls_rsa_context *)ctx );
}

inline int iotex_rsa_gen_key( iotex_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         unsigned int nbits, int exponent )
{
    return mbedtls_rsa_gen_key( (mbedtls_rsa_context *)ctx, f_rng, p_rng, nbits, exponent );
}

inline int iotex_rsa_check_pubkey( const iotex_rsa_context *ctx )
{
    return mbedtls_rsa_check_pubkey( (mbedtls_rsa_context *)ctx );
}

inline int iotex_rsa_check_privkey( const iotex_rsa_context *ctx )
{
    return mbedtls_rsa_check_privkey( (mbedtls_rsa_context *)ctx );
}

inline int iotex_rsa_check_pub_priv( const iotex_rsa_context *pub,
                                const iotex_rsa_context *prv )
{
    return mbedtls_rsa_check_pub_priv( (mbedtls_rsa_context *)pub, (mbedtls_rsa_context *)prv );
}

inline int iotex_rsa_public( iotex_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    return mbedtls_rsa_public( (mbedtls_rsa_context *)ctx,  input, output );
}

inline int iotex_rsa_private( iotex_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    return mbedtls_rsa_private( (mbedtls_rsa_context *)ctx, f_rng, p_rng, input, output );
}

inline int iotex_rsa_pkcs1_encrypt( iotex_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t ilen,
                       const unsigned char *input,
                       unsigned char *output )
{
    return mbedtls_rsa_pkcs1_encrypt( (mbedtls_rsa_context *)ctx, f_rng, p_rng, ilen, input, output );
}

inline int iotex_rsa_rsaes_pkcs1_v15_encrypt( iotex_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 size_t ilen,
                                 const unsigned char *input,
                                 unsigned char *output )
{
    return mbedtls_rsa_rsaes_pkcs1_v15_encrypt( (mbedtls_rsa_context *)ctx, f_rng, p_rng, ilen, input, output );
}

inline int iotex_rsa_rsaes_oaep_encrypt( iotex_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t ilen,
                            const unsigned char *input,
                            unsigned char *output )
{
    return mbedtls_rsa_rsaes_oaep_encrypt( (mbedtls_rsa_context *)ctx, f_rng, p_rng, label, label_len, ilen, input, output );
}

inline int iotex_rsa_pkcs1_decrypt( iotex_rsa_context *ctx,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng,
                       size_t *olen,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t output_max_len )
{
    return mbedtls_rsa_pkcs1_decrypt( (mbedtls_rsa_context *)ctx, f_rng, p_rng, olen, input, output, output_max_len );
}

inline int iotex_rsa_rsaes_pkcs1_v15_decrypt( iotex_rsa_context *ctx,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng,
                                 size_t *olen,
                                 const unsigned char *input,
                                 unsigned char *output,
                                 size_t output_max_len )
{
    return mbedtls_rsa_rsaes_pkcs1_v15_decrypt( (mbedtls_rsa_context *)ctx, f_rng, p_rng, olen, input, output, output_max_len );
}

inline int iotex_rsa_rsaes_oaep_decrypt( iotex_rsa_context *ctx,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng,
                            const unsigned char *label, size_t label_len,
                            size_t *olen,
                            const unsigned char *input,
                            unsigned char *output,
                            size_t output_max_len )
{
    return mbedtls_rsa_rsaes_oaep_decrypt( (mbedtls_rsa_context *)ctx, f_rng, p_rng, label, label_len, olen, input, output, output_max_len );
}

inline int iotex_rsa_pkcs1_sign( iotex_rsa_context *ctx,
                    int (*f_rng)(void *, unsigned char *, size_t),
                    void *p_rng,
                    iotex_md_type_t md_alg,
                    unsigned int hashlen,
                    const unsigned char *hash,
                    unsigned char *sig )
{
    return mbedtls_rsa_pkcs1_sign( (mbedtls_rsa_context *)ctx, f_rng, p_rng, (mbedtls_md_type_t) md_alg, hashlen, hash, sig );
}

inline int iotex_rsa_rsassa_pkcs1_v15_sign( iotex_rsa_context *ctx,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng,
                               iotex_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               unsigned char *sig )
{
    return mbedtls_rsa_rsassa_pkcs1_v15_sign( (mbedtls_rsa_context *)ctx, f_rng, p_rng, (mbedtls_md_type_t) md_alg, hashlen, hash, sig );
}

inline int iotex_rsa_rsassa_pss_sign_ext( iotex_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         iotex_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         int saltlen,
                         unsigned char *sig )
{
    return mbedtls_rsa_rsassa_pss_sign_ext( (mbedtls_rsa_context *)ctx, f_rng, p_rng, (mbedtls_md_type_t) md_alg, hashlen, hash, saltlen, sig );
}

inline int iotex_rsa_rsassa_pss_sign( iotex_rsa_context *ctx,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng,
                         iotex_md_type_t md_alg,
                         unsigned int hashlen,
                         const unsigned char *hash,
                         unsigned char *sig )
{
    return mbedtls_rsa_rsassa_pss_sign( (mbedtls_rsa_context *)ctx, f_rng, p_rng, (mbedtls_md_type_t) md_alg, hashlen, hash, sig );
}

inline int iotex_rsa_pkcs1_verify( iotex_rsa_context *ctx,
                      iotex_md_type_t md_alg,
                      unsigned int hashlen,
                      const unsigned char *hash,
                      const unsigned char *sig )
{
    return mbedtls_rsa_pkcs1_verify( (mbedtls_rsa_context *)ctx, (mbedtls_md_type_t) md_alg, hashlen, hash, sig );
}

inline int iotex_rsa_rsassa_pkcs1_v15_verify( iotex_rsa_context *ctx,
                                 iotex_md_type_t md_alg,
                                 unsigned int hashlen,
                                 const unsigned char *hash,
                                 const unsigned char *sig )
{
    return mbedtls_rsa_rsassa_pkcs1_v15_verify( (mbedtls_rsa_context *)ctx, (mbedtls_md_type_t) md_alg, hashlen, hash, sig );
}

inline int iotex_rsa_rsassa_pss_verify( iotex_rsa_context *ctx,
                           iotex_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           const unsigned char *sig )
{
    return mbedtls_rsa_rsassa_pss_verify( (mbedtls_rsa_context *)ctx, (mbedtls_md_type_t) md_alg, hashlen, hash, sig );
}

inline int iotex_rsa_rsassa_pss_verify_ext( iotex_rsa_context *ctx,
                               iotex_md_type_t md_alg,
                               unsigned int hashlen,
                               const unsigned char *hash,
                               iotex_md_type_t mgf1_hash_id,
                               int expected_salt_len,
                               const unsigned char *sig )
{
    return mbedtls_rsa_rsassa_pss_verify_ext( (mbedtls_rsa_context *)ctx, (mbedtls_md_type_t) md_alg, hashlen, hash, (mbedtls_md_type_t) mgf1_hash_id, expected_salt_len, sig );
}

inline int iotex_rsa_copy( iotex_rsa_context *dst, const iotex_rsa_context *src )
{
    return mbedtls_rsa_copy( (mbedtls_rsa_context *)dst, (mbedtls_rsa_context *)src );
}

inline void iotex_rsa_free( iotex_rsa_context *ctx )
{
    mbedtls_rsa_free( (mbedtls_rsa_context *)ctx );
}

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
inline const iotex_pk_info_t *iotex_pk_info_from_type( iotex_pk_type_t pk_type )
{
    return (iotex_pk_info_t *)mbedtls_pk_info_from_type( (mbedtls_pk_type_t) pk_type );
}

inline void iotex_pk_init( iotex_pk_context *ctx )
{
    mbedtls_pk_init( (mbedtls_pk_context *)ctx );
}

inline void iotex_pk_free( iotex_pk_context *ctx )
{
    mbedtls_pk_free( (mbedtls_pk_context *)ctx );
}

#if defined(IOTEX_ECDSA_C) && defined(IOTEX_ECP_RESTARTABLE)
inline void iotex_pk_restart_init( iotex_pk_restart_ctx *ctx )
{
    mbedttls_pk_restart_init( (mbedtls_pk_restart_ctx *)ctx );
}

inline void iotex_pk_restart_free( iotex_pk_restart_ctx *ctx )
{
    mbedtls_pk_restart_free( mbedlts_pk_restart_ctx *ctx );
}
#endif /* IOTEX_ECDSA_C && IOTEX_ECP_RESTARTABLE */

inline int iotex_pk_setup( iotex_pk_context *ctx, const iotex_pk_info_t *info )
{
    return mbedtls_pk_setup( (mbedtls_pk_context *)ctx, (mbedtls_pk_info_t *)info );
}

#if defined(IOTEX_USE_PSA_CRYPTO)
int iotex_pk_setup_opaque( iotex_pk_context *ctx, const iotex_svc_key_id_t key )
{
    return mbedtls_pk_setup_opaque( (mbedtls_pk_context *)ctx, (psa_key_handle_t) key );
}
#endif /* IOTEX_USE_PSA_CRYPTO */

#if defined(IOTEX_PK_RSA_ALT_SUPPORT)
int iotex_pk_setup_rsa_alt( iotex_pk_context *ctx, void * key,
                         iotex_pk_rsa_alt_decrypt_func decrypt_func,
                         iotex_pk_rsa_alt_sign_func sign_func,
                         iotex_pk_rsa_alt_key_len_func key_len_func );
#endif /* IOTEX_PK_RSA_ALT_SUPPORT */

size_t iotex_pk_get_bitlen( const iotex_pk_context *ctx );

int iotex_pk_can_do( const iotex_pk_context *ctx, iotex_pk_type_t type );

#if defined(IOTEX_USE_PSA_CRYPTO)
int iotex_pk_can_do_ext( const iotex_pk_context *ctx, psa_algorithm_t alg,
                           psa_key_usage_t usage );
#endif /* IOTEX_USE_PSA_CRYPTO */

int iotex_pk_verify( iotex_pk_context *ctx, iotex_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len );

int iotex_pk_verify_restartable( iotex_pk_context *ctx,
               iotex_md_type_t md_alg,
               const unsigned char *hash, size_t hash_len,
               const unsigned char *sig, size_t sig_len,
               iotex_pk_restart_ctx *rs_ctx );

int iotex_pk_verify_ext( iotex_pk_type_t type, const void *options,
                   iotex_pk_context *ctx, iotex_md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   const unsigned char *sig, size_t sig_len );

int iotex_pk_sign( iotex_pk_context *ctx, iotex_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t sig_size, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

#if defined(IOTEX_PSA_CRYPTO_C)
int iotex_pk_sign_ext( iotex_pk_type_t pk_type,
                         iotex_pk_context *ctx,
                         iotex_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng );
#endif /* IOTEX_PSA_CRYPTO_C */

int iotex_pk_sign_restartable( iotex_pk_context *ctx,
             iotex_md_type_t md_alg,
             const unsigned char *hash, size_t hash_len,
             unsigned char *sig, size_t sig_size, size_t *sig_len,
             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
             iotex_pk_restart_ctx *rs_ctx );

int iotex_pk_decrypt( iotex_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int iotex_pk_encrypt( iotex_pk_context *ctx,
                const unsigned char *input, size_t ilen,
                unsigned char *output, size_t *olen, size_t osize,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int iotex_pk_check_pair( const iotex_pk_context *pub,
                           const iotex_pk_context *prv,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng );

int iotex_pk_debug( const iotex_pk_context *ctx, iotex_pk_debug_item *items );

const char * iotex_pk_get_name( const iotex_pk_context *ctx );

iotex_pk_type_t iotex_pk_get_type( const iotex_pk_context *ctx );

#if defined(IOTEX_PK_PARSE_C)
int iotex_pk_parse_key( iotex_pk_context *ctx,
              const unsigned char *key, size_t keylen,
              const unsigned char *pwd, size_t pwdlen,
              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int iotex_pk_parse_public_key( iotex_pk_context *ctx,
                         const unsigned char *key, size_t keylen );

#if defined(IOTEX_FS_IO)
int iotex_pk_parse_keyfile( iotex_pk_context *ctx,
                  const char *path, const char *password,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int iotex_pk_parse_public_keyfile( iotex_pk_context *ctx, const char *path );
#endif /* IOTEX_FS_IO */
#endif /* IOTEX_PK_PARSE_C */

#if defined(IOTEX_PK_WRITE_C)
int iotex_pk_write_key_der( const iotex_pk_context *ctx, unsigned char *buf, size_t size );

int iotex_pk_write_pubkey_der( const iotex_pk_context *ctx, unsigned char *buf, size_t size );

#if defined(IOTEX_PEM_WRITE_C)
int iotex_pk_write_pubkey_pem( const iotex_pk_context *ctx, unsigned char *buf, size_t size );

int iotex_pk_write_key_pem( const iotex_pk_context *ctx, unsigned char *buf, size_t size );
#endif /* IOTEX_PEM_WRITE_C */
#endif /* IOTEX_PK_WRITE_C */

#if defined(IOTEX_PK_PARSE_C)
int iotex_pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        iotex_pk_context *pk );
#endif /* IOTEX_PK_PARSE_C */

#if defined(IOTEX_PK_WRITE_C)
int iotex_pk_write_pubkey( unsigned char **p, unsigned char *start,
                     const iotex_pk_context *key );
#endif /* IOTEX_PK_WRITE_C */

#if defined(IOTEX_FS_IO)
int iotex_pk_load_file( const char *path, unsigned char **buf, size_t *n );
#endif

#if defined(IOTEX_USE_PSA_CRYPTO)
int iotex_pk_wrap_as_opaque( iotex_pk_context *pk,
                               iotex_svc_key_id_t *key,
                               psa_algorithm_t alg,
                               psa_key_usage_t usage,
                               psa_algorithm_t alg2 );
#endif /* IOTEX_USE_PSA_CRYPTO */

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

    ret =  mbedtls_mpi_read_string(&key->d, 16, sebuf);
    if(ret)
        goto exit;

    mbedtls_ecp_check_privkey( &key->grp, &key->d );
    if(ret)
        goto exit;

exit:
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
    return mbedtls_ecp_point_read_binary( (const mbedtls_ecp_group *)grp, (mbedtls_ecp_point *)pt, buf, ilen );
}

inline int iotex_ecp_check_pubkey( const iotex_ecp_group *grp,
                              const iotex_ecp_point *pt )
{
    return mbedtls_ecp_check_pubkey( (const mbedtls_ecp_group *)grp, (const mbedtls_ecp_point *)pt );
}

inline nt iotex_ecp_write_key( iotex_ecp_keypair *key,
                           unsigned char *buf, size_t buflen )
{
    return iotex_ecp_write_key( (iotex_ecp_keypair *)key, buf, buflen);
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

inline int iotex_ecdsa_sign_det_ext( iotex_ecp_group *grp, iotex_mpi *r,
                            iotex_mpi *s, const iotex_mpi *d,
                            const unsigned char *buf, size_t blen,
                            iotex_md_type_t md_alg,
                            int (*f_rng_blind)(void *, unsigned char *, size_t),
                            void *p_rng_blind )
{
    return mbedtls_ecdsa_sign_det_ext( (mbedtls_ecp_group *)grp, (mbedtls_mpi *)r, (mbedtls_mpi *)s, (mbedtls_mpi *)d, buf, blen, (mbedtls_md_type_t) md_alg, f_rng_blind, p_rng_blind );
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#define CIPHER_UNSUPPORTED "unsupported"

#include <sodium.h>

#include "ppbloom.h"
#include "stream.h"
#include "utils.h"

#define SODIUM_BLOCK_SIZE   64

/*
 * Spec: http://shadowsocks.org/en/spec/Stream-Ciphers.html
 *
 * Stream ciphers provide only confidentiality. Data integrity and authenticity is not guaranteed. Users should use AEAD
 * ciphers whenever possible.
 *
 * Stream Encryption/Decryption
 *
 * Stream_encrypt is a function that takes a secret key, an initialization vector, a message, and produces a ciphertext
 * with the same length as the message.
 *
 *      Stream_encrypt(key, IV, message) => ciphertext
 *
 * Stream_decrypt is a function that takes a secret key, an initializaiton vector, a ciphertext, and produces the
 * original message.
 *
 *      Stream_decrypt(key, IV, ciphertext) => message
 *
 * TCP
 *
 * A stream cipher encrypted TCP stream starts with a randomly generated initializaiton vector, followed by encrypted
 * payload data.
 *
 *      [IV][encrypted payload]
 *
 * UDP
 *
 * A stream cipher encrypted UDP packet has the following structure:
 *
 *      [IV][encrypted payload]
 *
 * Each UDP packet is encrypted/decrypted independently with a randomly generated initialization vector.
 *
 */

#define NONE                -1
#define TABLE               0
#define RC4                 1
#define RC4_MD5             2
#define AES_128_CFB         3
#define AES_192_CFB         4
#define AES_256_CFB         5
#define AES_128_CTR         6
#define AES_192_CTR         7
#define AES_256_CTR         8
#define BF_CFB              9
#define CAMELLIA_128_CFB    10
#define CAMELLIA_192_CFB    11
#define CAMELLIA_256_CFB    12
#define CAST5_CFB           13
#define DES_CFB             14
#define IDEA_CFB            15
#define RC2_CFB             16
#define SEED_CFB            17
#define SALSA20             18
#define CHACHA20            19
#define CHACHA20IETF        20

#define MAMMADI_KEY         10

const char *supported_stream_ciphers[STREAM_CIPHER_NUM] = {
    "table",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf"
};

static const char *supported_stream_ciphers_mbedtls[STREAM_CIPHER_NUM] = {
    "table",
    "ARC4-128",
    "ARC4-128",
    "AES-128-CFB128",
    "AES-192-CFB128",
    "AES-256-CFB128",
    "AES-128-CTR",
    "AES-192-CTR",
    "AES-256-CTR",
    "BLOWFISH-CFB64",
    "CAMELLIA-128-CFB128",
    "CAMELLIA-192-CFB128",
    "CAMELLIA-256-CFB128",
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    CIPHER_UNSUPPORTED,
    "salsa20",
    "chacha20",
    "chacha20-ietf"
};

static const int supported_stream_ciphers_nonce_size[STREAM_CIPHER_NUM] = {
    0, 0, 16, 16, 16, 16, 16, 16, 16, 8, 16, 16, 16, 8, 8, 8, 8, 16, 8, 8, 12
};

static const int supported_stream_ciphers_key_size[STREAM_CIPHER_NUM] = {
    0, 16, 16, 16, 24, 32, 16, 24, 32, 16, 16, 24, 32, 16, 8, 16, 16, 16, 32, 32, 32
};

int
cipher_nonce_size(const cipher_t *cipher)
{
    if (cipher == NULL) {
        return 0;
    }
    return cipher->info->iv_size;
}

int
cipher_key_size(const cipher_t *cipher)
{
    /*
     * Semi-API changes (technically public, morally prnonceate)
     * Renamed a few headers to include _internal in the name. Those headers are
     * not supposed to be included by users.
     * Changed md_info_t into an opaque structure (use md_get_xxx() accessors).
     * Changed pk_info_t into an opaque structure.
     * Changed cipher_base_t into an opaque structure.
     */
    if (cipher == NULL) {
        return 0;
    }
    /* From Version 1.2.7 released 2013-04-13 Default Blowfish keysize is now 128-bits */
    return cipher->info->key_bitlen / 8;
}

const cipher_kt_t *
stream_get_cipher_type(int method)
{
    if (method <= TABLE || method >= STREAM_CIPHER_NUM) {
        LOGE("stream_get_cipher_type(): Illegal method");
        return NULL;
    }

    if (method == RC4_MD5) {
        method = RC4;
    }

    if (method >= SALSA20) {
        return NULL;
    }

    const char *ciphername  = supported_stream_ciphers[method];
    const char *mbedtlsname = supported_stream_ciphers_mbedtls[method];
    if (strcmp(mbedtlsname, CIPHER_UNSUPPORTED) == 0) {
        LOGE("Cipher %s currently is not supported by mbed TLS library",
             ciphername);
        return NULL;
    }
    return mbedtls_cipher_info_from_string(mbedtlsname);
}

void
stream_cipher_ctx_init(cipher_ctx_t *ctx, int method, int enc)
{
    if (method <= TABLE || method >= STREAM_CIPHER_NUM) {
        LOGE("stream_ctx_init(): Illegal method");
        return;
    }

    if (method >= SALSA20) {
        return;
    }

    const char *ciphername    = supported_stream_ciphers[method];
    const cipher_kt_t *cipher = stream_get_cipher_type(method);

    ctx->evp = ss_malloc(sizeof(cipher_evp_t));
    memset(ctx->evp, 0, sizeof(cipher_evp_t));
    cipher_evp_t *evp = ctx->evp;

    if (cipher == NULL) {
        LOGE("Cipher %s not found in mbed TLS library", ciphername);
        FATAL("Cannot initialize mbed TLS cipher");
    }
    mbedtls_cipher_init(evp);
    if (mbedtls_cipher_setup(evp, cipher) != 0) {
        FATAL("Cannot initialize mbed TLS cipher context");
    }
}

void
stream_ctx_release(cipher_ctx_t *cipher_ctx)
{
    if (cipher_ctx->chunk != NULL) {
        bfree(cipher_ctx->chunk);
        ss_free(cipher_ctx->chunk);
        cipher_ctx->chunk = NULL;
    }

    if (cipher_ctx->cipher->method >= SALSA20) {
        return;
    }

    mbedtls_cipher_free(cipher_ctx->evp);
    ss_free(cipher_ctx->evp);
}

void
cipher_ctx_set_nonce(cipher_ctx_t *cipher_ctx, size_t nonce_len, int enc)
{
	char pass[32] = "pass";
    cipher_t *cipher = cipher_ctx->cipher;

	unsigned char key_mammadi[32];
	int i = 0;
	key_mammadi[0] = 0;
	strcpy((char *)key_mammadi, pass);
	for( i=strlen(pass) ; i<31 ; i++)
	{
		key_mammadi[i] = ' ';
	}
	key_mammadi[31] = 0;

	unsigned char iv_mammadi[16];
	for( i=0 ; i<16 ; i++ )
	{
		iv_mammadi[i] = i;
	}

	printf("**** nonce_len = %zu ****\n", nonce_len);
	printf("**** key = <%s> , key_len = %zu ****\n", key_mammadi, cipher->key_len);

    cipher_evp_t *evp = cipher_ctx->evp;
    if (evp == NULL) {
        LOGE("cipher_ctx_set_nonce(): Cipher context is null");
        return;
    }
    if (mbedtls_cipher_setkey(evp, key_mammadi, cipher->key_len * 8, enc) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher key");
    }
    if (mbedtls_cipher_set_iv(evp, iv_mammadi, nonce_len) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher NONCE");
    }
    if (mbedtls_cipher_reset(evp) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot finalize mbed TLS cipher context");
    }

#ifdef SS_DEBUG
    dump("NONCE", (char *)iv_mammadi, nonce_len);
#endif
}

//static int
//cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *output, size_t *olen,
//                  const uint8_t *input, size_t ilen)
//{
//    cipher_evp_t *evp = ctx->evp;
//    return mbedtls_cipher_update(evp, (const uint8_t *)input, ilen,
//                                 (uint8_t *)output, olen);
//}

void chertChapkon(char *data, int len)
{
    int i;

    printf("len = %d; data = ", len);
    for ( i=0 ; i< len ; i++)
    {
        if( data[i]>31 && data[i]<128 )
        {
            printf("%c", data[i]);
        }
        else
        {
            printf("*");
        }
	}
    printf("\n");
}

int
stream_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    printf("stream_encrypt\n");
    if (cipher_ctx == NULL)
        cipher_ctx = 0;

    static buffer_t tmp = { 0, 0, 0, NULL };

    brealloc(&tmp, plaintext->len, capacity);

    //dump("PLAIN", plaintext->data, plaintext->len);

	uint16_t buf;
	int i; 
    for( i=0 ; i<plaintext->len ; i++ )
    {
        buf  = (uint8_t)plaintext->data[i];
        buf += MAMMADI_KEY;
        if( buf>255 )
        {
            buf -= 256;
        }
        uint8_t buf_8 = buf;
        plaintext->data[i] = (char) buf_8;
    }

    //dump("CIPHER", plaintext->data , plaintext->len);

    return CRYPTO_OK;
}

int
stream_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
	printf("stream_decrypt\n");
    if (cipher_ctx == NULL)
        cipher_ctx = 0;

    static buffer_t tmp = { 0, 0, 0, NULL };

    brealloc(&tmp, ciphertext->len, capacity);
	
	int16_t buf;
	int i;
	for( i=0 ; i<ciphertext->len ; i++ )
    {
        buf  = (uint8_t)ciphertext->data[i];
        buf -= MAMMADI_KEY;
        if( buf<0 )
        {
            buf += 256;
        }
		//printf("buf = %u, i = %d \n", buf, i);
        uint8_t buf_8 = buf;
        ciphertext->data[i] = (char) buf_8;
    }

    //chertChapkon(ciphertext->data, ciphertext->len);

    return CRYPTO_OK;
}

void
stream_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc)
{
    sodium_memzero(cipher_ctx, sizeof(cipher_ctx_t));
    stream_cipher_ctx_init(cipher_ctx, cipher->method, enc);
    cipher_ctx->cipher = cipher;

    if (enc) {
        rand_bytes(cipher_ctx->nonce, cipher->nonce_len);
    }
}

cipher_t *
stream_key_init(int method, const char *pass, const char *key)
{
    if (method <= TABLE || method >= STREAM_CIPHER_NUM) {
        LOGE("cipher->key_init(): Illegal method");
        return NULL;
    }

    cipher_t *cipher = (cipher_t *)ss_malloc(sizeof(cipher_t));
    memset(cipher, 0, sizeof(cipher_t));

    if (method == SALSA20 || method == CHACHA20 || method == CHACHA20IETF) {
        cipher_kt_t *cipher_info = (cipher_kt_t *)ss_malloc(sizeof(cipher_kt_t));
        cipher->info             = cipher_info;
        cipher->info->base       = NULL;
        cipher->info->key_bitlen = supported_stream_ciphers_key_size[method] * 8;
        cipher->info->iv_size    = supported_stream_ciphers_nonce_size[method];
    } else {
        cipher->info = (cipher_kt_t *)stream_get_cipher_type(method);
    }

    if (cipher->info == NULL && cipher->key_len == 0) {
        LOGE("Cipher %s not found in crypto library", supported_stream_ciphers[method]);
        FATAL("Cannot initialize cipher");
    }

    if (key != NULL)
        cipher->key_len = crypto_parse_key(key, cipher->key, cipher_key_size(cipher));
    else
        cipher->key_len = crypto_derive_key(pass, cipher->key, cipher_key_size(cipher));

    if (cipher->key_len == 0) {
        FATAL("Cannot generate key and NONCE");
    }
    if (method == RC4_MD5) {
        cipher->nonce_len = 16;
    } else {
        cipher->nonce_len = cipher_nonce_size(cipher);
    }
    cipher->method = method;

    return cipher;
}

cipher_t *
stream_init(const char *pass, const char *key, const char *method)
{
    int m = TABLE;
    if (method != NULL) {
        for (m = TABLE; m < STREAM_CIPHER_NUM; m++)
            if (strcmp(method, supported_stream_ciphers[m]) == 0) {
                break;
            }
        if (m >= STREAM_CIPHER_NUM) {
            LOGE("Invalid cipher name: %s, use chacha20-ietf instead", method);
            m = CHACHA20IETF;
        }
    }
    if (m == TABLE) {
        LOGE("Table is deprecated");
        return NULL;
    }
    return stream_key_init(m, pass, key);
}

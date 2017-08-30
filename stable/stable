/* AES-CBC test vectors from http://www.ietf.org/rfc/rfc3602.txt

    Test Vectors (Trailing '\0' of a character string not included in test):

    Case #1: Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key

    Key       : 0x06a9214036b8a15b512e03d534120006
    IV        : 0x3dafba429d9eb430b422da802c9fac41
    Plaintext : "test post please"
    Ciphertext: 0xe353779c1079aeb82708942dbe77181a

*/
#include <stdlib.h>
#include "wiced.h"
#include "wiced_security.h"
#include "wwd_debug.h"
#include "string.h"
#include "wiced_time.h"
#include "crypto_api.h"
#include "crypto_core.h"

#define NUM_OF_AES_CTR_TESTS     1
#define AES_CTR_IV_LENGTH        16              /* Length of the AES-CBC initialization vector in octets */
#define AES_CTR_KEY_LENGTH       128             /* Length of the AES-CBC key in bits */

hw_aes_context_t context_aes;

struct aes_cbc_test_case {
    int num;
    char label[32];
    uint8_t hex_key[16];
    uint8_t iv[16];
    int key_len;
    uint8_t hex_plain_text[128];
    char* char_plain_text;
    int data_len;
} aes_ctr_test_cases[NUM_OF_AES_CTR_TESTS] = {
    {
        .num = 1,
        .label = "Test Case AES-CBC-1 (hardware)",
        .hex_key = {
                0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
                0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06,
            },
        .iv = {
                0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
                0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41,
            },
        .key_len = 16,
        .hex_plain_text = { 0 },
        .char_plain_text = "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",
        .data_len = 2048,

    }
};

void dump_bytes(const uint8_t* bptr, uint32_t len, uint8_t mode)
{
    int i = 0;

    for (i = 0; i < len; )
    {
        if ((i & 0x0f) == 0)
        {
            WPRINT_APP_INFO( ( "\n" ) );
        }
        else if ((i & 0x07) == 0)
        {
            WPRINT_APP_INFO( (" ") );
        }
        if(mode == 0)
            WPRINT_APP_INFO( ( "%02x ", bptr[i++] ) );
        else
            WPRINT_APP_INFO( ( "%c ", (char)bptr[i++] ) );
    }
    WPRINT_APP_INFO( ( "\n" ) );
}


void application_start(void)
{
    platform_hwcrypto_init();

    wiced_time_t t1, t2, i;
    uint8_t cipher_text[2048];
    uint8_t plain_text[2048];
    uint8_t iv[16];
    char *plain_text_ptr;

    for (i = 0; i < 1; i++)
    {
        /* Test encryption */
        WPRINT_APP_INFO( ( "" ) );
        memcpy(iv, aes_ctr_test_cases[0].iv, AES_CTR_IV_LENGTH);
        memset(&context_aes, 0, sizeof(context_aes));
        hw_aes_setkey_enc(&context_aes, aes_ctr_test_cases[0].hex_key, AES_CTR_KEY_LENGTH);
        WPRINT_APP_INFO( ( "" ) );
        if ( aes_ctr_test_cases[0].char_plain_text != NULL )
        {
            plain_text_ptr = aes_ctr_test_cases[0].char_plain_text;
            WPRINT_APP_INFO( ( "" ) );
            WPRINT_APP_INFO( ( "" ) );
            WPRINT_APP_INFO( ( "" ) );
        }
        else
        {
            plain_text_ptr = (char*)aes_ctr_test_cases[0].hex_plain_text;
            dump_bytes( (uint8_t*)plain_text_ptr, aes_ctr_test_cases[0].data_len, 0 );
        }
        WPRINT_APP_INFO((""));
        wiced_time_get_time( &t1 );
        hw_aes_crypt_cbc(&context_aes, HW_AES_ENCRYPT, (uint32_t)aes_ctr_test_cases[0].data_len, iv, (const unsigned char*)plain_text_ptr, (unsigned char *)cipher_text);
        WPRINT_APP_INFO((""));
        wiced_time_get_time( &t2 );
        t2 = t2 - t1;

        WPRINT_APP_INFO( ( "" ) );
        dump_bytes( cipher_text, aes_ctr_test_cases[0].data_len,0);

        /* Test decryption */
        WPRINT_APP_INFO( ( "" ) );
        memcpy(iv, aes_ctr_test_cases[i].iv, AES_CTR_IV_LENGTH);
        memset(&context_aes, 0, sizeof(context_aes));
        hw_aes_setkey_dec(&context_aes, aes_ctr_test_cases[0].hex_key, AES_CTR_KEY_LENGTH);
        hw_aes_crypt_cbc(&context_aes, HW_AES_DECRYPT, aes_ctr_test_cases[0].data_len, iv, cipher_text, plain_text );

        dump_bytes(plain_text, aes_ctr_test_cases[0].data_len, 1);

        WPRINT_APP_INFO( ( "Time for AES-CBC encrypt = %u ms\n", (unsigned int) t2 ) );
    }
}

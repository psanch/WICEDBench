#include <stdlib.h>
#include "wiced.h"
#include "wiced_security.h"
#include "wwd_debug.h"
#include "string.h"
#include "wiced_time.h"

#define NUM_OF_AES_CBC_TESTS     1
#define AES_CBC_IV_LENGTH        16              /* Length of the AES-CBC initialization vector in octets */
#define AES_CBC_KEY_LENGTH       128             /* Length of the AES-CBC key in bits */
#define DATA_LENGTH_BYTES        2048
#define TRIAL_COUNT              10000


aes_context_t context_aes;

struct aes_cbc_test_case {
    int num;
    char label[32];
    uint8_t hex_key[16];
    uint8_t iv[16];
    int key_len;
    char* char_plain_text;
    int data_len;
} aes_cbc_test_cases[NUM_OF_AES_CBC_TESTS] = {
    {
        .num = 1,
        .label = "Test Case AES-CBC-128(software)",
        .hex_key = {
                0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
                0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06,
            },
        .iv = {
                0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
                0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41,
            },
        .key_len = 16,
        .char_plain_text = "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",
        .data_len = DATA_LENGTH_BYTES,

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
                //print hex
                WPRINT_APP_INFO( ( "%02x ", bptr[i++] ) );
            else
                //cast into ASCII format
                WPRINT_APP_INFO( ( "%c ", (char)bptr[i++] ) );
        }
        WPRINT_APP_INFO( ( "\n" ) );
    }

void application_start(void)
{

    wiced_time_t t1, t2, t3 = 0;
    uint32_t i,j;
    i = j = 0;
    uint8_t cipher_text[DATA_LENGTH_BYTES];
    char* plain_text;
    uint8_t iv[16];


    //WPRINT_APP_INFO( ( "\nBegin Trial:\n" ) );
    uint32_t round_total = 0 ;
    for(j = 0; j < 10; j++){

    for (i = 0; i < TRIAL_COUNT; i++)
    {


        memcpy(iv, aes_cbc_test_cases[0].iv, AES_CBC_IV_LENGTH);
        memset(&context_aes, 0, sizeof(context_aes));
        aes_setkey_enc(&context_aes, aes_cbc_test_cases[0].hex_key, AES_CBC_KEY_LENGTH);

        plain_text = aes_cbc_test_cases[0].char_plain_text;
        //WPRINT_APP_INFO( ( "\nPlain text: " ) );
        //WPRINT_APP_INFO( ( "\"" ) );
        //WPRINT_APP_INFO( ( "%s", plain_text) );
        //WPRINT_APP_INFO( ( "\"\n" ) );



        wiced_time_get_time( &t1 );
        aes_crypt_cbc(&context_aes, AES_ENCRYPT, aes_cbc_test_cases[0].data_len, iv, (unsigned char*)plain_text, cipher_text);
        wiced_time_get_time( &t2 );
        t3 = t2 - t1;
        round_total += t3;

        //WPRINT_APP_INFO( ( "\nResulting Cipher Text:" ) );
        //dump_bytes( cipher_text, aes_cbc_test_cases[0].data_len, 0);

        /*
        memcpy(iv, aes_cbc_test_cases[0].iv, AES_CBC_IV_LENGTH);
        memset(&context_aes, 0, sizeof(context_aes));
        aes_setkey_dec(&context_aes, aes_cbc_test_cases[0].hex_key, AES_CBC_KEY_LENGTH);
        aes_crypt_cbc(&context_aes, AES_DECRYPT, aes_cbc_test_cases[0].data_len, iv, (unsigned char*)cipher_text, plain_text );
        */

        /* dump_bytes(plain_text, aes_cbc_test_cases[0].data_len, 1);
        if(strcmp(plain_text,aes_cbc_test_cases[0].char_plain_text) == 0){
            WPRINT_APP_INFO( ("SUCCESS" ) );
        }
        */

        //WPRINT_APP_INFO( ( "%u\n", (unsigned int) t3 ) );

        //WPRINT_APP_INFO( ( "End of Trial" ) );
    }
    WPRINT_APP_INFO(("%.6f\n", ((float)round_total)/(float)TRIAL_COUNT));

    round_total = 0;
    }

}

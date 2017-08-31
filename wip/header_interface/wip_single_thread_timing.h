/* Make Target:
WICEDBench.header_interface-CYW943907AEVAL1F download run
*/

/* This header file serves as the interface and configuration menu for
 * conducting time trials with various security schemes.
 */

#ifndef SINGLE_THREAD_TIMING_H
#define SINGLE_THREAD_TIMING_H

#include <stdlib.h>
#include "wiced.h"
#include "wiced_security.h"
#include "string.h"
#include "wiced_time.h"
#include "crypto_api.h"
#include "crypto_core.h"
#include "platform/wwd_platform_interface.h"

//timing constants
#define CPU_CYCLES_PER_MICROSECOND    ( CPU_CLOCK_HZ / 1000000 )
#define MICROSECONDS_PER_CPU_CYCLE 1 / CPU_CYCLES_PER_MICROSECOND

//trial constants
#define NUM_CASES 1
#define NUM_LOOPS 1

//message constants
#define DATA_LENGTH_BYTES 256
#define MESSAGE_PT "dIRLDGFcf3eolc7xIgDM76pnIcYPaXkLnyoqQnbPz5KhMUHMNwLu2Pmqt00huzZyfSPsMpvp3SDkxAyW7UW3oEgmIFGMensPAgrql8Bk49B8ZdE8Lw0pQjCfoDj4vHVndIRLDGFcf3eolc7xIgDM76pnIcYPaXkLnyoqQnbPz5KhMUHMNwLu2Pmqt00huzZyfSPsMpvp3SDkxAyW7UW3oEgmIFGMensPAgrql8Bk49B8ZdE8Lw0pQjCfoDj4vHVn"

//RSA constants
#define RSA_EXPONENT 3

//AES constants
#define AES_KEY_LENGTH 192 //[128, 192, 256] if altered, change Hex key in sec struct
#define AES_IV_LENGTH 16

//trial structure
typedef struct sec_test_case_tag {
    int num;
    char label[64];
    uint8_t hex_key[AES_KEY_LENGTH/8];
    uint8_t iv[AES_IV_LENGTH];
    int key_len;
    uint8_t hex_plain_text[DATA_LENGTH_BYTES];
    char* char_plain_text;
    int data_len;
} sec_test_case;

uint8_t cipher_text[DATA_LENGTH_BYTES]; //cipher and plaintext buffers
uint8_t plain_text[DATA_LENGTH_BYTES];

uint32_t a_time, b_time; //reference points for timing/clock cycle counting
uint32_t num_cycles_enc, num_cycles_dec; //arrays to hold time/cycles per trial

//Security protocol prototypes

//public key
void rsa(void);

//symmetric key
    //software
void sw_aes_cbc(void);
void sw_aes_ctr(void); //functionality uncertain


    //hardware
void hw_aes_cbc(void);
void hw_aes_ctr(void); //functionality uncertain


//clock cycle -> time functions
float get_average_cycles(uint32_t num_cycles);
float get_elapsed_time_mcs(uint32_t num_cycles);
float get_average_time_mcs(uint32_t num_cycles);

//hex or ASCII output function
void dump_bytes(const uint8_t* bptr, uint32_t len, uint8_t mode);

float get_average_cycles(uint32_t num_cycles){
    return (float)num_cycles/(float)NUM_LOOPS;
}

float get_elapsed_time_mcs(uint32_t num_cycles){
    return (float)num_cycles * (1.00000000 / (float)CPU_CYCLES_PER_MICROSECOND);
}

float get_average_time_mcs(uint32_t num_cycles){
    return get_elapsed_time_mcs(num_cycles)/(float)NUM_LOOPS;
}

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


/*
Quick Reference:

typedef enum
{
    RSA_PKCS_V15    = 0,
    RSA_PKCS_V21    = 1, //V21 NOT usable in WICED SDK, (found in API)
} rsa_pkcs_padding_t;

*/

void rsa(void)
{
    rsa_context ctx;
    uint32_t i,j;

    microrng_state state;
    sec_test_case rsa_test_cases[NUM_CASES] = {
        {
            .num = 1,
            .label = "Test Case RSA (software)",
            .hex_plain_text = { 0 },
            .char_plain_text = MESSAGE_PT,
            .data_len = DATA_LENGTH_BYTES,

        }
    };

    uint32_t keysize_bits = DATA_LENGTH_BYTES*8;
    uint32_t exponent = RSA_EXPONENT;
    num_cycles_enc = num_cycles_dec = 0;
    //uint32_t crypt_code;

    //Initialize RNG with user-give entropy
    state.entropy = 666;
    microrng_init(&state);

    //Initialize RSA context and pass RNG function
    rsa_init(&ctx, RSA_PKCS_V15, RSA_RAW, microrng_rand, &state );
    uint32_t error_code = rsa_gen_key( &ctx, keysize_bits, exponent );
    WPRINT_APP_INFO(("err code: %u\n", (unsigned int)error_code));

    char *plain_text_ptr = rsa_test_cases[0].char_plain_text;
    for(i = 0, num_cycles_enc = 0, num_cycles_dec = 0; i < NUM_CASES; i++){
        for (j = 0; j < NUM_LOOPS; j++){

            //count clock cycles of encryption
            a_time = host_platform_get_cycle_count();
            rsa_public( &ctx, (const unsigned char*)plain_text_ptr, cipher_text );
            b_time = host_platform_get_cycle_count();

            num_cycles_enc += b_time - a_time;

            //WPRINT_APP_INFO(("enc err code: %u\n", (unsigned int)crypt_code));
            //dump_bytes(cipher_text, DATA_LENGTH_BYTES, 0);

            //count clock cycles of decryption
            a_time = host_platform_get_cycle_count();
            rsa_private( &ctx, cipher_text, plain_text );
            b_time = host_platform_get_cycle_count();

            num_cycles_dec += b_time - a_time;

            //WPRINT_APP_INFO(("dec err code: %u\n", (unsigned int)crypt_code));
            //dump_bytes(plain_text, DATA_LENGTH_BYTES, 1);
        }
        WPRINT_APP_INFO(("Avg encrypt time: %.8f\n", get_average_time_mcs(num_cycles_enc)/NUM_LOOPS));
        WPRINT_APP_INFO(("Avg decrypt time: %.8f\n", get_average_time_mcs(num_cycles_dec)/NUM_LOOPS));
    }

    //output data

}

void sw_aes_cbc(void){

    aes_context_t context_aes;
    uint32_t i,j;

    sec_test_case aes_cbc_cases[NUM_CASES] = {
            {
                .num = 1,
                .label = "Test Case AES-CBC-xxx (software)",
                .hex_key = {
                        0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
                        0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06,
                        0x2e, 0x6f, 0x93, 0xd5, 0x43, 0x11, 0xa3, 0x09, //uncomment for AES-192 & AES-256
                        //0x41, 0x3b, 0xd3, 0xd8, 0x84, 0x18, 0x10, 0x7e, //uncomment for AES-256 ONLY

                    },
                .iv = {
                        0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
                        0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41,
                    },
                .key_len = AES_KEY_LENGTH/8,
                .hex_plain_text = { 0 },
                .char_plain_text = MESSAGE_PT,
                .data_len = DATA_LENGTH_BYTES,

            }
        };

    uint8_t iv[AES_IV_LENGTH];
    char *plain_text_ptr;

    for(i = 0, num_cycles_enc = 0, num_cycles_dec = 0; i < NUM_CASES; i++){
        for (j = 0; j < NUM_LOOPS; j++){

            /* Test encryption */
            //WPRINT_APP_INFO( ( "\n%s\n", aes_ctr_test_cases[i].label ) );
            memcpy(iv, aes_cbc_cases[i].iv, AES_IV_LENGTH);
            memset(&context_aes, 0, sizeof(context_aes));
            aes_setkey_enc(&context_aes, aes_cbc_cases[i].hex_key, AES_KEY_LENGTH);

            plain_text_ptr = aes_cbc_cases[i].char_plain_text;

            /*
            WPRINT_APP_INFO( ( "\nPlain text: " ) );
            WPRINT_APP_INFO( ( "\"" ) );
            WPRINT_APP_INFO( ( "%s", plain_text_ptr ) );
            WPRINT_APP_INFO( ( "\"\n" ) );
            */

            //wiced_time_get_time( &t1 );
            a_time = host_platform_get_cycle_count();
            aes_crypt_cbc(&context_aes, AES_ENCRYPT, aes_cbc_cases[i].data_len, iv, (unsigned char *)plain_text_ptr, cipher_text);
            b_time = host_platform_get_cycle_count();
            //wiced_time_get_time( &t2 );
            num_cycles_enc += b_time - a_time;
            //t2 = t2 - t1;

            /*
            WPRINT_APP_INFO( ( "\nResulting Cipher Text:" ) );
            dump_bytes( cipher_text, aes_cbc_cases[i].data_len,0);
            */


            // Test decryption
            //WPRINT_APP_INFO( ( "\nResulting Decrypted ASCII Text:" ) );
            memcpy(iv, aes_cbc_cases[i].iv, AES_IV_LENGTH);
            memset(&context_aes, 0, sizeof(context_aes));

            aes_setkey_dec(&context_aes, aes_cbc_cases[i].hex_key, AES_KEY_LENGTH);
            a_time = host_platform_get_cycle_count();
            aes_crypt_cbc(&context_aes, AES_DECRYPT, aes_cbc_cases[i].data_len, iv, (unsigned char*)cipher_text, plain_text );
            b_time = host_platform_get_cycle_count();
            num_cycles_dec += b_time - a_time;

            //dump_bytes(plain_text, aes_cbc_cases[i].data_len, 1);

        }
            WPRINT_APP_INFO(("%.8f\n", get_average_time_mcs(num_cycles_enc)));
           //WPRINT_APP_INFO( ( "Time for AES-CBC encrypt = %u ms\n", (unsigned int) t2 ) );
    }

}

void hw_aes_cbc(void){

    platform_hwcrypto_init();

    hw_aes_context_t context_aes;
    uint32_t i,j;

    sec_test_case aes_cbc_cases[NUM_CASES] = {
        {
            .num = 1,
            .label = "Test Case AES-CBC-1 (hardware)",
            .hex_key = {
                    0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
                    0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06,
                    0x2e, 0x6f, 0x93, 0xd5, 0x43, 0x11, 0xa3, 0x09, //uncomment line for AES-192
                    //0x41, 0x3b, 0xd3, 0xd8, 0x84, 0x18, 0x10, 0x7e, //uncomment line for AES-256
                },
            .iv = {
                    0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
                    0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41,
                },
            .key_len = AES_KEY_LENGTH/8,
            .hex_plain_text = { 0 },
            .char_plain_text = MESSAGE_PT,
            .data_len = DATA_LENGTH_BYTES,

        }
    };

    uint8_t iv[AES_IV_LENGTH];
    char *plain_text_ptr;

    for(i = 0, num_cycles_enc = 0, num_cycles_dec = 0; i < NUM_CASES; i++){
        for (j = 0; j < NUM_LOOPS; j++){

            /* Test encryption */
            //WPRINT_APP_INFO( ( "\n%s\n", aes_cbc_cases[i].label ) );
            memcpy(iv, aes_cbc_cases[i].iv, AES_IV_LENGTH);
            memset(&context_aes, 0, sizeof(context_aes));
            hw_aes_setkey_enc(&context_aes, aes_cbc_cases[i].hex_key, AES_KEY_LENGTH);

            plain_text_ptr = aes_cbc_cases[i].char_plain_text;

            /*
            WPRINT_APP_INFO( ( "\nPlain text: " ) );
            WPRINT_APP_INFO( ( "\"" ) );
            WPRINT_APP_INFO( ( "%s", plain_text_ptr ) );
            WPRINT_APP_INFO( ( "\"\n" ) );
            */

            //wiced_time_get_time( &t1 );

            a_time = host_platform_get_cycle_count();
            hw_aes_crypt_cbc(&context_aes, HW_AES_ENCRYPT, aes_cbc_cases[i].data_len, iv, (const unsigned char*)plain_text_ptr, cipher_text);
            b_time = host_platform_get_cycle_count();


            //wiced_time_get_time( &t2 );
            num_cycles_enc += b_time - a_time;
            //t2 = t2 - t1;

            //WPRINT_APP_INFO( ( "\nResulting Cipher Text:" ) );
            dump_bytes( cipher_text, aes_cbc_cases[i].data_len, 0);

            //Test decryption
            //WPRINT_APP_INFO( ( "\nResulting Decrypted ASCII Text:" ) );
            memcpy(iv, aes_cbc_cases[i].iv, AES_IV_LENGTH);
            memset(&context_aes, 0, sizeof(context_aes));

            hw_aes_setkey_dec(&context_aes, aes_cbc_cases[i].hex_key, AES_KEY_LENGTH);
            a_time = host_platform_get_cycle_count();
            hw_aes_crypt_cbc(&context_aes, HW_AES_DECRYPT, aes_cbc_cases[i].data_len, iv, cipher_text, plain_text );
            b_time = host_platform_get_cycle_count();

            num_cycles_dec += b_time - a_time;

            dump_bytes(plain_text, aes_cbc_cases[i].data_len, 1);
        }
            //WPRINT_APP_INFO( ( "Time for AES-CBC encrypt = %u ms\n", (unsigned int) t2 ) );
            WPRINT_APP_INFO(("\n%.8f\n", get_average_time_mcs((float)num_cycles_enc)));
    }
}
#endif

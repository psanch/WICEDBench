#include "wip_multi_thread_timing.h"

#define THREAD_STACK_SIZE 10000
#define PRIORITY 4
#define NUM_THREADS 16

rsa_context ctx;
rsa_context ctxs[NUM_THREADS];

void tf0(wiced_thread_arg_t arg)
{

    rsa_post_keygen(1, &ctxs[0]);
    return;
}

void tf1(wiced_thread_arg_t arg)
{

    rsa_post_keygen(1, &ctxs[1]);
    return;
}

void tf2(wiced_thread_arg_t arg)
{

    rsa_post_keygen(1, &ctxs[2]);
    return;
}

void tf3(wiced_thread_arg_t arg)
{

    rsa_post_keygen(1, &ctxs[3]);
    return;
}

void tf4(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[4]);
    return;
}

void tf5(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[5]);
    return;
}

void tf6(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[6]);
    return;
}

void tf7(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[7]);
    return;
}

void tf8(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[8]);
    return;
}

void tf9(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[9]);
    return;
}

void tf10(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[10]);
    return;
}
void tf11(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[11]);
    return;
}
void tf12(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[12]);
    return;
}
void tf13(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[13]);
    return;
}
void tf14(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[14]);
    return;
}
void tf15(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[15]);
    return;
}
/*
void tf16(wiced_thread_arg_t arg)
{

    rsa_post_keygen(1, &ctxs[16]);
    return;
}

void tf17(wiced_thread_arg_t arg)
{

    rsa_post_keygen(1, &ctxs[17]);
    return;
}

void tf18(wiced_thread_arg_t arg)
{

    rsa_post_keygen(1, &ctxs[18]);
    return;
}

void tf19(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[19]);
    return;
}

void tf20(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[20]);
    return;
}

void tf21(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[21]);
    return;
}

void tf22(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[22]);
    return;
}

void tf23(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[23]);
    return;
}

void tf24(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[24]);
    return;
}

void tf25(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[25]);
    return;
}
void tf26(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[26]);
    return;
}
void tf27(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[27]);
    return;
}
void tf28(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[28]);
    return;
}
void tf29(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[29]);
    return;
}
void tf30(wiced_thread_arg_t arg)
{
    rsa_post_keygen(1, &ctxs[30]);
    return;
}
*/
void application_start( )
{
    wiced_init();
    wiced_thread_t th0, th1, th2, th3, th4, th5, th6, th7, th8, th9, th10, th11, th12, th13, th14, th15;
                   //th16, th17, th18, th19, th20, th21, th22, th23, th24, th25, th26, th27, th28, th29, th30;

    rsa_keygen(&ctx);

    uint32_t i;
    for(i = 0; i < NUM_THREADS; i++)
        ctxs[i] = ctx;

    wiced_rtos_create_thread(&th0, PRIORITY, NULL, tf0, THREAD_STACK_SIZE, NULL);

    wiced_rtos_create_thread(&th1, PRIORITY, NULL, tf1, THREAD_STACK_SIZE, NULL);

    wiced_rtos_create_thread(&th2, PRIORITY, NULL, tf2, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th3, PRIORITY, NULL, tf3, THREAD_STACK_SIZE, NULL);

    wiced_rtos_create_thread(&th4, PRIORITY, NULL, tf4, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th5, PRIORITY, NULL, tf5, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th6, PRIORITY, NULL, tf6, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th7, PRIORITY, NULL, tf7, THREAD_STACK_SIZE, NULL);

    wiced_rtos_create_thread(&th8, PRIORITY, NULL, tf8, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th9, PRIORITY, NULL, tf9, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th10, PRIORITY, NULL, tf10, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th11, PRIORITY, NULL, tf11, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th12, PRIORITY, NULL, tf12, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th13, PRIORITY, NULL, tf13, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th14, PRIORITY, NULL, tf14, THREAD_STACK_SIZE, NULL);
    wiced_rtos_create_thread(&th15, PRIORITY, NULL, tf15, THREAD_STACK_SIZE, NULL);






}

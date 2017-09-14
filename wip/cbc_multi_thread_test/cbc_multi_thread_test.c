#include "wip_multi_thread_timing.h"

#define THREAD_STACK_SIZE 10000
#define PRIORITY 4
#define NUM_THREADS 100

aes_context_t context_aes;
aes_context_t contexts_aes[NUM_THREADS];

void tf0(wiced_thread_arg_t arg)
{

    sw_aes_cbc_multi_th(1, &contexts_aes[0]);
    return;
}

void tf1(wiced_thread_arg_t arg)
{

    sw_aes_cbc_multi_th(1, &contexts_aes[1]);
    return;
}

void tf2(wiced_thread_arg_t arg)
{

    sw_aes_cbc_multi_th(1, &contexts_aes[2]);
    return;
}

void tf3(wiced_thread_arg_t arg)
{

    sw_aes_cbc_multi_th(1, &contexts_aes[3]);
    return;
}

void tf4(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[4]);
    return;
}

void tf5(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[5]);
    return;
}

void tf6(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[6]);
    return;
}

void tf7(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[7]);
    return;
}

void tf8(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[8]);
    return;
}

void tf9(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[9]);
    return;
}

void tf10(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[10]);
    return;
}
void tf11(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[11]);
    return;
}
void tf12(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[12]);
    return;
}
void tf13(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[13]);
    return;
}
void tf14(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[14]);
    return;
}
void tf15(wiced_thread_arg_t arg)
{
    sw_aes_cbc_multi_th(1, &contexts_aes[15]);
    return;
}

void application_start( )
{
    wiced_init();
    wiced_thread_t th0, th1, th2, th3, th4, th5, th6, th7, th8, th9, th10, th11, th12, th13, th14, th15;
                   //th16, th17, th18, th19, th20, th21, th22, th23, th24, th25, th26, th27, th28, th29, th30;

    uint32_t i;
    for(i = 0; i < NUM_THREADS; i++)
        contexts_aes[i] = context_aes;

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

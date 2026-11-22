/**
 * @file FreeRTOSConfig.h
 * @brief FreeRTOS Kernel Configuration for Nordic nRF52840 (Cortex-M4F) Toob-Boot E2E.
 */

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#include <stdint.h>

extern volatile uint32_t g_rtos_context_switches;
void app_freertos_assert_failed(const char *file, int line);

#define configUSE_PREEMPTION                        1
#define configUSE_TIME_SLICING                      1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION     1
#define configUSE_TICKLESS_IDLE                     0
#define configCPU_CLOCK_HZ                          (64000000UL)
#define configTICK_RATE_HZ                          ((TickType_t)1000U)
#define configMAX_PRIORITIES                        5
#define configMINIMAL_STACK_SIZE                    ((uint16_t)256U)
#define configMAX_TASK_NAME_LEN                     24
#define configTICK_TYPE_WIDTH_IN_BITS               TICK_TYPE_WIDTH_32_BITS
#define configIDLE_SHOULD_YIELD                     1

/* Static + Dynamic Memory Allocation (heap_4.c + StaticSemaphore_t/StaticTask_t) */
#define configSUPPORT_STATIC_ALLOCATION             1
#define configSUPPORT_DYNAMIC_ALLOCATION            1
#define configKERNEL_PROVIDED_STATIC_MEMORY         1
#define configTOTAL_HEAP_SIZE                       ((size_t)(32U * 1024U))
#define configAPPLICATION_ALLOCATED_HEAP            0

/* Synchronization & Timers (Required by integrations/freertos/files/toob_hooks.c) */
#define configUSE_MUTEXES                           1
#define configUSE_RECURSIVE_MUTEXES                 1
#define configUSE_COUNTING_SEMAPHORES               1
#define configQUEUE_REGISTRY_SIZE                   0
#define configUSE_QUEUE_SETS                        0
#define configUSE_TASK_NOTIFICATIONS                1
#define configUSE_TIMERS                            1
#define configTIMER_TASK_PRIORITY                   (configMAX_PRIORITIES - 1)
#define configTIMER_QUEUE_LENGTH                    8
#define configTIMER_TASK_STACK_DEPTH                (configMINIMAL_STACK_SIZE * 2U)

/* Hook & Diagnostic Settings */
#define configUSE_IDLE_HOOK                         1
#define configUSE_TICK_HOOK                         0
#define configCHECK_FOR_STACK_OVERFLOW              2
#define configUSE_MALLOC_FAILED_HOOK                1
#define configCHECK_HANDLER_INSTALLATION            1

/* API Function Inclusions */
#define INCLUDE_vTaskPrioritySet                    1
#define INCLUDE_uxTaskPriorityGet                   1
#define INCLUDE_vTaskDelete                         1
#define INCLUDE_vTaskSuspend                        1
#define INCLUDE_vTaskDelay                          1
#define INCLUDE_xTaskDelayUntil                     1
#define INCLUDE_xTaskGetSchedulerState              1
#define INCLUDE_xTaskGetCurrentTaskHandle           1
#define INCLUDE_uxTaskGetStackHighWaterMark         1

/* Cortex-M4F NVIC Priority Configuration (nRF52840 implements 3 priority bits: 0..7) */
#define configPRIO_BITS                             3
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY     7U
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY 2U
#define configKERNEL_INTERRUPT_PRIORITY             (configLIBRARY_LOWEST_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))
#define configMAX_SYSCALL_INTERRUPT_PRIORITY        (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))

/* Preemptive Context-Switch Instrumentation */
#define traceTASK_SWITCHED_IN()                     do { g_rtos_context_switches++; } while (0)

/* Fail-Closed Kernel Assertion Hook */
#define configASSERT(x)                             if ((x) == 0) { app_freertos_assert_failed(__FILE__, __LINE__); }

#endif /* FREERTOS_CONFIG_H */

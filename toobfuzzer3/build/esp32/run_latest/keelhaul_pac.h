/* Auto-Generated Peripheral Access Crate (PAC) for esp32 */
#pragma once
#include <stdint.h>

typedef struct {
    volatile uint32_t FIFO;
    volatile uint32_t INT_RAW;
    volatile uint32_t INT_ST;
    volatile uint32_t INT_ENA;
    volatile uint32_t INT_CLR;
    volatile uint32_t CLKDIV;
    volatile uint32_t AUTOBAUD;
    volatile uint32_t STATUS;
    volatile uint32_t CONF0;
    volatile uint32_t CONF1;
    volatile uint32_t LOWPULSE;
    volatile uint32_t HIGHPULSE;
    volatile uint32_t RXD_CNT;
    volatile uint32_t FLOW_CONF;
    volatile uint32_t SLEEP_CONF;
    volatile uint32_t SWFC_CONF;
    volatile uint32_t IDLE_CONF;
    volatile uint32_t RS485_CONF;
    volatile uint32_t AT_CMD_PRECNT;
    volatile uint32_t AT_CMD_POSTCNT;
    volatile uint32_t AT_CMD_GAPTOUT;
    volatile uint32_t AT_CMD_CHAR;
    volatile uint32_t MEM_CONF;
    volatile uint32_t MEM_TX_STATUS;
    volatile uint32_t MEM_RX_STATUS;
    volatile uint32_t MEM_CNT_STATUS;
    volatile uint32_t POSPULSE;
    volatile uint32_t NEGPULSE;
    uint8_t reserved_70[8];
    volatile uint32_t DATE;
    volatile uint32_t ID;
} pac_uart0_t;

#define PAC_UART0 ((pac_uart0_t*) 0x3FF40000)

typedef struct {
    volatile uint32_t FIFO;
    volatile uint32_t INT_RAW;
    volatile uint32_t INT_ST;
    volatile uint32_t INT_ENA;
    volatile uint32_t INT_CLR;
    volatile uint32_t CLKDIV;
    volatile uint32_t AUTOBAUD;
    volatile uint32_t STATUS;
    volatile uint32_t CONF0;
    volatile uint32_t CONF1;
    volatile uint32_t LOWPULSE;
    volatile uint32_t HIGHPULSE;
    volatile uint32_t RXD_CNT;
    volatile uint32_t FLOW_CONF;
    volatile uint32_t SLEEP_CONF;
    volatile uint32_t SWFC_CONF;
    volatile uint32_t IDLE_CONF;
    volatile uint32_t RS485_CONF;
    volatile uint32_t AT_CMD_PRECNT;
    volatile uint32_t AT_CMD_POSTCNT;
    volatile uint32_t AT_CMD_GAPTOUT;
    volatile uint32_t AT_CMD_CHAR;
    volatile uint32_t MEM_CONF;
    volatile uint32_t MEM_TX_STATUS;
    volatile uint32_t MEM_RX_STATUS;
    volatile uint32_t MEM_CNT_STATUS;
    volatile uint32_t POSPULSE;
    volatile uint32_t NEGPULSE;
    uint8_t reserved_70[8];
    volatile uint32_t DATE;
    volatile uint32_t ID;
} pac_uart1_t;

#define PAC_UART1 ((pac_uart1_t*) 0x3FF50000)

typedef struct {
    volatile uint32_t FIFO;
    volatile uint32_t INT_RAW;
    volatile uint32_t INT_ST;
    volatile uint32_t INT_ENA;
    volatile uint32_t INT_CLR;
    volatile uint32_t CLKDIV;
    volatile uint32_t AUTOBAUD;
    volatile uint32_t STATUS;
    volatile uint32_t CONF0;
    volatile uint32_t CONF1;
    volatile uint32_t LOWPULSE;
    volatile uint32_t HIGHPULSE;
    volatile uint32_t RXD_CNT;
    volatile uint32_t FLOW_CONF;
    volatile uint32_t SLEEP_CONF;
    volatile uint32_t SWFC_CONF;
    volatile uint32_t IDLE_CONF;
    volatile uint32_t RS485_CONF;
    volatile uint32_t AT_CMD_PRECNT;
    volatile uint32_t AT_CMD_POSTCNT;
    volatile uint32_t AT_CMD_GAPTOUT;
    volatile uint32_t AT_CMD_CHAR;
    volatile uint32_t MEM_CONF;
    volatile uint32_t MEM_TX_STATUS;
    volatile uint32_t MEM_RX_STATUS;
    volatile uint32_t MEM_CNT_STATUS;
    volatile uint32_t POSPULSE;
    volatile uint32_t NEGPULSE;
    uint8_t reserved_70[8];
    volatile uint32_t DATE;
    volatile uint32_t ID;
} pac_uart2_t;

#define PAC_UART2 ((pac_uart2_t*) 0x3FF6E000)

/* Heuristic Universal UART Bridging Macro */
#define PAC_UART_TX_BYTE(dev, val) (dev->FIFO = (val))
#define PAC_UART_RX_BYTE(dev, val_ptr) (*(val_ptr) = dev->FIFO)

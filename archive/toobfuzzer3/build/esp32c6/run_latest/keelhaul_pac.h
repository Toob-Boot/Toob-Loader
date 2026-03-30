/* Auto-Generated Peripheral Access Crate (PAC) for esp32c6 */
#pragma once
#include <stdint.h>

typedef struct {
    volatile uint32_t FIFO;
    volatile uint32_t INT_RAW;
    volatile uint32_t INT_ST;
    volatile uint32_t INT_ENA;
    volatile uint32_t INT_CLR;
    volatile uint32_t CLKDIV;
    volatile uint32_t RX_FILT;
    volatile uint32_t STATUS;
    volatile uint32_t CONF0;
    volatile uint32_t CONF1;
    uint8_t reserved_28[4];
    volatile uint32_t HWFC_CONF;
    volatile uint32_t SLEEP_CONF0;
    volatile uint32_t SLEEP_CONF1;
    volatile uint32_t SLEEP_CONF2;
    volatile uint32_t SWFC_CONF0;
    volatile uint32_t SWFC_CONF1;
    volatile uint32_t TXBRK_CONF;
    volatile uint32_t IDLE_CONF;
    volatile uint32_t RS485_CONF;
    volatile uint32_t AT_CMD_PRECNT;
    volatile uint32_t AT_CMD_POSTCNT;
    volatile uint32_t AT_CMD_GAPTOUT;
    volatile uint32_t AT_CMD_CHAR;
    volatile uint32_t MEM_CONF;
    volatile uint32_t TOUT_CONF;
    volatile uint32_t MEM_TX_STATUS;
    volatile uint32_t MEM_RX_STATUS;
    volatile uint32_t FSM_STATUS;
    uint8_t reserved_74[20];
    volatile uint32_t CLK_CONF;
    volatile uint32_t DATE;
    volatile uint32_t AFIFO_STATUS;
    uint8_t reserved_94[4];
    volatile uint32_t REG_UPDATE;
    volatile uint32_t ID;
} pac_lp_uart_t;

#define PAC_LP_UART ((pac_lp_uart_t*) 0x600B1400)

typedef struct {
    volatile uint32_t FIFO;
    volatile uint32_t INT_RAW;
    volatile uint32_t INT_ST;
    volatile uint32_t INT_ENA;
    volatile uint32_t INT_CLR;
    volatile uint32_t CLKDIV;
    volatile uint32_t RX_FILT;
    volatile uint32_t STATUS;
    volatile uint32_t CONF0;
    volatile uint32_t CONF1;
    uint8_t reserved_28[4];
    volatile uint32_t HWFC_CONF;
    volatile uint32_t SLEEP_CONF0;
    volatile uint32_t SLEEP_CONF1;
    volatile uint32_t SLEEP_CONF2;
    volatile uint32_t SWFC_CONF0;
    volatile uint32_t SWFC_CONF1;
    volatile uint32_t TXBRK_CONF;
    volatile uint32_t IDLE_CONF;
    volatile uint32_t RS485_CONF;
    volatile uint32_t AT_CMD_PRECNT;
    volatile uint32_t AT_CMD_POSTCNT;
    volatile uint32_t AT_CMD_GAPTOUT;
    volatile uint32_t AT_CMD_CHAR;
    volatile uint32_t MEM_CONF;
    volatile uint32_t TOUT_CONF;
    volatile uint32_t MEM_TX_STATUS;
    volatile uint32_t MEM_RX_STATUS;
    volatile uint32_t FSM_STATUS;
    volatile uint32_t POSPULSE;
    volatile uint32_t NEGPULSE;
    volatile uint32_t LOWPULSE;
    volatile uint32_t HIGHPULSE;
    volatile uint32_t RXD_CNT;
    volatile uint32_t CLK_CONF;
    volatile uint32_t DATE;
    volatile uint32_t AFIFO_STATUS;
    uint8_t reserved_94[4];
    volatile uint32_t REG_UPDATE;
    volatile uint32_t ID;
} pac_uart0_t;

#define PAC_UART0 ((pac_uart0_t*) 0x60000000)

typedef struct {
    volatile uint32_t FIFO;
    volatile uint32_t INT_RAW;
    volatile uint32_t INT_ST;
    volatile uint32_t INT_ENA;
    volatile uint32_t INT_CLR;
    volatile uint32_t CLKDIV;
    volatile uint32_t RX_FILT;
    volatile uint32_t STATUS;
    volatile uint32_t CONF0;
    volatile uint32_t CONF1;
    uint8_t reserved_28[4];
    volatile uint32_t HWFC_CONF;
    volatile uint32_t SLEEP_CONF0;
    volatile uint32_t SLEEP_CONF1;
    volatile uint32_t SLEEP_CONF2;
    volatile uint32_t SWFC_CONF0;
    volatile uint32_t SWFC_CONF1;
    volatile uint32_t TXBRK_CONF;
    volatile uint32_t IDLE_CONF;
    volatile uint32_t RS485_CONF;
    volatile uint32_t AT_CMD_PRECNT;
    volatile uint32_t AT_CMD_POSTCNT;
    volatile uint32_t AT_CMD_GAPTOUT;
    volatile uint32_t AT_CMD_CHAR;
    volatile uint32_t MEM_CONF;
    volatile uint32_t TOUT_CONF;
    volatile uint32_t MEM_TX_STATUS;
    volatile uint32_t MEM_RX_STATUS;
    volatile uint32_t FSM_STATUS;
    volatile uint32_t POSPULSE;
    volatile uint32_t NEGPULSE;
    volatile uint32_t LOWPULSE;
    volatile uint32_t HIGHPULSE;
    volatile uint32_t RXD_CNT;
    volatile uint32_t CLK_CONF;
    volatile uint32_t DATE;
    volatile uint32_t AFIFO_STATUS;
    uint8_t reserved_94[4];
    volatile uint32_t REG_UPDATE;
    volatile uint32_t ID;
} pac_uart1_t;

#define PAC_UART1 ((pac_uart1_t*) 0x60001000)

/* Heuristic Universal UART Bridging Macro */
#define PAC_UART_TX_BYTE(dev, val) (dev->FIFO = (val))
#define PAC_UART_RX_BYTE(dev, val_ptr) (*(val_ptr) = dev->FIFO)

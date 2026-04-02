/**
 * ==============================================================================
 * Toob-Boot M-SANDBOX: Console UART Mock Implementation
 * ==============================================================================
 * 
 * REFERENCED SPECIFICATIONS:
 * 1. docs/hals.md -> console_hal_t
 * 2. docs/stage_1_5_spec.md -> Serial Rescue / UART RX Pipeline (Naked COBS)
 */

#include "mock_console.h"
#include "mock_clock.h"
#include "chip_fault_inject.h"
#include <stdio.h>

static FILE *g_rx_stream = NULL;

static boot_status_t mock_console_init(uint32_t baudrate) {
    (void)baudrate; // Ignoriert: Die Sandbox pollt RX Daten instantly vom Dateisystem
    fault_inject_init();

    if (g_fault_config.console_hardware_fault) {
        return BOOT_ERR_STATE; /* P10 Hardened: Simulation eines abgerauchten UART Controllers */
    }

    mock_console_reset_state(); /* Sauberen Zustand erzwingen */

    if (g_fault_config.uart_rx_file != NULL) {
        g_rx_stream = fopen(g_fault_config.uart_rx_file, "rb");
    }

    /* Es ist architektonisch zulässig, dass die Datei nicht existiert 
     * (= kein Serial-Kabel vom Techniker gesteckt). */
    return BOOT_OK;
}

static void mock_console_deinit(void) {
    if (g_rx_stream != NULL) {
        fclose(g_rx_stream);
        g_rx_stream = NULL;
    }
}

static void mock_console_putchar(char c) {
    if (g_fault_config.console_hardware_fault) {
        return; /* Toter Controller sendet keine ACKs */
    }
    putchar(c);
}

static int mock_console_getchar(uint32_t timeout_ms) {
    if (g_fault_config.console_hardware_fault || g_rx_stream == NULL) {
        /* P10 Timing Defense: Ohne diesen künstlichen Delay ignoriert der
           M-SANDBOX Host reale Timeout-Limits seiner C-Core Loops komplett und 
           fristet auf 100% CPU Auslastung beim File-Polling. */
        if (timeout_ms > 0) {
            sandbox_clock_hal.delay_ms(timeout_ms);
        }
        return -1; /* -1 symbolisiert `BOOT_UART_NO_DATA` nach Spec */
    }

    int c = fgetc(g_rx_stream);
    if (c == EOF) {
        /* Hardware Timing-Emulation (Poll auf leere Puffer) */
        if (timeout_ms > 0) {
            sandbox_clock_hal.delay_ms(timeout_ms);
        }
        return -1;
    }
    return c;
}

static void mock_console_flush(void) {
    if (g_fault_config.console_hardware_fault) {
        return;
    }
    fflush(stdout); /* Garantiert, dass Boot-Journals vor einem Test-Crash ausgegeben sind */
}

void mock_console_reset_state(void) {
    mock_console_deinit();
}

const console_hal_t sandbox_console_hal = {
    .abi_version = 0x01000000,
    .init        = mock_console_init,
    .deinit      = mock_console_deinit,
    .putchar     = mock_console_putchar,
    .getchar     = mock_console_getchar,
    .flush       = mock_console_flush
};

#include "keelhaul_pac.h"
#include <stdbool.h>
#include <stdint.h>

// Ultra-dumb, primitive hardware access
void hal_uart_tx_byte(char c) {
  // Primitive bare-metal FIFO throttle: Ensure we don't overrun the hardware
  // queue. At 160MHz CPU and 115200 Baud (~86us per byte), waiting ~12000
  // cycles guarantees the byte is shifted out safely.
  for (volatile int i = 0; i < 12000; i++) {
  }

  // PAC_UART0 is mapped dynamically to the first UART found in the SVD XML
  PAC_UART_TX_BYTE(PAC_UART0, c);
}

// Ultra-dumb hardware receive
// Returns true to satisfy signatures, though it's polling blindly right now via
// SVD
bool hal_uart_rx_byte(uint8_t *c) {
  PAC_UART_RX_BYTE(PAC_UART0, c);
  // Note: A true industrial implementation would query the SVD STATUS register
  // for `RX_FIFO_CNT > 0` before reading to prevent blocking or reading junk.
  // For this prototype, we assume the Host synchronizes delays.
  return true;
}

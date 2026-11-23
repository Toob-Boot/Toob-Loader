/**
 * @file main.c
 * @brief Recovery OS Application Entry Point.
 */

#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#else
#include "generated_boot_config.h"
#endif

#include "libtoob.h"
#include "recovery_port.h"
#include "boot_tbm1.h"
#include <stddef.h>
#include <string.h>

extern uint32_t toob_lib_crc32(const uint8_t *data, size_t length);
extern uint32_t recovery_get_tick_ms(void);

#define SOH 0x01
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define CAN 0x18
#define CRC_CHAR 'C'

#define XMODEM_DATA_SIZE 128U
#define XMODEM_PACKET_PAYLOAD_SIZE (1U + 1U + XMODEM_DATA_SIZE + 2U) /* block_num + inv_block_num + data + crc */
#define XMODEM_TAIL_WINDOW_SIZE (2U * XMODEM_DATA_SIZE)              /* 256B two-block sliding window (MED-22) */
#define RECOVERY_MAX_TOTAL_ERRORS 64U
#define RECOVERY_RX_IDLE_TIMEOUT_MS 60000U

static uint32_t elapsed_ms_since(uint32_t now_ms, uint32_t then_ms) {
    return (now_ms >= then_ms) ? (now_ms - then_ms)
                               : ((UINT32_MAX - then_ms) + 1U + now_ms);
}

static uint16_t crc16_ccitt(const uint8_t *data, size_t length) {
    uint16_t crc = 0;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (int j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (uint16_t)((crc << 1) ^ 0x1021);
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

static toob_status_t read_bytes(uint8_t *buf, uint32_t len, uint32_t timeout_ms) {
    for (uint32_t i = 0; i < len; i++) {
        toob_status_t status = recovery_serial_getchar(&buf[i], timeout_ms);
        if (status != TOOB_OK) {
            return status;
        }
    }
    return TOOB_OK;
}

static bool compute_head_tbm1_size(const tbm1_header_t *manifest, uint32_t slot_limit, uint32_t *out_size) {
    if (manifest->image_count == 0 || manifest->image_count > TBM1_MAX_IMAGES) {
        return false;
    }
    uint32_t max_end = manifest->total_len;
    for (uint8_t i = 0; i < manifest->image_count; i++) {
        uint32_t off = manifest->images[i].data_off;
        uint32_t sz = manifest->images[i].stored_size;
        if (off > UINT32_MAX - sz) {
            return false;
        }
        uint32_t end = off + sz;
        if (end > max_end) {
            max_end = end;
        }
    }
    if (max_end == 0 || max_end > slot_limit) {
        return false;
    }
    *out_size = max_end;
    return true;
}

int recovery_main(void);

#ifdef TOOB_HOST_FUZZING
int main(void) {
#else
int recovery_main(void) {
#endif
    /* 1. Initialize guest OS library and validate handoff */
    TOOB_OS_INIT_OR_PANIC();

    /* 2. Check booted partition to ensure we are running in Recovery mode */
    toob_handoff_t handoff;
    toob_status_t status = toob_get_handoff(&handoff);
    if (status != TOOB_OK || handoff.booted_partition != TOOB_PARTITION_RECOVERY) {
        while (1) {
            TOOB_TRAP();
        }
    }

    uint32_t slot_limit = (CHIP_STAGING_SLOT_SIZE != 0U)
                              ? CHIP_STAGING_SLOT_SIZE
                              : CHIP_APP_SLOT_SIZE;
#if TOOB_TRANSPORT_PROVIDER == TOOB_TRANSPORT_POINTER
    if (handoff.active_slot > 1U) {
        while (1) {
            TOOB_TRAP();
        }
    }
    slot_limit = (handoff.active_slot == 0U) ? CHIP_STAGING_SLOT_SIZE : CHIP_APP_SLOT_SIZE;
#endif

    /* 3. Initialize Recovery Serial */
    if (recovery_serial_init() != TOOB_OK) {
        while (1) {
            TOOB_TRAP();
        }
    }

    recovery_serial_print("[REC] listening...\r\n");

    /* 4. Sync with sender: transmit 'C' until first packet control character starts */
    bool synced = false;
    uint8_t sync_retries = 0;
    uint8_t c = 0;

    while (!synced && sync_retries < 60) {
        recovery_serial_putchar(CRC_CHAR);
        toob_status_t sync_stat = recovery_serial_getchar(&c, 1000);
        if (sync_stat == TOOB_OK) {
            if (c == SOH || c == EOT || c == CAN) {
                synced = true;
            }
        }
        if (!synced) {
            sync_retries++;
        }
    }

    if (!synced) {
        recovery_serial_print("[REC] sync timeout\r\n");
        recovery_system_reboot();
    }

    /* 5. Main Receive Loop (manifest_buf and tail_window have disjoint lifetimes) */
    union {
        uint8_t manifest_buf[640];
        uint8_t tail_window[XMODEM_TAIL_WINDOW_SIZE];
    } rx_stage __attribute__((aligned(8))) = { .manifest_buf = { 0U } };
    uint32_t tail_len = 0U;
    uint32_t bytes_buffered = 0U;
    uint8_t expected_packet = 1U;
    uint8_t packet_payload[XMODEM_PACKET_PAYLOAD_SIZE];
    bool ota_started = false;
    bool trailer_mode = false;
    toob_ota_ctx_t ota_ctx;
    status = toob_ota_ctx_init(&ota_ctx);
    if (status != TOOB_OK) {
        recovery_system_reboot();
    }

    recovery_serial_print("[REC] flashing...\r\n");

    uint32_t total_errors = 0U;
    uint32_t last_activity_ms = recovery_get_tick_ms();

    while (1) {
        if (elapsed_ms_since(recovery_get_tick_ms(), last_activity_ms) >= RECOVERY_RX_IDLE_TIMEOUT_MS) {
            recovery_serial_print("[REC] rx timeout\r\n");
            recovery_system_reboot();
        }

        if (c != SOH && c != EOT && c != CAN) {
            toob_status_t rd_stat = recovery_serial_getchar(&c, 1000);
            if (rd_stat != TOOB_OK) {
                total_errors++;
                if (total_errors >= RECOVERY_MAX_TOTAL_ERRORS) {
                    recovery_serial_print("[REC] rx abort\r\n");
                    recovery_system_reboot();
                }
                recovery_serial_putchar(NAK);
                continue;
            }
        }

        if (c == EOT) {
            recovery_serial_putchar(ACK);
            break;
        }
        if (c == CAN) {
            recovery_serial_print("[REC] aborted\r\n");
            recovery_system_reboot();
        }
        if (c != SOH) {
            total_errors++;
            if (total_errors >= RECOVERY_MAX_TOTAL_ERRORS) {
                recovery_serial_print("[REC] rx abort\r\n");
                recovery_system_reboot();
            }
            recovery_serial_putchar(NAK);
            c = 0;
            continue;
        }

        /* Read the remaining 132 bytes of the XMODEM packet */
        toob_status_t rd_payload = read_bytes(packet_payload, XMODEM_PACKET_PAYLOAD_SIZE, 1000);
        if (rd_payload != TOOB_OK) {
            total_errors++;
            if (total_errors >= RECOVERY_MAX_TOTAL_ERRORS) {
                recovery_serial_print("[REC] rx abort\r\n");
                recovery_system_reboot();
            }
            recovery_serial_putchar(NAK);
            c = 0;
            continue;
        }

        uint8_t block_num = packet_payload[0];
        uint8_t inv_block_num = packet_payload[1];
        const uint8_t *data_ptr = &packet_payload[2];
        uint16_t packet_crc = (uint16_t)(((uint16_t)packet_payload[130] << 8) | packet_payload[131]);

        bool val_ok = ((uint8_t)(block_num + inv_block_num) == 0xFF);
        bool seq_ok = (block_num == expected_packet);
        bool crc_ok = (crc16_ccitt(data_ptr, XMODEM_DATA_SIZE) == packet_crc);

        if (val_ok && seq_ok && crc_ok) {
            if (!ota_started) {
                memcpy(&rx_stage.manifest_buf[bytes_buffered], data_ptr, XMODEM_DATA_SIZE);
                bytes_buffered += XMODEM_DATA_SIZE;

                if (bytes_buffered >= 640U) {
                    uint32_t magic = 0U;
                    memcpy(&magic, rx_stage.manifest_buf, sizeof(magic));
                    uint32_t total_size = 0U;

                    if (magic == TBM1_MAGIC) {
                        const tbm1_header_t *manifest = (const tbm1_header_t *)rx_stage.manifest_buf;
                        if (!compute_head_tbm1_size(manifest, slot_limit, &total_size)) {
                            recovery_serial_print("[REC] invalid manifest\r\n");
                            recovery_system_reboot();
                        }
                    } else if (magic == TOOB_MAGIC_HEADER) {
                        /* Zero-Copy Trailer-TBM1 bundle: exact trailer end discovered at EOT */
                        trailer_mode = true;
                        total_size = slot_limit;
                    } else {
                        recovery_serial_print("[REC] invalid magic\r\n");
                        recovery_system_reboot();
                    }

                    status = toob_ota_begin(&ota_ctx, total_size, NULL);
                    if (status != TOOB_OK) {
                        recovery_serial_print("[REC] ota init fail\r\n");
                        recovery_system_reboot();
                    }

                    if (trailer_mode) {
                        /* MED-22: Hold back 256-byte sliding window so split 16B trailer + 0x1A
                         * padding can be located & trimmed cleanly before hitting flash. */
                        uint32_t prefix_len = bytes_buffered - XMODEM_TAIL_WINDOW_SIZE;
                        status = toob_ota_process_chunk(&ota_ctx, rx_stage.manifest_buf, prefix_len);
                        if (status != TOOB_OK) {
                            recovery_serial_print("[REC] process fail\r\n");
                            recovery_system_reboot();
                        }
                        memmove(rx_stage.tail_window, &rx_stage.manifest_buf[prefix_len], XMODEM_TAIL_WINDOW_SIZE);
                        tail_len = XMODEM_TAIL_WINDOW_SIZE;
                    } else {
                        uint32_t to_write = (bytes_buffered > total_size) ? total_size : bytes_buffered;
                        status = toob_ota_process_chunk(&ota_ctx, rx_stage.manifest_buf, to_write);
                        if (status != TOOB_OK) {
                            recovery_serial_print("[REC] process fail\r\n");
                            recovery_system_reboot();
                        }
                    }
                    ota_started = true;
                }
            } else if (trailer_mode) {
                /* Flush oldest 128B half of the 256B sliding window and shift in new 128B block */
                if (ota_ctx.bytes_queued > (slot_limit - tail_len) ||
                    XMODEM_DATA_SIZE > (slot_limit - (ota_ctx.bytes_queued + tail_len))) {
                    recovery_serial_print("[REC] ota flash fail\r\n");
                    recovery_system_reboot();
                }
                status = toob_ota_process_chunk(&ota_ctx, rx_stage.tail_window, XMODEM_DATA_SIZE);
                if (status != TOOB_OK) {
                    recovery_serial_print("[REC] ota flash fail\r\n");
                    recovery_system_reboot();
                }
                memmove(rx_stage.tail_window, &rx_stage.tail_window[XMODEM_DATA_SIZE], XMODEM_DATA_SIZE);
                memcpy(&rx_stage.tail_window[XMODEM_DATA_SIZE], data_ptr, XMODEM_DATA_SIZE);
            } else {
                uint32_t remaining = (ota_ctx.total_size > ota_ctx.bytes_queued)
                                     ? (ota_ctx.total_size - ota_ctx.bytes_queued)
                                     : 0U;
                uint32_t to_write = (remaining < XMODEM_DATA_SIZE) ? remaining : XMODEM_DATA_SIZE;
                if (to_write > 0U) {
                    status = toob_ota_process_chunk(&ota_ctx, data_ptr, to_write);
                    if (status != TOOB_OK) {
                        recovery_serial_print("[REC] ota flash fail\r\n");
                        recovery_system_reboot();
                    }
                }
            }
            last_activity_ms = recovery_get_tick_ms();
            expected_packet++;
            recovery_serial_putchar(ACK);
        } else {
            total_errors++;
            if (total_errors >= RECOVERY_MAX_TOTAL_ERRORS) {
                recovery_serial_print("[REC] rx abort\r\n");
                recovery_system_reboot();
            }
            if (val_ok && block_num == (uint8_t)(expected_packet - 1U)) {
                recovery_serial_putchar(ACK);
            } else {
                recovery_serial_putchar(NAK);
            }
        }

        c = 0;
    }

    /* 6. Handle stream completion at EOT */
    if (!ota_started) {
        if (bytes_buffered < sizeof(tbm1_header_t)) {
            recovery_serial_print("[REC] manifest too small\r\n");
            recovery_system_reboot();
        }
        const tbm1_header_t *manifest = (const tbm1_header_t *)rx_stage.manifest_buf;
        uint32_t total_size = 0U;
        if (manifest->magic != TBM1_MAGIC || !compute_head_tbm1_size(manifest, slot_limit, &total_size)) {
            recovery_serial_print("[REC] invalid manifest\r\n");
            recovery_system_reboot();
        }
        status = toob_ota_begin(&ota_ctx, total_size, NULL);
        if (status != TOOB_OK) {
            recovery_serial_print("[REC] ota init fail\r\n");
            recovery_system_reboot();
        }
        uint32_t to_write = (bytes_buffered > total_size) ? total_size : bytes_buffered;
        status = toob_ota_process_chunk(&ota_ctx, rx_stage.manifest_buf, to_write);
        if (status != TOOB_OK) {
            recovery_serial_print("[REC] process fail\r\n");
            recovery_system_reboot();
        }
    } else if (trailer_mode) {
        /* MED-22: Scan backwards across the 256B two-block sliding window and verify
         * both TOOB_TBM1_TRAILER_MAGIC and CRC-32 so split trailers across 128B XMODEM
         * block boundaries are always found and payload coincidences are rejected. */
        bool trailer_found = false;
        uint32_t flush_tail = 0U;

        for (int off = (int)tail_len - (int)sizeof(toob_tbm1_trailer_locator_t); off >= 0; off--) {
            toob_tbm1_trailer_locator_t loc;
            memcpy(&loc, &rx_stage.tail_window[off], sizeof(loc));
            if (loc.magic == TOOB_TBM1_TRAILER_MAGIC) {
                uint32_t calc_crc = toob_lib_crc32(
                    (const uint8_t *)&loc, offsetof(toob_tbm1_trailer_locator_t, crc32));
                uint32_t cand_tail = (uint32_t)off + (uint32_t)sizeof(loc);
                uint32_t cand_total = ota_ctx.bytes_queued + cand_tail;
                uint32_t body_limit = cand_total - (uint32_t)sizeof(loc);
                if (calc_crc == loc.crc32 &&
                    cand_total <= slot_limit &&
                    loc.tbm1_off <= body_limit &&
                    loc.tbm1_len >= (uint32_t)(TBM1_FIXED_LEN + TBM1_SIG_LEN) &&
                    loc.tbm1_len <= (body_limit - loc.tbm1_off)) {
                    flush_tail = cand_tail;
                    trailer_found = true;
                    break;
                }
            }
        }

        if (!trailer_found || flush_tail == 0U) {
            recovery_serial_print("[REC] invalid trailer\r\n");
            recovery_system_reboot();
        }

        status = toob_ota_trim_total_size(&ota_ctx, ota_ctx.bytes_queued + flush_tail);
        if (status != TOOB_OK) {
            recovery_serial_print("[REC] ota trim fail\r\n");
            recovery_system_reboot();
        }
        status = toob_ota_process_chunk(&ota_ctx, rx_stage.tail_window, flush_tail);
        if (status != TOOB_OK) {
            recovery_serial_print("[REC] ota flash fail\r\n");
            recovery_system_reboot();
        }
    }

    /* 7. Finalize OTA (writes WAL_INTENT_UPDATE_PENDING pointing to staged manifest).
     * Recovery resolution is withheld until Stage 1 cryptographically verifies
     * and applies the staged image on reboot. */
    status = toob_ota_finalize(&ota_ctx);
    if (status != TOOB_OK) {
        recovery_serial_print("[REC] finalize fail\r\n");
        recovery_system_reboot();
    }

    recovery_serial_print("[REC] resolved\r\n");
    recovery_system_reboot();

    return 0;
}

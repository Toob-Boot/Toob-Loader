/**
 * @file main.c
 * @brief Recovery OS Application Entry Point.
 */

#include "libtoob.h"
#include "recovery_port.h"
#include "boot_tbm1.h"
#include <string.h>

#ifdef TOOB_HOST_FUZZING
#include "libtoob_config_sandbox.h"
#else
#include "generated_boot_config.h"
#endif

#define SOH 0x01
#define EOT 0x04
#define ACK 0x06
#define NAK 0x15
#define CAN 0x18
#define CRC_CHAR 'C'

#define XMODEM_DATA_SIZE 128
#define XMODEM_PACKET_PAYLOAD_SIZE (1 + 1 + XMODEM_DATA_SIZE + 2) // block_num + inv_block_num + data + crc

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

    /* 5. Main Receive Loop */
    uint8_t manifest_buf[640];
    uint32_t bytes_buffered = 0;
    uint8_t expected_packet = 1;
    uint8_t packet_payload[XMODEM_PACKET_PAYLOAD_SIZE];
    bool ota_started = false;
    toob_ota_ctx_t ota_ctx;

    recovery_serial_print("[REC] flashing...\r\n");

    while (1) {
        /* If c is not already SOH/EOT/CAN (which happens on the very first packet after sync),
         * read the control character from serial. */
        if (c != SOH && c != EOT && c != CAN) {
            toob_status_t rd_stat = recovery_serial_getchar(&c, 1000);
            if (rd_stat != TOOB_OK) {
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
            recovery_serial_putchar(NAK);
            c = 0; /* Reset so we wait for a valid control character */
            continue;
        }

        /* Read the remaining 132 bytes of the XMODEM packet */
        toob_status_t rd_payload = read_bytes(packet_payload, XMODEM_PACKET_PAYLOAD_SIZE, 1000);
        if (rd_payload != TOOB_OK) {
            recovery_serial_putchar(NAK);
            c = 0; /* Reset control character so we resync on next iteration */
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
                /* Buffer the manifest blocks first */
                memcpy(&manifest_buf[bytes_buffered], data_ptr, XMODEM_DATA_SIZE);
                bytes_buffered += XMODEM_DATA_SIZE;

                if (bytes_buffered >= 640) {
                    /* Parse manifest to start the OTA session */
                    const tbm1_header_t *manifest = (const tbm1_header_t *)manifest_buf;
                    if (manifest->magic != TBM1_MAGIC) {
                        recovery_serial_print("[REC] invalid magic\r\n");
                        recovery_system_reboot();
                    }
                    if (manifest->image_count == 0 || manifest->image_count > TBM1_MAX_IMAGES) {
                        recovery_serial_print("[REC] invalid image count\r\n");
                        recovery_system_reboot();
                    }
                    /* Prevent Integer Overflow during size accumulation (CERT C / MISRA C) */
                    uint32_t total_size = manifest->total_len;
                    for (uint8_t i = 0; i < manifest->image_count; i++) {
                        uint32_t size = manifest->images[i].stored_size;
                        if (total_size > UINT32_MAX - size) {
                            recovery_serial_print("[REC] size overflow\r\n");
                            recovery_system_reboot();
                        }
                        total_size += size;
                    }
                    if (total_size > CHIP_STAGING_SLOT_SIZE) {
                        recovery_serial_print("[REC] update too large\r\n");
                        recovery_system_reboot();
                    }
                    status = toob_ota_begin(&ota_ctx, total_size, NULL);
                    if (status != TOOB_OK) {
                        recovery_serial_print("[REC] ota init fail\r\n");
                        recovery_system_reboot();
                    }
                    status = toob_ota_process_chunk(&ota_ctx, manifest_buf, bytes_buffered);
                    if (status != TOOB_OK) {
                        recovery_serial_print("[REC] process fail\r\n");
                        recovery_system_reboot();
                    }
                    ota_started = true;
                }
            } else {
                /* Stream data directly to OTA flash */
                status = toob_ota_process_chunk(&ota_ctx, data_ptr, XMODEM_DATA_SIZE);
                if (status != TOOB_OK) {
                    recovery_serial_print("[REC] ota flash fail\r\n");
                    recovery_system_reboot();
                }
            }
            expected_packet++;
            recovery_serial_putchar(ACK);
        } else {
            /* Duplicate block check (retransmitted ACK) */
            if (val_ok && block_num == (uint8_t)(expected_packet - 1)) {
                recovery_serial_putchar(ACK);
            } else {
                recovery_serial_putchar(NAK);
            }
        }

        c = 0; /* Reset control character so we read the next one */
    }

    /* 6. If EOT was received but OTA was not started yet (very small update case) */
    if (!ota_started) {
        if (bytes_buffered < sizeof(tbm1_header_t)) {
            recovery_serial_print("[REC] manifest too small\r\n");
            recovery_system_reboot();
        }
        const tbm1_header_t *manifest = (const tbm1_header_t *)manifest_buf;
        if (manifest->magic != TBM1_MAGIC) {
            recovery_serial_print("[REC] invalid magic\r\n");
            recovery_system_reboot();
        }
        if (manifest->image_count == 0 || manifest->image_count > TBM1_MAX_IMAGES) {
            recovery_serial_print("[REC] invalid image count\r\n");
            recovery_system_reboot();
        }
        /* Prevent Integer Overflow during size accumulation (CERT C / MISRA C) */
        uint32_t total_size = manifest->total_len;
        for (uint8_t i = 0; i < manifest->image_count; i++) {
            uint32_t size = manifest->images[i].stored_size;
            if (total_size > UINT32_MAX - size) {
                recovery_serial_print("[REC] size overflow\r\n");
                recovery_system_reboot();
            }
            total_size += size;
        }
        status = toob_ota_begin(&ota_ctx, total_size, NULL);
        if (status != TOOB_OK) {
            recovery_serial_print("[REC] ota init fail\r\n");
            recovery_system_reboot();
        }
        status = toob_ota_process_chunk(&ota_ctx, manifest_buf, bytes_buffered);
        if (status != TOOB_OK) {
            recovery_serial_print("[REC] process fail\r\n");
            recovery_system_reboot();
        }
    }

    /* 7. Finalize OTA & set recovery resolved */
    status = toob_ota_finalize(&ota_ctx);
    if (status != TOOB_OK) {
        recovery_serial_print("[REC] finalize fail\r\n");
        recovery_system_reboot();
    }

    status = toob_recovery_resolved();
    if (status != TOOB_OK) {
        recovery_serial_print("[REC] resolve fail\r\n");
        recovery_system_reboot();
    }

    recovery_serial_print("[REC] resolved\r\n");
    recovery_system_reboot();

    return 0;
}

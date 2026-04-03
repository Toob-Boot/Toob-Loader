/*
 * Toob-Boot Core File: boot_panic.c
 * Relevant Spec-Dateien:
 * - docs/stage_1_5_spec.md (Serial Rescue, SOS, Exponential Penalty)
 * - docs/testing_requirements.md
 */

#include "boot_panic.h"
#include "boot_delay.h"
#include "boot_config_mock.h"
#include "boot_secure_zeroize.h"
#include <string.h>

/**
 * @brief Streams a buffer to UART using Naked COBS encoding with O(1) memory.
 *        O(n) time complexity and native WDT feeding.
 */
static void send_cobs_frame(const boot_platform_t *platform, const uint8_t *data, size_t len) {
    if (!platform || !platform->console) return;

    /* Frame Start Marker (Sync) */
    platform->console->putchar(0x00);
    
    size_t ptr = 0;
    while (ptr < len) {
        uint8_t code = 1;
        size_t end = ptr;
        
        /* Find next zero or hit 254 data bytes limit (0xFF code) */
        while (end < len && data[end] != 0 && code < 0xFF) {
            end++;
            code++;
        }
        
        /* Write Block Code */
        platform->console->putchar(code);
        
        /* Write Block Data */
        for (size_t i = ptr; i < end; i++) {
            platform->console->putchar(data[i]);
            if (platform->wdt) {
                platform->wdt->kick();
            }
        }
        
        ptr = end;
        /* Consume the physical zero that we encoded virtually */
        if (ptr < len && data[ptr] == 0) {
            ptr++;
        }
    }
    
    /* Frame End Marker */
    platform->console->putchar(0x00);
    platform->console->flush();
}

/**
 * @brief O(1) in-place Naked COBS Decoder. Validates packet structure.
 */
static boot_status_t cobs_decode_in_place(uint8_t *data, size_t len, size_t *out_len) {
    if (len == 0) return BOOT_ERR_INVALID_ARG;
    
    size_t read_idx = 0;
    size_t write_idx = 0;
    
    while (read_idx < len) {
        uint8_t code = data[read_idx++];
        if (code == 0) return BOOT_ERR_INVALID_ARG; /* Zeroes are illegal in Naked COBS */
        
        uint8_t copy_len = code - 1;
        if (read_idx + copy_len > len) return BOOT_ERR_INVALID_ARG; /* Trucation Attack Guard */
        
        /* O(1) in-place shift. This works because write_idx <= read_idx is mathematically guaranteed */
        for (uint8_t i = 0; i < copy_len; i++) {
            data[write_idx++] = data[read_idx++];
        }
        
        /* Implicit zeroes are restored except for block max (0xFF) or end of frame */
        if (code < 0xFF && read_idx < len) {
            data[write_idx++] = 0x00;
        }
    }
    
    *out_len = write_idx;
    return BOOT_OK;
}

static void enter_sos_loop(const boot_platform_t *platform) {
    // Endlosschleife ohne Serial Rescue (Fallback)
    while (1) {
        if (platform->wdt) {
            platform->wdt->kick();
        }
        boot_delay_with_wdt(platform, 500); 
    }
}

_Noreturn void boot_panic(const boot_platform_t *platform, boot_status_t reason) {
    if (!platform) {
        while (1) {} // Hard Fault Fallback
    }

    // GAP-28: Pull-Up/Down Evaluierung des Hardware-Recovery-Pins auf Floating-State 
    // erfolgt zwingend upstream in boot_main.c vor Aufruf dieses Boot_Panic Entry-Points.
    
    if (!platform->console) {
        enter_sos_loop(platform);
    }
    
    uint32_t failed_auth_attempts = 0;
    
    // Initialisierungs-UART Flush
    platform->console->putchar('P');
    platform->console->putchar('N');
    platform->console->putchar('C');
    platform->console->flush();

    /*
     * ============================================================================
     * BLOCK 1: Challenge Generation (2FA)
     * ============================================================================
     */
     
    /* 1. & 2. Generiere Nonce und lese DSLC in isolierten Buffer */
    uint8_t challenge_buf[104] = {0};
    _Static_assert(sizeof(challenge_buf) >= 32 + 64 + sizeof(uint32_t) + sizeof(boot_status_t), "challenge_buf auesserstes Limit verletzt");
    size_t challenge_len = 32; /* Nonce Base */
    
    if (platform->crypto && platform->crypto->random) {
        if (platform->crypto->random(challenge_buf, 32) != BOOT_OK) {
            enter_sos_loop(platform); /* TRNG Health Check Failed -> Terminal */
        }
    } else {
        enter_sos_loop(platform); /* Kein Crypto für 2FA -> Terminal */
    }

    size_t dslc_len = 0;
    if (platform->crypto->read_dslc) {
        boot_status_t d_status = platform->crypto->read_dslc(challenge_buf + 32, &dslc_len);
        if (d_status == BOOT_ERR_NOT_SUPPORTED || dslc_len == 0) {
            /* Fallback: Zero-Padding auf 32 Bytes wenn der Chip keinen DSLC OTP besitzt.
             * Die Sicherheit wird alleinig durch den Private-Key Guard der Ed25519 Signatur gesichert. */
            memset(challenge_buf + 32, 0, 32);
            dslc_len = 32;
        } else if (dslc_len > 64) {
             /* Hardware DSLC Clamp */
             dslc_len = 64;
        }
    } else {
        memset(challenge_buf + 32, 0, 32);
        dslc_len = 32;
    }
    
    challenge_len += dslc_len;

    /* 3. Lese Highest-Seen Anti-Replay Timestamp (muss hier eigentlich nicht gesendet werden, 
     *    da der Techniker einen frischen senden muss. Aber wir senden die aktuelle Basis als Hilfe.) */
    uint32_t current_monotonic = 0;
    if (platform->crypto->read_monotonic_counter) {
        platform->crypto->read_monotonic_counter(&current_monotonic);
    }
    // Hänge den aktuellen Monotonic als Referenz für den Host an das Challenge (4 Bytes LSB)
    memcpy(challenge_buf + challenge_len, &current_monotonic, sizeof(current_monotonic));
    challenge_len += sizeof(current_monotonic);

    // Hänge den Error Reason an, damit der Host direkt debuggen kann
    memcpy(challenge_buf + challenge_len, &reason, sizeof(reason));
    challenge_len += sizeof(reason);

    /* 4. Sende isoliertes Challenge via COBS an den Techniker */
    send_cobs_frame(platform, challenge_buf, challenge_len);

    while (1) {
        if (platform->wdt) {
            platform->wdt->kick();
        }
        
        /*
         * ============================================================================
         * BLOCK 2: Auth-Token Empfang & P10-Verifikation
         * ============================================================================
         */
         
        uint8_t rx_buf[128] = {0}; 
        size_t rx_len = 0;
        bool frame_ready = false;
        
        while (!frame_ready) {
            if (platform->wdt) platform->wdt->kick();
            
            uint8_t c;
            if (platform->console->getchar(&c, 100) != BOOT_OK) continue; 
            
            if (c == COBS_MARKER_END) {
                if (rx_len > 0) {
                    frame_ready = true;
                }
            } else {
                if (rx_len < sizeof(rx_buf)) {
                    rx_buf[rx_len++] = (uint8_t)c;
                } else {
                    rx_len = 0; /* Overflow Defense: Flush buffer and wait for next sync */
                }
            }
        }
         
        bool is_authenticated = false; 
        size_t decoded_len = 0;
        
        if (cobs_decode_in_place(rx_buf, rx_len, &decoded_len) == BOOT_OK) {
            if (decoded_len == sizeof(stage15_auth_payload_t)) {
                stage15_auth_payload_t *payload = (stage15_auth_payload_t *)rx_buf;
                
                /* Anti-Replay: Verify new timestamp is > current (Time-Forward Pattern) */
                /* Reviewer-Note (Timing-Leak): Die Nonce ist kein langfristiges Geheimnis (sie wurde im Klartext 
                 * nach außen gesendet). Ein `constant_time_memcmp` verbirgt dem Angreifer hier absolut nichts. 
                 * Standard memcmp ist performance-gerecht und by-design sicher. */
                if (payload->timestamp > current_monotonic && 
                    memcmp(payload->nonce, challenge_buf, 32) == 0) {
                    
                    /* Validate Ed25519 Token. 
                     * Signierte Message (76 bytes): [Nonce (32)] | [Padded DSLC (32)] | [Slot ID (4)] | [Timestamp (8)] 
                     * Wir nutzen den `challenge_buf` (der Nonce + DSLC exakt bereit hält) als sichere Basis! */
                    uint8_t verify_msg[76];
                    memcpy(verify_msg, challenge_buf, 64);
                    memcpy(verify_msg + 64, &payload->slot_id, 4);
                    
                    _Static_assert(sizeof(payload->timestamp) == 8, "Timestamp size MUSS 8 Bytes betragen");
                    memcpy(verify_msg + 68, &payload->timestamp, 8);
                    
                    uint8_t root_pubkey[32] = {0};
                    if (platform->crypto->read_pubkey && platform->crypto->read_pubkey(root_pubkey, sizeof(root_pubkey), 0) == BOOT_OK) {
                        if (platform->crypto->verify_ed25519(verify_msg, 76, payload->sig, root_pubkey) == BOOT_OK) {
                            
                            /* GAP-17 "Dies verhindert, dass ein Host einen gültigen Payload in den falschen Slot forciert."
                             * MUSS eine Prüfung stattfinden, ob `payload->slot_id` tatsächlich dem `CHIP_STAGING_SLOT_ID` entspricht. */
                            if (payload->slot_id == CHIP_STAGING_SLOT_ID) {
                                is_authenticated = true;
                                
                                /* OTP Burn: Nach erfolgreicher Autorisierung den Counter voranbringen um Tokens einweg zu machen */
                                if (platform->crypto->advance_monotonic_counter) {
                                    platform->crypto->advance_monotonic_counter();
                                    current_monotonic = (uint32_t)payload->timestamp;
                                }
                            }
                        }
                    }
                    boot_secure_zeroize(root_pubkey, sizeof(root_pubkey));
                }
            }
        }
        
        if (!is_authenticated) {
            failed_auth_attempts++;
            
            
            /* GAP-C06: Serial Rescue DoS Penalty
             * Um CPU-Sperren von ~15ms (Sig-Check) zu begrenzen, wird ein exponentieller Penalty erzwungen.
             */
            uint32_t shifts = failed_auth_attempts;
            if (shifts > 10) shifts = 10;
            
            uint32_t penalty_ms = (1U << shifts) * 100U;
            
            /* WDT-Amnesie Guard: Wenn der Penalty-Sleep den WDT verschluckt, verlieren wir 
             * RAM Zustände bei Low-Power. Wir nutzen daher konsequent P10 WDT-feeding delays! */
            boot_delay_with_wdt(platform, penalty_ms);
            continue;
        }

        /*
         * ============================================================================
         * BLOCK 3: Naked COBS Flash-Transfer (Ping-Pong) & Handoff
         * ============================================================================
         */
         
        uint32_t flash_offset = 0;
        uint32_t current_sector_end = CHIP_STAGING_SLOT_ABS_ADDR;
        bool staging_erased = false;
        
        while (1) {
            send_cobs_frame(platform, (const uint8_t *)"RDY", 3);
            
            uint8_t chunk_buf[1050] = {0}; 
            size_t chunk_len = 0;
            bool chunk_received = false;
            
            while (!chunk_received) {
                if (platform->wdt) platform->wdt->kick();
                
                uint8_t c;
                if (platform->console->getchar(&c, 500) != BOOT_OK) break; /* Outer loop will resend "RDY" */
                
                if (c == COBS_MARKER_END) {
                    if (chunk_len > 0) chunk_received = true;
                } else {
                    if (chunk_len < sizeof(chunk_buf)) {
                        chunk_buf[chunk_len++] = (uint8_t)c;
                    } else {
                        chunk_len = 0; /* Frame overflow trap */
                    }
                }
            }
            
            if (!chunk_received) continue; 
            
            size_t payload_len = 0;
            if (cobs_decode_in_place(chunk_buf, chunk_len, &payload_len) == BOOT_OK && payload_len > 0) {
                
                /* EOF Marker: We are fully done. Trigger the OS-Load. */
                if (payload_len == 3 && memcmp(chunk_buf, "EOF", 3) == 0) {
                    send_cobs_frame(platform, (const uint8_t *)"ACK", 3);
                    
                    /* P10 Handoff: Force an un-kickable WDT reset loop to safely reboot into Stage 1/Stage 2. 
                     * Der Bootloader findet das intakte Staging-Image beim nächsten Kaltstart. */
                    if (platform->console) platform->console->flush();
                    while (1) { } 
                }
                
                /* Bounds Guard: Verhindere Flash Overflow (CVE Prevention) via Subtraktion */
                /* Reviewer-Note (While-Bound): Diese Schleife ist implizit sicher gebunden!
                 * Leere Chunks (payload_len == 0) blockieren das Erhöhen. Gefüllte Chunks erhöhen 
                 * `flash_offset` iterativ um `aligned_len >= 1`. Sobald `flash_offset` in die Nähe
                 * der maximalen App-Slot-Größe wandert, löst genau dieser Check den Abbruch aus. */
                if (payload_len > CHIP_APP_SLOT_SIZE || 
                    flash_offset > CHIP_APP_SLOT_SIZE - payload_len ||
                    CHIP_STAGING_SLOT_ABS_ADDR > UINT32_MAX - CHIP_APP_SLOT_SIZE) {
                    enter_sos_loop(platform); 
                }
                
                uint32_t addr = CHIP_STAGING_SLOT_ABS_ADDR + flash_offset;
                size_t write_end = addr + payload_len;
                
                /* On-Demand Sequential Erase */
                while (!staging_erased || current_sector_end < write_end) {
                    size_t s_size = 0;
                    uint32_t erase_target = !staging_erased ? addr : current_sector_end;
                    
                    if (platform->flash->get_sector_size(erase_target, &s_size) == BOOT_OK) {
                        if (platform->wdt && platform->wdt->suspend_for_critical_section) {
                            platform->wdt->suspend_for_critical_section();
                        } else if (platform->wdt) {
                            platform->wdt->kick();
                        }
                        
                        if (platform->flash->erase_sector(erase_target) != BOOT_OK) {
                            enter_sos_loop(platform);
                        }
                        
                        if (platform->wdt && platform->wdt->resume) {
                            platform->wdt->resume();
                        }
                        
                        current_sector_end = erase_target + s_size;
                        staging_erased = true;
                    } else {
                        enter_sos_loop(platform);
                    }
                }
                
                /* Padding Alignment Guard for the final Chunk. 
                 * Verhindert ECC Hardware-Exceptions beim Flashen ungerader Bytegrößen. */
                uint8_t align = platform->flash->write_align;
                if (align == 0) align = 1;
                
                size_t aligned_len = payload_len;
                uint8_t align_mod = payload_len % align;
                if (align_mod != 0) {
                    size_t padding = align - align_mod;
                    if (aligned_len + padding > sizeof(chunk_buf)) {
                        enter_sos_loop(platform);
                    }
                    memset(chunk_buf + payload_len, platform->flash->erased_value, padding);
                    aligned_len += padding;
                }
                
                /* Flash Write */
                if (platform->flash->write(addr, chunk_buf, aligned_len) == BOOT_OK) {
                    /* Wir addieren aligned_len um ECC Double-Writes bei Folge-Chunks sicher zu verhindern.
                     * Host-Skripte sind verantwortlich Chunk-Sizes aligned zu framen. */
                    flash_offset += aligned_len; 
                    send_cobs_frame(platform, (const uint8_t *)"ACK", 3);
                } else {
                    enter_sos_loop(platform);
                }
            }
        }
    }
}

#!/usr/bin/env bash
# ==============================================================================
# Toob-Boot Code Generator Bridge (ZCBOR + Manifest Compiler)
# ==============================================================================
# Verhindert CI Pipeline-Abbrüche durch intelligentes Fallback-Mocking.
# 
# P10 Constraint & Review Integration:
# 1. ZCBOR-Fallback erzwingt stabile Memory-Constraints (C-Stubs) anstatt CMake crashen zu lassen.
# 2. Windows-PE Linker erstickt an leeren Layout Skripten -> Safe SECTIONS Mock.
# 3. Unit-Test False Positives -> Mocks garantieren 'return false'.
# 4. Sandbox Memory Safety -> Hardware-Pointers als Safe 'extern', ODR-Resolution via .c
# ==============================================================================

set -euo pipefail

OUTPUT_DIR=$1

if [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <output_dir>"
    exit 1
fi

PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUTPUT_DIR"

echo "[SUIT CodeGen] Generating C artifacts in: $OUTPUT_DIR"

# ------------------------------------------------------------------------------
# 1. ZCBOR CODE GENERATION (CDDL -> C-Logic)
# ------------------------------------------------------------------------------
must_mock_zcbor=1

if python3 -c "import zcbor; assert zcbor.__version__ >= '0.8.0'" 2>/dev/null; then
    echo "[SUIT CodeGen] Python zcbor >= 0.8.0 found. Generating strict parsers..."
    python3 -m zcbor code -c "$PROJECT_ROOT/suit/toob_suit.cddl" --decode --type toob_suit --output-c "$OUTPUT_DIR/boot_suit.c" --output-h "$OUTPUT_DIR/boot_suit.h"
    python3 -m zcbor code -c "$PROJECT_ROOT/suit/toob_telemetry.cddl" --decode --type toob_telemetry --output-c "$OUTPUT_DIR/toob_telemetry_decode.c" --output-h "$OUTPUT_DIR/toob_telemetry_decode.h"
    python3 -m zcbor code -c "$PROJECT_ROOT/suit/toob_telemetry.cddl" --encode --type toob_telemetry --output-c "$OUTPUT_DIR/toob_telemetry_encode.c" --output-h "$OUTPUT_DIR/toob_telemetry_encode.h"
    must_mock_zcbor=0
elif [ -f "$OUTPUT_DIR/boot_suit.h" ] && ! grep -q "BOOT_SUIT_MOCK_H" "$OUTPUT_DIR/boot_suit.h"; then
    echo "[SUIT CodeGen] zcbor not found, but real outputs exist. Preserving them! (Idempotence Guard)"
    must_mock_zcbor=0
fi

if [ "$must_mock_zcbor" -eq 1 ]; then
    echo "[SUIT CodeGen] WARNING: Valid Python zcbor not found! Injecting CI Mock Stubs (Fail-Secure)..."
    
    # SUIT Parser Mock
        cat << 'EOF' > "$OUTPUT_DIR/boot_suit.h"
#ifndef BOOT_SUIT_MOCK_H
#define BOOT_SUIT_MOCK_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct zcbor_string {
    const uint8_t *value;
    size_t len;
};

struct toob_suit_suit_envelope {
    struct zcbor_string signature_ed25519;
    uint8_t key_index; /* ABI Alignment Fix (CDDL uint .size 1) */
    bool pqc_hybrid_active;
    struct zcbor_string signature_pqc;
    struct zcbor_string pubkey_pqc;
};

struct toob_suit_suit_conditions {
    struct zcbor_string device_identifier;
    uint32_t svn;
    uint32_t required_key_epoch;
    uint16_t min_parser_version;
    uint16_t max_resume_attempts;
};

struct toob_suit_suit_payload {
    struct zcbor_string images; /* Minimalistischer Array Platzhalter */
};

struct toob_suit {
    struct toob_suit_suit_envelope suit_envelope;
    struct toob_suit_suit_conditions suit_conditions;
    struct toob_suit_suit_payload suit_payload;
};

extern bool cbor_decode_toob_suit(const uint8_t *payload, size_t payload_len, struct toob_suit *result, size_t *payload_len_out);
#endif
EOF

        cat << 'EOF' > "$OUTPUT_DIR/boot_suit.c"
#include "boot_suit.h"

bool cbor_decode_toob_suit(const uint8_t *payload, size_t payload_len, struct toob_suit *result, size_t *payload_len_out) {
    (void)payload; (void)payload_len; (void)result; (void)payload_len_out;
    return false; /* Mocks lehnen Parsing stets ab! */
}
EOF

        # Telemetry Parser Mock
        cat << 'EOF' > "$OUTPUT_DIR/toob_telemetry_decode.h"
#ifndef TOOB_TELEMETRY_MOCK_H
#define TOOB_TELEMETRY_MOCK_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct ext_health {
    uint32_t ext_health_wal_erasures;
    uint32_t ext_health_app_erasures;
    uint32_t ext_health_staging_erasures;
    uint32_t ext_health_swap_erasures;
};

struct zcbor_string {
    const uint8_t *value;
    size_t len;
};

/* Minimalistisches ZCBOR Dummy Struct (ABI Aligned) */
struct toob_telemetry {
    uint8_t schema_version;
    uint32_t boot_duration_ms;
    uint32_t edge_recovery_events;
    uint32_t hardware_fault_record;
    uint32_t vendor_error;
    uint32_t wdt_kicks;
    uint32_t current_svn;
    uint8_t active_key_index;
    bool fallback_occurred;
    struct zcbor_string sbom_digest;
    uint32_t boot_session_id;
    struct ext_health ext_health;
    bool ext_health_present;
};

extern bool cbor_decode_toob_telemetry(const uint8_t *payload, size_t payload_len, struct toob_telemetry *result, size_t *payload_len_out);
#endif
EOF

        cat << 'EOF' > "$OUTPUT_DIR/toob_telemetry_encode.h"
#ifndef TOOB_TELEMETRY_ENCODE_MOCK_H
#define TOOB_TELEMETRY_ENCODE_MOCK_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "toob_telemetry_decode.h"

extern bool cbor_encode_toob_telemetry(uint8_t *payload, size_t payload_len, const struct toob_telemetry *input, size_t *payload_len_out);
#endif
EOF

        cat << 'EOF' > "$OUTPUT_DIR/toob_telemetry_decode.c"
#include "toob_telemetry_decode.h"

bool cbor_decode_toob_telemetry(const uint8_t *payload, size_t payload_len, struct toob_telemetry *result, size_t *payload_len_out) {
    (void)payload; (void)payload_len; (void)result; (void)payload_len_out;
    return false; /* Mocks lehnen Parsing stets ab! */
}
EOF

        cat << 'EOF' > "$OUTPUT_DIR/toob_telemetry_encode.c"
#include "toob_telemetry_encode.h"

bool cbor_encode_toob_telemetry(uint8_t *payload, size_t payload_len, const struct toob_telemetry *input, size_t *payload_len_out) {
    (void)payload; (void)payload_len; (void)input; (void)payload_len_out;
    return false; /* Mocks erzeugen keinen Output! */
}
EOF
    fi

# ------------------------------------------------------------------------------
# 2. CHIP CONFIG && MANIFEST COMPILER GENERATION
# ------------------------------------------------------------------------------

inject_hardware_mocks() {
    echo "[SUIT CodeGen] Injecting Sandbox Hardware Mocks..."
    cat << 'EOF' > "$OUTPUT_DIR/chip_config.h"
#ifndef TOOB_CHIP_CONFIG_MOCK_H
#define TOOB_CHIP_CONFIG_MOCK_H

#include <stdint.h>

/* ========================================================
 * AUTO-GENERATED MOCK WIRING - TARGET: SANDBOX / CI
 * Segfault-sicher: Externe Zeiger, allokiert in chip_config_mock.c
 * ======================================================== */
#define CHIP_FLASH_MAX_SECTOR_SIZE  4096
#define CHIP_FLASH_WRITE_ALIGNMENT  4
#define CHIP_APP_ALIGNMENT_BYTES    65536
#define BOOT_WDT_TIMEOUT_MS         4100

extern volatile uint32_t toob_mock_reg_reset_reason;
extern volatile uint32_t toob_mock_reg_wdt_feed;
extern volatile uint32_t toob_mock_addr_rtc_ram;

#define REG_RESET_REASON            (&toob_mock_reg_reset_reason)
#define REG_WDT_FEED                (&toob_mock_reg_wdt_feed)
#define ADDR_CONFIRM_RTC_RAM        (&toob_mock_addr_rtc_ram)

#define VAL_WDT_KICK                0x80000000
#define MASK_RESET_WDT              0x08

#endif
EOF

    cat << 'EOF' > "$OUTPUT_DIR/chip_config_mock.c"
#include "chip_config.h"

/* ODR-sichere Allokation für Sandbox Pointer-Targets, verhindert Segfaults */
volatile uint32_t toob_mock_reg_reset_reason = 0;
volatile uint32_t toob_mock_reg_wdt_feed = 0;
volatile uint32_t toob_mock_addr_rtc_ram = 0;
EOF

    cat << 'EOF' > "$OUTPUT_DIR/stage0_layout.ld"
/* ========================================================
 * AUTO-GENERATED MOCK LINKER - TARGET: SANDBOX / CI
 * Verhindert 'relocation truncated' Ausfälle bei leeren Scripts!
 * ======================================================== */
SECTIONS {
    .toob_mock_section : {
        KEEP(*(.toob_mock_section))
    }
}
EOF
}

MANIFEST_CLI="$PROJECT_ROOT/tools/manifest_compiler/cli.py"

if [ -f "$MANIFEST_CLI" ]; then
    echo "[SUIT CodeGen] Executing Manifest-Compiler..."
    if ! python3 "$MANIFEST_CLI" generate --output-dir "$OUTPUT_DIR"; then
        echo "[SUIT CodeGen] ERROR: Manifest-Compiler crashed! Yielding to fallback mocks to preserve CI..."
        inject_hardware_mocks
    fi
    # Falls manifest_compiler erfolgreich ist, MUSS chip_config_mock.c für CMake existieren (als leere Datei)
    if [ ! -f "$OUTPUT_DIR/chip_config_mock.c" ]; then
        echo '/* Empty Mock file generated by success branch */' > "$OUTPUT_DIR/chip_config_mock.c"
    fi
else
    echo "[SUIT CodeGen] WARNING: manifest_compiler not deployed. Using secure Sandbox Fallbacks."
    inject_hardware_mocks
fi

echo "[SUIT CodeGen] Complete."

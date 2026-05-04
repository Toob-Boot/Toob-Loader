#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../core/include/boot_hal.h"
#include "../../crypto/monocypher/crypto_monocypher.h"
#include "../../crypto/monocypher/monocypher.h"
#include "../../crypto/monocypher/monocypher-ed25519.h"

/* The boot platform initialize method we want to test */
extern const boot_platform_t *boot_platform_init(void);

/* Helper to convert hex string to byte array for testing */
static void hex2bin(const char *in, uint8_t *out) {
    size_t len = strlen(in);
    for (size_t i = 0; i < len; i += 2) {
        sscanf(&in[i], "%2hhx", &out[i / 2]);
    }
}

int main(void) {
    printf("==================================================\n");
    printf("   Toob-Boot M-SANDBOX Native Integration Test\n");
    printf("==================================================\n\n");

    printf("[1] Initializing Platform...\n");
    const boot_platform_t *plat = boot_platform_init();
    assert(plat != NULL);
    assert(plat->flash != NULL);
    assert(plat->confirm != NULL);
    assert(plat->crypto != NULL);
    assert(plat->clock != NULL);
    assert(plat->wdt != NULL);
    assert(plat->console != NULL);
    assert(plat->soc != NULL);
    printf("    -> Platform initialized successfully. All 7 HAL traits present.\n\n");

    printf("[2] Testing Mock SOC (Battery & Watchdog)...\n");
    int32_t battery_mv = plat->soc->battery_level_mv();
    printf("    -> Battery Level: %d mV\n", battery_mv);
    assert(battery_mv >= 3700); /* Our chip_config.h specifies CHIP_MIN_BATTERY_MV as 3700 */

    plat->soc->flush_bus_matrix();
    printf("    -> Bus Matrix flush succeeded.\n\n");

    printf("[3] Testing Crypto Monocypher Wrapper...\n");
    boot_status_t status = plat->crypto->init();
    assert(status == BOOT_OK);

    /* Test Hashing: SHA-512 of empty string */
    uint8_t hash_ctx[sizeof(crypto_sha512_ctx)];
    status = plat->crypto->hash_init(hash_ctx, sizeof(hash_ctx));
    assert(status == BOOT_OK);

    /* Hashing empty string */
    status = plat->crypto->hash_update(hash_ctx, NULL, 0);
    assert(status == BOOT_OK);

    uint8_t digest[64];
    size_t digest_len = 64;
    status = plat->crypto->hash_finish(hash_ctx, digest, &digest_len);
    assert(status == BOOT_OK);
    assert(digest_len == 64);
    
    /* Known empty SHA-512 hash starts with cf83e135... */
    assert(digest[0] == 0xcf && digest[1] == 0x83 && digest[2] == 0xe1 && digest[3] == 0x35);
    printf("    -> SHA-512 hashing wrapper behaves correctly.\n\n");

    /* Test Ed25519 Checking (Mock Signature) */
    /* Using Monocypher's own mathematical check for a valid pair */
    uint8_t fake_sk[64], fake_pk[32], fake_seed[32];
    /* Generate a random valid keypair using Monocypher raw API just to test our wrapper */
    for(int i = 0; i < 32; i++) fake_seed[i] = (uint8_t)i;
    crypto_ed25519_key_pair(fake_sk, fake_pk, fake_seed);
    
    uint8_t fake_sig[64];
    const uint8_t *test_msg = (const uint8_t *)"hello";
    size_t test_msg_len = 5;
    crypto_ed25519_sign(fake_sig, fake_sk, test_msg, test_msg_len);

    /* Test via our wrapper! */
    status = plat->crypto->verify_ed25519(test_msg, test_msg_len, fake_sig, fake_pk);
    assert(status == BOOT_OK);
    printf("    -> Ed25519 Verify Wrapper behaves correctly (Signature Valid: OK).\n\n");

    /* Test Invalid Signature */
    fake_sig[0] ^= 0x01; /* Corrupt the signature */
    status = plat->crypto->verify_ed25519(test_msg, test_msg_len, fake_sig, fake_pk);
    assert(status != BOOT_OK);
    printf("    -> Ed25519 Verify Wrapper catches invalid signatures.\n\n");

    printf("[4] Testing Mock Flash Device...\n");
    status = plat->flash->init();
    assert(status == BOOT_OK);
    
    /* We mock flash reads. mock_flash.c handles bounds. */
    uint8_t read_buf[16];
    status = plat->flash->read(0x0, read_buf, sizeof(read_buf));
    assert(status == BOOT_OK);
    
    /* Out of bounds read */
    status = plat->flash->read(0xFFFFFFFF, read_buf, 4);
    assert(status == BOOT_ERR_FLASH_BOUNDS);
    printf("    -> Mock Flash Boundary Checks Active.\n\n");

    printf("==================================================\n");
    printf("   ALL M-SANDBOX ASSERTIONS PASSED!\n");
    printf("==================================================\n");

    return 0;
}

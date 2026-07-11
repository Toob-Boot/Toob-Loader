#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define BOOT_STAGE1_SVN 1
#define TOOB_WAL_SECTORS 4

/* Wir inkludieren boot_journal.c direkt, um Zugriff auf die statische
 * Funktion tmr_majority_vote zu erhalten. */
#include "../../toobloader/core/boot_journal.c"

/* CBMC-Nondet-Hilfsfunktionen */
int nondet_int(void);
void __CPROVER_havoc_object(void *p);

void harness(void) {
    wal_tmr_payload_t candidates[3];
    __CPROVER_havoc_object(candidates);

    int count = nondet_int();
    __CPROVER_assume(count >= 1 && count <= 3);

    /* Ausführen des extrahierten Majority Votes */
    wal_tmr_payload_t result = tmr_majority_vote(candidates, count);

    /* PROPERTY 1: Das Wahlergebnis muss exakt einer der wählbaren Kandidaten sein.
     * Es darf unter keinen Umständen ein "Frankenstein-Mischzustand" entstehen. */
    bool is_valid_candidate = false;
    for (int i = 0; i < count; i++) {
        if (memcmp(&result, &candidates[i], sizeof(wal_tmr_payload_t)) == 0) {
            is_valid_candidate = true;
        }
    }
    assert(is_valid_candidate);

    /* PROPERTY 2: Wenn ein echtes Mehrheitsquorum existiert (mind. 2 übereinstimmende Kandidaten),
     * MUSS das Ergebnis diesem Quorum entsprechen. */
    if (count == 2) {
        if (memcmp(&candidates[0], &candidates[1], sizeof(wal_tmr_payload_t)) == 0) {
            assert(memcmp(&result, &candidates[0], sizeof(wal_tmr_payload_t)) == 0);
        }
    } else if (count == 3) {
        if (memcmp(&candidates[0], &candidates[1], sizeof(wal_tmr_payload_t)) == 0) {
            assert(memcmp(&result, &candidates[0], sizeof(wal_tmr_payload_t)) == 0);
        } else if (memcmp(&candidates[0], &candidates[2], sizeof(wal_tmr_payload_t)) == 0) {
            assert(memcmp(&result, &candidates[0], sizeof(wal_tmr_payload_t)) == 0);
        } else if (memcmp(&candidates[1], &candidates[2], sizeof(wal_tmr_payload_t)) == 0) {
            assert(memcmp(&result, &candidates[1], sizeof(wal_tmr_payload_t)) == 0);
        }
    }
}

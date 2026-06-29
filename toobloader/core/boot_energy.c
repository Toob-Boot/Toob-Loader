/*
 * ==============================================================================
 * Toob-Boot Core File: boot_energy.c (Mathematical Perfection Revision)
 * ==============================================================================
 *
 * REFERENCED SPECIFICATIONS:
 * - docs/hals.md (Batterie/SoC HAL limits, PMIC States)
 * - docs/provisioning_guide.md (Brownout Penalties, min_battery_mv)
 * - docs/concept_fusion.md (Preventive Hardware Protection)
 *
 * ARCHITECTURAL UPGRADES:
 * 1. Brownout Death-Loop Prevention: Fängt Updates bei niedrigem Ladestand ab,
 *    BEVOR der stromfressende Flash-Erase das System physisch zum Absturz
 * bringt.
 * 2. Active Deep-Sleep Punisher: Statt einer fehlerhaften OS-Propagation, die
 *    das System in einer Panic-Loop den Akku leeren lässt, erzwingt diese
 *    Logik einen harten 1-Stunden Deep-Sleep zur Akku-Regeneration.
 * 3. O(1) Transient Noise Filter: Liest den ADC-Wert 3x mit WDT-Delays aus und
 *    wertet verzweigungsfrei den Median aus. Glättet VDD-Ripple und wehrt
 *    Voltage-Glitches bei der ADC-Messung ab.
 * 4. Hysteresis on Brownout: Addiert 12.5% Sicherheitsmarge, falls der letzte
 *    Neustart ein Brownout war, da die Ruhespannung oft trügerisch hoch ist.
 * 5. P10 Control Flow Integrity (CFI): Sichert den Validierungspfad
 * mathematisch gegen Instruction-Skips durch Fault-Injection-Angriffe.
 */


#include "boot_energy.h"
#include "boot_fih.h"
#include "boot_ct_utils.h"
#include "boot_delay.h"
#include "boot_hal.h"
#include "boot_panic.h"
#include "boot_types.h"
#include <stdbool.h>
#include <stdint.h>


/* Mathematisches Glitch-Resistenz-Gating */
_Static_assert(BOOT_OK == 0x55AA55AA,
               "BOOT_OK muss zwingend ein High-Hamming-Weight Pattern sein!");

/* P10 CFI Token Slots (Randomized per boot via TRNG) */
#define ENERGY_CFI_SLOT_INIT     0
#define ENERGY_CFI_SLOT_NO_HAL   1
#define ENERGY_CFI_SLOT_PMIC     2
#define ENERGY_CFI_SLOT_ADC      3

/**
 * @brief Branchless O(1) 3-Sample Median Filter
 *
 * Verhindert, dass kurzzeitiges Rauschen (EMI/EMV) auf der ADC-Leitung
 * ein gültiges Update blockiert oder einen leeren Akku maskiert.
 * Da keine if-Sprünge genutzt werden, ist der Code resistent gegen
 * Simple Power Analysis (SPA) und wird per CSEL (Conditional Select)
 * kompiliert.
 *
 * Mathematischer Beweis: median = max(min(a,b), min(max(a,b), c))
 */
static inline uint32_t branchless_median_3(uint32_t a, uint32_t b, uint32_t c) {
  uint32_t min_ab = (a < b) ? a : b;
  uint32_t max_ab = (a > b) ? a : b;
  uint32_t min_max_ab_c = (max_ab < c) ? max_ab : c;
  return (min_ab > min_max_ab_c) ? min_ab : min_max_ab_c;
}

/**
 * @brief Evaluiert absolut sicher, ob die Stromversorgung Flash-Operationen
 * überlebt.
 *
 * @param platform HAL Platform Pointer
 * @return BOOT_OK wenn genug Energie vorhanden. Bei kritischem Energiemangel
 *         kehrt diese Funktion NIEMALS zurück, sondern friert die CPU sicher
 * ein.
 */
boot_status_t boot_energy_check_safe_update(const boot_platform_t *platform) {
  /* 1. Pointer & HAL Sanity Gating */
  if (!platform || !platform->clock || !platform->clock->get_reset_reason) {
    return BOOT_ERR_INVALID_ARG;
  }

  /* P10 CFI Randomisierung: Tokens zur Laufzeit aus TRNG ableiten */
  uint32_t energy_cfi_seed = 0;
  if (platform->crypto && platform->crypto->random) {
    platform->crypto->random((uint8_t *)&energy_cfi_seed, sizeof(energy_cfi_seed));
  }
  boot_cfi_ctx_t energy_cfi_ctx;
  boot_cfi_init(energy_cfi_ctx, energy_cfi_seed);

  /* ====================================================================
   * 2. FAIL-OPEN FÜR NETZBETRIEB (Wall-Powered Devices)
   * ====================================================================
   * Besitzt das Target keine SoC-HAL (weil Desktop-Gerät oder starr
   * netzbetrieben ohne PMIC), wird das Update bedingungslos freigegeben.
   */
  if (!platform->soc) {
    boot_cfi_add_expected(energy_cfi_ctx, ENERGY_CFI_SLOT_NO_HAL);
    boot_cfi_step(energy_cfi_ctx, ENERGY_CFI_SLOT_NO_HAL);
    boot_cfi_require(energy_cfi_ctx, {
      return BOOT_ERR_INVALID_STATE; /* PC-Glitch Trap */
    });
    return BOOT_OK;
  }

  boot_cfi_add_expected(energy_cfi_ctx, ENERGY_CFI_SLOT_PMIC);
  boot_cfi_add_expected(energy_cfi_ctx, ENERGY_CFI_SLOT_ADC);

  bool pmic_sustain_ok = true;
  bool adc_voltage_ok = true;

  /* ====================================================================
   * 3. COMPLEX PMIC / SUPERCAP EVALUATION
   * ====================================================================
   * Verlässt sich auf die Fuel-Gauge oder externe PMIC-Chips, falls
   * der Vendor diese Logik in der HAL ausprogrammiert hat.
   */
  if (platform->soc->can_sustain_update) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    bool result = platform->soc->can_sustain_update();

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();

    /* Direkter Ausschluss, wenn der PMIC Veto einlegt */
    if (!result)
      pmic_sustain_ok = false;
  }

  boot_cfi_step(energy_cfi_ctx, ENERGY_CFI_SLOT_PMIC);

  /* ====================================================================
   * 4. RAW ADC VOLTAGE EVALUATION (Median Filtered)
   * ====================================================================
   * Evaluierung der Rohspannung gegen den spezifizierten Min-Wert.
   */
  if (platform->soc->battery_level_mv && platform->soc->min_battery_mv > 0) {
    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    uint32_t sample_1 = platform->soc->battery_level_mv();
    boot_delay_with_wdt(platform, 2);

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    uint32_t sample_2 = platform->soc->battery_level_mv();
    boot_delay_with_wdt(platform, 2);

    if (platform->wdt && platform->wdt->kick)
      platform->wdt->kick();
    uint32_t sample_3 = platform->soc->battery_level_mv();

    uint32_t stable_mv = branchless_median_3(sample_1, sample_2, sample_3);

    /* ADC Hardware Failure Traps:
     * 0mV = Komplettausfall / Kurzschluss nach GND
     * 0xFFFFFFFF = Open-Circuit / Kurzschluss nach VDD / I2C Disconnect
     */
    if (stable_mv == 0 || stable_mv == 0xFFFFFFFF) {
      adc_voltage_ok = false;
    } else {
      uint32_t required_mv = platform->soc->min_battery_mv;

      /* BROWNOUT HYSTERESE: Wenn wir aus einem Brownout kommen,
       * müssen wir die Schwelle anheben (+12.5%), um zu verhindern,
       * dass wir sofort wieder abbrechen. Die "Ruhespannung" erholt sich ohne
       * Last trügerisch. */
      reset_reason_t rst = platform->clock->get_reset_reason();
      if (rst == RESET_REASON_BROWNOUT) {
        uint32_t margin = required_mv >> 3;
        /* Overflow-Defense gegen Integer-Wraparound */
        if (UINT32_MAX - required_mv >= margin) {
          required_mv += margin;
        } else {
          required_mv = UINT32_MAX;
        }
      }

      if (stable_mv < required_mv) {
        adc_voltage_ok = false;
      }
    }
  }

  boot_cfi_step(energy_cfi_ctx, ENERGY_CFI_SLOT_ADC);

  /* ====================================================================
   * 5. GLITCH-RESISTANT RESOLUTION & CFI VALIDATION
   * ====================================================================
   */
  boot_cfi_require(energy_cfi_ctx, {
    boot_terminal_halt(platform, BOOT_ERR_INVALID_STATE, SITE_ENERGY_CFI_MISMATCH);
  });

  /* Logik-Akkumulator: Darf das Update geflasht werden? */
  BOOT_SECURE_REQUIRE(pmic_sustain_ok && adc_voltage_ok, {
    goto brownout_trap;
  });
  return BOOT_OK;

brownout_trap:
  /* ========================================================================
   * BROWNOUT DEATH-LOOP TRAP (ACTIVE MITIGATION)
   * ========================================================================
   */
#if BOOT_CONFIG_EDGE_UNATTENDED_MODE
  if (platform->soc->enter_low_power) {
    /* Penalty Sleep: 1 Stunde (3600s) Deep-Sleep Penalty zum Akku laden erzwingen */
    platform->soc->enter_low_power(BOOT_CONFIG_BACKOFF_BASE_S);

    /* Halt-Guard: Falls enter_low_power fehlschlägt/aufwacht, frieren wir das System ein. */
    boot_terminal_halt(platform, BOOT_ERR_POWER, SITE_ENERGY_BROWNOUT);
  }
#endif

  /* Fallback: Wenn Unattended Mode deaktiviert ist oder enter_low_power fehlt.
   * Es bleibt nur der Panic-State, da das Flash-Update tödlich wäre. */
  boot_terminal_halt(platform, BOOT_ERR_POWER, SITE_ENERGY_BROWNOUT);
}
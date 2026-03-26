/**
 * @file kb_tags.h
 * @brief Kernel Builder (KB) Semantic Feature Tags
 *
 * Provides C macros to annotate source code for the Kernel Builder's
 * linker-level module slicing and the OS-Visualizer's (OSV) semantic
 * feature tracking.
 *
 * @osv
 * component: Kernel.API
 *
 * @copyright Copyright (c) Toobloader 2026
 * @license Proprietary
 */

#ifndef KB_TAGS_H
#define KB_TAGS_H

/**
 * @brief Annotates a function or struct as belonging to a specific Feature
 * Capability.
 *
 * @param feature The target feature identifier (e.g., HAL_WIFI,
 * CONFIG_TICKLESS)
 *
 * @todo (Phase 2): Map this to GCC/LD specific `__attribute__((section(".kb."
 * #feature)))` to enforce hard linker exclusion when the feature is disabled in
 * kernel_config.yaml. Currently, this serves as an explicit AST marker tracked
 * by the OS-Visualizer.
 */
#define KB_FEATURE(feature)

/**
 * @brief Annotates a function or struct as strict Core Kernel Logic.
 *
 * Functions marked with KB_CORE are critical to the system's baseline operation
 * (e.g. Ring Switching, Loader, Boot Init) and cannot be toggled via YAML
 * configurations.
 */
#define KB_CORE()

#endif // KB_TAGS_H

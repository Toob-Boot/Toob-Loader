# Bootloader Architecture & Tagging Conventions

Even though "Toobloader" is a standalone, physically extracted repository, you may notice some recurring patterns and macros in the source code. This document explains their origin and purpose.

## The `rp_` Prefix

Functions, structures, or macros prefixed with `rp_` (e.g., `rp_assert.h()`, `rp_boot_state_t`) originate from the larger **Toobloader** ecosystem.
Toobloader uses a strict namespace separation model ("Link-Time Security") to distinguish between low-level drivers (`drv_`), microkernel core internals (`_rp_`), and public SDK interfaces (`rp_`).

While the Toobloader is completely decoupled and standalone, we retain these prefixes to strictly separate the bare-metal boot flow from application logic and to maintain its architectural identity.

## Semantic Tags (`@osv` and `KB_CORE()`)

Throughout the C files, you will often find documentation blocks and macros like this:

```c
/**
 * @osv
 * component: Bootloader.Main
 * tag_status: auto
 */
KB_CORE()
void boot_main(void) { ... }
```

These are markers for the **OS-Visualizer (OSV)** and the **Kernel Builder (KB)** static analysis pipelines used by the core OS team.

1. **`KB_CORE()` / `KB_FEATURE(name)`**: These macros allow custom AST extractors to generate dependency graphs and slice the codebase dynamically at link-time. Functions marked with `KB_CORE()` are foundational elements that cannot be stripped.
2. **`@osv` blocks**: The OS-Visualizer consumes these YAML docstrings to enforce strict architectural rules (such as NASA Power of 10 compliance bounds) and map functions to 3D topological graphs during security audits.

In a standalone Toobloader build, `KB_CORE()` resolves to an empty macro (via `include/common/kb_tags.h`) and costs **0 bytes** of memory or processing time. They exist purely to allow mathematical proving and the rigid audit trail of the firmware through static analysis.

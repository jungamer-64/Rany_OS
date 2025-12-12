/* ============================================================================
 * drivers/driver.ld - ExoRust Dynamic Driver Linker Script
 * ============================================================================
 * 
 * This linker script is used for building standalone driver ELFs that can be
 * dynamically loaded by the kernel at runtime.
 *
 * Usage:
 *   RUSTFLAGS="-C link-arg=-T../driver.ld" cargo build --features standalone
 */

ENTRY(_exorust_driver_entry)

SECTIONS {
    /* Start at address 0 (will be relocated by the ELF loader) */
    . = 0;

    /* Code section */
    .text : {
        *(.text._exorust_driver_entry)
        *(.text .text.*)
    }

    /* Read-only data */
    .rodata : {
        *(.rodata .rodata.*)
    }

    /* Initialized data */
    .data : {
        *(.data .data.*)
    }

    /* Uninitialized data */
    .bss : {
        *(.bss .bss.*)
    }

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}

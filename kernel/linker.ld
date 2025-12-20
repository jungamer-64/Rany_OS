/* Limine Bootloader Linker Script for RanyOS */
/* Supports both UEFI and BIOS boot */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    text            PT_LOAD FLAGS(5);  /* rx */
    rodata          PT_LOAD FLAGS(4);  /* r  */
    data            PT_LOAD FLAGS(6);  /* rw */
    tls             PT_TLS  FLAGS(4);  /* r - Thread Local Storage */
}

SECTIONS
{
    /* Higher half kernel at -2GiB */
    . = 0xffffffff80000000;

    /* Code section */
    .text : {
        *(.text .text.*)
    } :text

    /* Read-only data */
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    /* Data section */
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .data : {
        *(.data .data.*)

        /* Place the sections that contain the Limine requests as part of the .data */
        /* output section. */
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
    } :data

    /* Thread Local Storage */
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .tls : {
        __tls_start = .;
        *(.tdata .tdata.*)
        *(.tbss .tbss.*)
        __tls_end = .;
    } :tls :data

    /* BSS - uninitialized data */
    /* NOTE: .bss needs to be the last thing mapped to :data, otherwise lots of */
    /* unnecessary zeros will be written to the binary. */
    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } :data

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
    }
}

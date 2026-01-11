OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    text            PT_LOAD FLAGS(5);  /* rx */
    rodata          PT_LOAD FLAGS(4);  /* r  */
    data            PT_LOAD FLAGS(6);  /* rw */
    tls             PT_TLS  FLAGS(4);  /* r - Thread Local Storage */
    metadata        PT_NOTE FLAGS(4); /* Non-loadable metadata (symtab, shstrtab, debug info) */
}

SECTIONS
{
    /* Higher half kernel at -2GiB */
    . = 0xffffffff80000000;
    __kernel_start = .;

    /* Place section header string table and other metadata in a non-loadable
       program header to avoid collisions with PT_LOAD file offsets. */
    .shstrtab : { KEEP(*(.shstrtab)) } :metadata

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

    __kernel_end = .;

    /* Discard unnecessary sections (includes DWARF/debug sections to avoid placing
       large debug segments inside loadable ranges and causing overlapping ranges in the final
       kernel image). */
    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
        /* Strip debug sections produced by Rust/LLVM/other deps for kernel image builds */
        *(.debug*)
        *(.zdebug*)

        /* Remove link-time symbol / string tables (not needed in kernel image) to prevent
           file-offset layout collisions with loadable sections. */
        *(.symtab)
        *(.strtab)
        *(.symtab.*)
        *(.gnu.version)
        *(.gnu.version_r)
        *(.gnu_debuglink)
        *(.note.GNU-stack)
    }

    /* Place non-alloc ELF metadata (symbol tables, section name tables, ksymtab, etc.)
       after the kernel image so they do not overlap with loadable segments' file offsets. */
    . = ALIGN(4096);
    .shstrtab : { *(.shstrtab) }
    .symtab   : { *(.symtab) }
    .strtab   : { *(.strtab) }
    .ksymtab  : { *(.ksymtab) *(.ksymtab.*) }
    .ksymtab_gpl : { *(.ksymtab_gpl) *(.ksymtab_gpl.*) }
}

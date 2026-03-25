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
    __kernel_start = .;

    /* Section header string table moved to the non-alloc 'metadata' PHDR at the end
       of this script to ensure file offsets are placed after PT_LOAD data. */

    /* Code section */
    .text : AT(0x1000) {
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

        /* GOT (Global Offset Table): must be in a mapped, writable segment.
           The LLVM backend may emit @GOTPCREL references for vtable pointer loads
           even with code-model=kernel + relocation-model=static. If .got is not
           placed in an output section, the linker creates an orphan section that
           may land outside mapped memory, causing indirect calls through vtable
           pointers to jump to garbage addresses (truncated upper bits). */
        *(.got .got.plt)

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

    /* The unwind subsystem probes these linker symbols and gracefully treats
       zero-valued bounds as "eh_frame unavailable". Keep the section discarded
       for the kernel image, but always provide the symbols so full-boot/test
       links do not fail when Rust emits unwind references. */
    PROVIDE(__eh_frame_start = 0);
    PROVIDE(__eh_frame_end = 0);

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

    /* Non-alloc ELF metadata: let the linker place these after loadable segments.
       Do NOT assign a PHDR — they should not appear as loadable segments in the
       ELF program headers, preventing the bootloader from mapping invalid memory. */
    . = ALIGN(4096);
    .shstrtab (NOLOAD) : { *(.shstrtab) }
    .ksymtab  (NOLOAD) : { *(.ksymtab) *(.ksymtab.*) }
    .ksymtab_gpl (NOLOAD) : { *(.ksymtab_gpl) *(.ksymtab_gpl.*) }
}

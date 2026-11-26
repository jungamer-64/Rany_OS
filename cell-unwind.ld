SECTIONS {
    .eh_frame_hdr : { PROVIDE_HIDDEN(__GNU_EH_FRAME_HDR = .); *(.eh_frame_hdr) }
    PROVIDE_HIDDEN(__executable_start = ADDR(.text));
    PROVIDE_HIDDEN(__etext = ADDR(.text) + SIZEOF(.text));
}
INSERT AFTER .rodata;

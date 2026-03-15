use core::arch::global_asm;

global_asm!(
    r#"
.section .ap_trampoline,"a"
.balign 16
.global __ap_trampoline_start
.global __ap_trampoline_end
.global __ap_patch_long_mode_far_ptr
.global __ap_patch_gdt_descriptor_base
.global __ap_patch_gdt_code_base
.global __ap_patch_gdt_data_base
.set AP_GDT_DESCRIPTOR_OFFSET, ap_gdt_descriptor - __ap_trampoline_start
.set AP_MAILBOX_PAGE_TABLE_OFFSET, ap_mailbox - __ap_trampoline_start + 8
.set AP_LONG_MODE_FAR_PTR_OFFSET, ap_long_mode_far_ptr - __ap_trampoline_start
.code16
__ap_trampoline_start:
    cli
    cld
    xor ax, ax
    mov ss, ax
    mov sp, 0x7000
    mov ax, cs
    mov ds, ax
    mov es, ax
    lgdt [AP_GDT_DESCRIPTOR_OFFSET]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    .byte 0xea
    .word protected_mode_entry - __ap_trampoline_start
    .word 0x08
.code32
protected_mode_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax
    mov eax, DWORD PTR [AP_MAILBOX_PAGE_TABLE_OFFSET]
    mov cr3, eax
    mov ecx, 0xc0000080
    rdmsr
    or eax, 0x900
    wrmsr
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax
    .byte 0xff, 0x2d
    .long AP_LONG_MODE_FAR_PTR_OFFSET
.balign 8
ap_long_mode_far_ptr:
__ap_patch_long_mode_far_ptr:
    .long 0
    .word 0x18
.code64
long_mode_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov rax, cr0
    and rax, 0xfffffffffffffffb
    and rax, 0xfffffffffffffff7
    mov cr0, rax
    mov rax, cr4
    or rax, 0x600
    mov cr4, rax
    mov rsp, QWORD PTR [rip + ap_mailbox + 16]
    lea rdi, [rip + ap_mailbox]
    mov rax, QWORD PTR [rip + ap_mailbox + 24]
    call rax
.hang:
    cli
    hlt
    jmp .hang
.balign 8
ap_gdt_descriptor:
    .word ap_gdt_end - ap_gdt - 1
__ap_patch_gdt_descriptor_base:
    .long 0
.balign 8
ap_gdt:
    .quad 0
    .word 0xffff
__ap_patch_gdt_code_base:
    .word 0
    .byte 0
    .byte 0x9a
    .byte 0xcf
    .byte 0
    .word 0xffff
__ap_patch_gdt_data_base:
    .word 0
    .byte 0
    .byte 0x92
    .byte 0xcf
    .byte 0
    .quad 0x00af9a000000ffff
ap_gdt_end:
    .zero 0x200 - (. - __ap_trampoline_start)
ap_mailbox:
    .long 0
    .long 0
    .quad 0
    .quad 0
    .quad 0
    .quad 0
__ap_trampoline_end:
"#
);

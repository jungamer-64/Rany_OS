// ============================================================================
// libs/ap_trampoline/src/trampoline_asm.rs
// ============================================================================
use core::arch::global_asm;

// Keep the assembler constants sourced from `contract.rs` so the Rust image
// patching code and the trampoline binary stay in lockstep.
global_asm!(
    r#"
.section .ap_trampoline,"a"
.balign 16
.global __ap_trampoline_start
.global __ap_trampoline_end
.global __ap_long_mode_entry
.global __ap_patch_long_mode_far_ptr
.global __ap_patch_gdt_descriptor
.global __ap_patch_gdt
.global __ap_mailbox
.set AP_GDT_DESCRIPTOR_OFFSET, __ap_patch_gdt_descriptor - __ap_trampoline_start
.set AP_LONG_MODE_FAR_PTR_OFFSET, __ap_patch_long_mode_far_ptr - __ap_trampoline_start
.code16
__ap_trampoline_start:
    cli
    cld
    mov ax, cs
    mov ss, ax
    mov sp, {trampoline_size}
    mov ds, ax
    mov es, ax
    lgdt [AP_GDT_DESCRIPTOR_OFFSET]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    .byte 0xea
    .word protected_mode_entry - __ap_trampoline_start
    .word {gdt_code32_selector}
.code32
protected_mode_entry:
    mov ax, {gdt_data32_selector}
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr4
    or eax, 0x20
    mov cr4, eax
    mov eax, DWORD PTR [{mailbox_page_table_offset}]
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
__ap_patch_long_mode_far_ptr:
    .zero 6
.code64
__ap_long_mode_entry:
    mov ax, {gdt_data32_selector}
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax
    mov rax, cr0
    and rax, -13
    mov cr0, rax
    mov rax, cr4
    or rax, 0x600
    mov cr4, rax
    mov rsp, QWORD PTR [rip + __ap_mailbox + {mailbox_stack_ptr_offset}]
    lea rdi, [rip + __ap_mailbox]
    mov rax, QWORD PTR [rip + __ap_mailbox + {mailbox_entry_point_offset}]
    call rax
.hang:
    cli
    hlt
    jmp .hang
__ap_patch_gdt_descriptor:
    .zero 6
__ap_patch_gdt:
    .zero {gdt_size}
.zero {mailbox_offset} - (. - __ap_trampoline_start)
__ap_mailbox:
    .zero {mailbox_size}
__ap_trampoline_end:
"#,
    gdt_code32_selector = const crate::contract::GDT32_CODE_SELECTOR,
    gdt_data32_selector = const crate::contract::GDT32_DATA_SELECTOR,
    mailbox_offset = const crate::MAILBOX_OFFSET,
    mailbox_size = const core::mem::size_of::<crate::mailbox::ApTrampolineMailbox>(),
    mailbox_page_table_offset =
        const crate::MAILBOX_OFFSET + crate::mailbox::MAILBOX_PAGE_TABLE_OFFSET,
    mailbox_stack_ptr_offset = const crate::mailbox::MAILBOX_STACK_PTR_OFFSET,
    mailbox_entry_point_offset = const crate::mailbox::MAILBOX_ENTRY_POINT_OFFSET,
    gdt_size = const crate::contract::GDT_SIZE,
    trampoline_size = const crate::TRAMPOLINE_SIZE,
);

BITS 16
ORG 0

%define TRAMPOLINE_MAILBOX_OFFSET 0x200
%define AP_MAILBOX_AP_SLOT      (TRAMPOLINE_MAILBOX_OFFSET + 0)
%define AP_MAILBOX_CPU_ID       (TRAMPOLINE_MAILBOX_OFFSET + 4)
%define AP_MAILBOX_PAGE_TABLE   (TRAMPOLINE_MAILBOX_OFFSET + 8)
%define AP_MAILBOX_STACK_PTR    (TRAMPOLINE_MAILBOX_OFFSET + 16)
%define AP_MAILBOX_ENTRY_POINT  (TRAMPOLINE_MAILBOX_OFFSET + 24)
%define AP_MAILBOX_PROBE_ADDR   (TRAMPOLINE_MAILBOX_OFFSET + 32)

%macro serial_mark16 1
    push ax
    push dx
    mov dx, 0x3F8
    mov al, %1
    out dx, al
    pop dx
    pop ax
%endmacro

%macro serial_mark32 1
    push eax
    push edx
    mov dx, 0x3F8
    mov al, %1
    out dx, al
    pop edx
    pop eax
%endmacro

%macro serial_mark64 1
    push rax
    push rdx
    mov dx, 0x3F8
    mov al, %1
    out dx, al
    pop rdx
    pop rax
%endmacro

ap_trampoline_start:
    cli
    cld
    serial_mark16 'r'

    xor ax, ax
    mov ss, ax
    mov sp, 0x7000

    mov ax, cs
    mov ds, ax
    mov es, ax

    xor eax, eax
    mov ax, cs
    shl eax, 4
    mov esi, eax

    mov eax, esi
    add eax, ap_gdt
    mov [ap_gdt_descriptor + 2], eax

    mov eax, esi
    mov word [ap_gdt + 8 + 2], ax
    shr eax, 16
    mov byte [ap_gdt + 8 + 4], al
    mov byte [ap_gdt + 8 + 7], ah

    mov eax, esi
    mov word [ap_gdt + 16 + 2], ax
    shr eax, 16
    mov byte [ap_gdt + 16 + 4], al
    mov byte [ap_gdt + 16 + 7], ah

    lgdt [ap_gdt_descriptor]

    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:protected_mode_entry

BITS 32
protected_mode_entry:
    serial_mark32 'p'
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    mov eax, [AP_MAILBOX_PAGE_TABLE]
    mov cr3, eax

    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8) | (1 << 11)
    wrmsr

    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax

    mov eax, esi
    add eax, long_mode_entry
    mov [long_mode_far_ptr], eax
    jmp far [long_mode_far_ptr]

align 8
long_mode_far_ptr:
    dd 0
    dw 0x18

BITS 64
DEFAULT REL
long_mode_entry:
    serial_mark64 'l'
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax

    ; Rust/x86_64 ABI requires SSE/SSE2 to be enabled on each AP.
    mov rax, cr0
    and rax, ~(1 << 2)
    and rax, ~(1 << 3)
    mov cr0, rax

    mov rax, cr4
    or rax, (1 << 9) | (1 << 10)
    mov cr4, rax

    mov rsp, [ap_mailbox + 16]
    mov edi, [ap_mailbox + 0]
    mov esi, [ap_mailbox + 4]
    mov rbx, [ap_mailbox + 32]
    mov al, [rbx]
    cmp al, 0x5A
    jne .probe_failed
    jmp .probe_done

.probe_failed:

.probe_done:
    serial_mark64 'c'
    mov rax, [ap_mailbox + 24]
    call rax

.hang:
    cli
    hlt
    jmp .hang

align 8
ap_gdt_descriptor:
    dw ap_gdt_end - ap_gdt - 1
    dd 0

align 8
ap_gdt:
    dq 0x0000000000000000
    dq 0x00CF9A000000FFFF
    dq 0x00CF92000000FFFF
    dq 0x00AF9A000000FFFF
ap_gdt_end:

times (TRAMPOLINE_MAILBOX_OFFSET - ($ - $$)) db 0

ap_mailbox:
    dd 0
    dd 0
    dq 0
    dq 0
    dq 0
    dq 0

ap_trampoline_end:

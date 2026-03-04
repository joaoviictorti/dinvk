#[cfg(target_arch = "x86_64")]
core::arch::global_asm!("
.global do_syscall

.section .text

do_syscall:
    mov [rsp - 0x8],  rsi
    mov [rsp - 0x10], rdi
    mov [rsp - 0x18], r12

    mov eax, ecx
    mov r12, rdx
    mov rcx, r8

    mov r10, r9
    mov rdx,  [rsp + 0x28]
    mov r8,   [rsp + 0x30]
    mov r9,   [rsp + 0x38]

    sub rcx, 0x4
    jle skip

    lea rsi,  [rsp + 0x40]
    lea rdi,  [rsp + 0x28]

    rep movsq
skip:

    mov rcx, r12

    mov rsi, [rsp - 0x8]
    mov rdi, [rsp - 0x10]
    mov r12, [rsp - 0x18]

    jmp rcx
");

#[cfg(target_arch = "x86")]
core::arch::global_asm!("
.global _do_syscall

.section .text

_do_syscall:
    mov ecx, [esp + 0x0C]
    not ecx
    add ecx, 1
    lea edx, [esp + ecx * 4]

    mov ecx, [esp]
    mov [edx], ecx

    mov [edx - 0x04], esi
    mov [edx - 0x08], edi

    mov eax, [esp + 0x04]
    mov ecx, [esp + 0x0C]

    lea esi, [esp + 0x10]
    lea edi, [edx + 0x04]

    rep movsd

    mov esi, [edx - 0x04]
    mov edi, [edx - 0x08]
    mov ecx, [esp + 0x08]
    
    mov esp, edx

    mov edx, fs:[0xC0]
    test edx, edx
    je native

    mov edx, fs:[0xC0]
    jmp ecx

native:
    mov edx, ecx
    sub edx, 0x05
    push edx
    mov edx, esp
    jmp ecx
    ret

is_wow64:
");

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!("
.global do_syscall
.section .text

do_syscall:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]

    mov x19, x0
    mov x20, x1
    mov x21, x2
    mov x22, x3
    mov x23, x4
    mov x24, x5
    mov x25, x6
    mov x26, x7

    mov x27, #0
    subs x9, x20, #8
    csel x27, x27, x9, mi

    add x28, x27, #1
    bic x28, x28, #1
    lsl x28, x28, #3
    sub sp, sp, x28

    cbz x27, .Lsetup_regs

    add x9, x29, #112
    mov x10, sp
    mov x11, x27

.Lcopy_stack:
    ldr x12, [x9], #8
    str x12, [x10], #8
    subs x11, x11, #1
    b.ne .Lcopy_stack

.Lsetup_regs:
    mov x0, x21
    mov x1, x22
    mov x2, x23
    mov x3, x24
    mov x4, x25
    mov x5, x26

    cmp x20, #6
    b.le .Lcall
    ldr x6, [x29, #96]

    cmp x20, #7
    b.le .Lcall
    ldr x7, [x29, #104]

.Lcall:
    blr x19

    add sp, sp, x28
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret
");

#[doc(hidden)]
#[allow(unused_doc_comments)]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
unsafe extern "C" {
    pub fn do_syscall(
        ssn: u16,
        syscall_addr: usize,
        n_args: u32,
        ...
    ) -> i32;
}

#[doc(hidden)]
#[allow(unused_doc_comments)]
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    pub fn do_syscall(
        fn_ptr: *mut core::ffi::c_void,
        n_args: u32,
        ...
    ) -> i32;
}
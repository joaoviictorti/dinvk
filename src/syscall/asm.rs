// Copyright (c) 2025 joaoviictorti
// Licensed under the MIT License. See LICENSE file in the project root for details.

//! Reference: <https://github.com/janoglezcampos/rust_syscalls>

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

#[doc(hidden)]
#[allow(unused_doc_comments)]
#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    pub fn do_syscall(
        ssn: u16,
        syscall_addr: u64,
        n_args: u32,
        ...
    ) -> i32;
}

#[doc(hidden)]
#[allow(unused_doc_comments)]
#[cfg(target_arch = "x86")]
unsafe extern "C" {
    pub fn do_syscall(
        ssn: u16,
        syscall_addr: u32,
        n_args: u32,
        ...
    ) -> i32;
}
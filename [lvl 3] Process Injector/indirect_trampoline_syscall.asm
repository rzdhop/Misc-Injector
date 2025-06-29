; w/ nasm -f win64 NtCreateThreadEx.asm -o NtCreateThreadEx.o
default rel
extern g_SSN_NtCreateThreadEx
extern g_Stub_NtCreateThreadEx  
global stubNtCreateThreadEx
section .text

stubNtCreateThreadEx:
    mov     r10, rcx        ; r10 : adresse syscall (stub+0x12)
    mov     eax, [g_SSN_NtCreateThreadEx]        ; eax : SSN
    jmp [g_Stub_NtCreateThreadEx]
    ret
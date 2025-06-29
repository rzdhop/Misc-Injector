; syscall_stub.asm
global syscall_trampoline7
;Compile avec : nasm -f win64 .\indirect_trampoline_syscall.asm -o indirect_trampoline_syscall.o
section .text
syscall_trampoline7:
; NTSTATUS syscall_trampoline7(PBYTE syscallStub, DWORD syscallID, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7);
    mov r10, rcx                ; r10 = syscallStub
    mov eax, edx                ; eax = syscallID

    mov rcx, r8                 ; rcx (argv[0]) = arg1 
    mov rdx, r9                 ; rcx (argv[0]) = arg1 
    mov r8, [rsp+0x28]
    mov r9, [rsp+0x30] 

    ;Les args 5 - 7 sur la stack
    sub rsp, 0x28               ; On alloue l'espace pour les args a venir
    mov r11, [rsp+0x60]         ; arg5 depuis ancienne pile
    mov [rsp+0x28], r11

    mov r11, [rsp+0x68]         ; arg6
    mov [rsp+0x30], r11

    mov r11, [rsp+0x70]         ; arg7
    mov [rsp+0x38], r11

    call r10                    ; Call stub
    add rsp, 0x28
    ret

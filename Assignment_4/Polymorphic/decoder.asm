; Filename    : decoder.asm
; Author      : Joris Hartog
; Date        : 17-12-2015
; Student     : SLAE-704
; Description : This program decodes the shellcode by XOR'ing each encoded byte
;  with the previous encoded byte. The first encoded byte gets XOR'd with a key. 

global _start

section .text

_start:

	jmp short shellcodeCall

continueCode:
	
	pop esi			; esi contains pointer to shellcode
	push byte 0xAA
	pop eax			; eax contains the key
	push byte 0xAA
	pop ecx			; ecx contains the shellcode length minus one

	mov dl, byte [esi]	; dl contains the encoded byte
	xor byte [esi], al

decode:
	
	mov bl, dl
	inc esi
	mov dl, byte [esi]
	xor byte [esi], bl

	loop decode

	jmp short shellcode

shellcodeCall:

	call continueCode
	shellcode: db 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF

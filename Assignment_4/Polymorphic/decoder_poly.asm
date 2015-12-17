; Filename    : decoder.asm
; Author      : Joris Hartog
; Date        : 17-12-2015
; Student     : SLAE-704
; Size        : 25 (code) + 44 (decoder) = 69
; Description : This program decodes the shellcode by XOR'ing each encoded byte
;  with the previous encoded byte. The first encoded byte gets XOR'd with a key. 

global _start

section .text

_start:

	jmp short shellcodeCall

continueCode:
	
	;7;
	nop

	pop esi
	;1;
	xor eax, eax		;push byte 0xAA
	mov al, 0xAA		;pop eax
	;2;
	xor ecx, ecx		;push byte 0xAA
	mov cl, 0xAA		;pop ecx
	;3;
	mov bl, byte [esi]	;mov dl, byte [esi]
	
	;4;
	xor al, byte [esi]	;xor byte [esi], al
	mov byte [esi], al
decode:
	;3;
	mov dl, bl		;mov bl, dl
	;5;
	add esi, 1		;inc esi
	;3;	
	mov bl, byte [esi]	;mov dl, byte [esi]
	xor byte [esi], dl	;xor byte [esi], bl
	;6;
	dec ecx			;loop decode
	jnz decode

	jmp short shellcode

shellcodeCall:

	;8;
	nop
	call continueCode
	shellcode: db 0xAA,0xBB,0xCC,0xDD,0xEE,0xFF

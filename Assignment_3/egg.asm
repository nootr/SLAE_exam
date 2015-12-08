; egg.asm
; Author : Joris Hartog
; Date   : 23-11-2015
; Student: SLAE-704

; Filename    : egg.asm
; Author      : Joris Hartog
; Date        : 23-11-2015
; Student     : SLAE-704
; Size        : 49 bytes 
; Description : This program prints "Egg was found! \n"
;               and exits gracefully.

global _start


section .text

_start:
	
	; This is the actual egg
	push eax
	pop eax
	push eax
	pop eax
	
	; print "Egg was found! \n"
	push byte 0x4
	pop eax

	push byte 0x1
	pop ebx
	 	
	push 0x0a202164
	push 0x6e756f66
	push 0x20736177
	push 0x20676765
	push 0x20656854
	mov ecx, esp

	push byte 0x14
	pop edx

	int 0x80

	; exit program
	push byte 0x1
	pop eax
	int 0x80


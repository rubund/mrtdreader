/*
 *   crypto-openssl.c - Cryptography routines needed by mrtreader using
 *     openssl.
 *
 *   Copyright (C) 2014 Ruben Undheim <ruben.undheim@gmail.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/des.h>


void mrtd_crypto_sha1(uint8_t *input, int length, uint8_t *output)
{
	SHA1(input,length,output);
}

void mrtd_crypto_crypt_des(uint8_t *input, uint8_t *output, int length, uint8_t *key, char encrypt)
{
	DES_cblock key1;
	DES_cblock iv = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	DES_key_schedule schedule1;
	memcpy(key1,key,8);
	DES_set_key((C_Block *)&key1,&schedule1);
	DES_cbc_encrypt(input,output,length,&schedule1,&iv,encrypt);

}

void mrtd_crypto_encrypt_des(uint8_t *input, uint8_t *output, int length, uint8_t *key)
{
	mrtd_crypto_crypt_des(input,output,length,key,1);
}

void mrtd_crypto_decrypt_des(uint8_t *input, uint8_t *output, int length, uint8_t *key)
{
	mrtd_crypto_crypt_des(input,output,length,key,0);
}

void mrtd_crypto_crypt_3des(uint8_t *input, uint8_t *output, int length, uint8_t *key, char encrypt)
{
	DES_cblock key1,key2;
	DES_cblock iv = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	DES_key_schedule schedule1,schedule2;
	memcpy(key1,key,8);
	memcpy(key2,key+8,8);
	DES_set_key((C_Block *)&key1,&schedule1);
	DES_set_key((C_Block *)&key2,&schedule2);
	DES_ede2_cbc_encrypt(input,output,length,&schedule1,&schedule2,&iv,encrypt);
}

void mrtd_crypto_encrypt_3des(uint8_t *input, uint8_t *output, int length, uint8_t *key)
{
	mrtd_crypto_crypt_3des(input,output,length,key,1);
}

void mrtd_crypto_decrypt_3des(uint8_t *input, uint8_t *output, int length, uint8_t *key)
{
	mrtd_crypto_crypt_3des(input,output,length,key,0);
}

void mrtd_crypto_fix_parity(uint8_t *input, uint8_t *output, int length, int *newlength)
{
	int i,j;
	unsigned char y;
	int parity;
	*newlength = length+(length/8);
	for(i=0;i<length;i++){
		y = input[i] & 0xfe;	
		parity = 0;
		for(j=0;j<8;j++){
			parity += y >> j & 1;
		}
		if(parity % 2 == 0){
			output[i] = (char)(y + 1);
		}
		else{
			output[i] = y;
		}
	}

}
void mrtd_crypto_padding(uint8_t *input, uint8_t *output, int length, int *newlength)
{
	*newlength = ((length+8)/8)*8;
	memset(output,0,*newlength);
	memcpy(output,input,length);
	output[length] = 0x80;
}

void mrtd_crypto_mac(uint8_t *input, uint8_t *output, int length, uint8_t *key)
{
	int i,j;
	uint8_t current[8];
	uint8_t mac[8];
	uint8_t left[8];
	uint8_t right[8];
	uint8_t machex[8];
	uint8_t tmp[8];
	memset(mac,0,8);
	for(i=0;i<(length/8);i++){
		for(j=0;j<8;j++){
			current[j] = input[i*8+j];
		}
		for(j=0;j<8;j++){
			left[j] = mac[j];
			right[j] = current[j];
			machex[j] = mac[j] ^ current[j];
		}
		mrtd_crypto_encrypt_des(machex,mac,8,key);
	}
	mrtd_crypto_decrypt_des(mac,tmp,8,key+8);
	mrtd_crypto_encrypt_des(tmp,output,8,key);
}

void mrtd_crypto_mac_padding(uint8_t *input, uint8_t *output, int length, uint8_t *key)
{
	int newlength;
	uint8_t *tmp;
	tmp = malloc(((length+8)/8)*8);
	mrtd_crypto_padding(input,tmp,length,&newlength);
	mrtd_crypto_mac(tmp,output,newlength,key);

	free(tmp);
}

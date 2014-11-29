/*
 *   crypto-tomgrypt.c - Cryptography routines needed by mrtreader using
 *     libtomcrypt.
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
#include <tomcrypt.h>


void mrtd_crypto_sha1(uint8_t *input, int length, uint8_t *output)
{
	hash_state md;
	sha1_init(&md);
	sha1_process(&md, (const unsigned char*) input, length);
	sha1_done(&md, output);
}

void mrtd_crypto_crypt_des(uint8_t *input, uint8_t *output, int length, uint8_t *key, char encrypt)
{
	int err;
	symmetric_CBC cbc_state;
	char IV[8];

	memset(IV,0,8);

	if(register_cipher(&des_desc) == -1){
		printf("Error registering cipher\n");
	}
	if((err = cbc_start(find_cipher("des"),IV,key,8,0,&cbc_state)) != CRYPT_OK){
		printf("cbc_start error: %s\n", error_to_string(err));
	}
	if(encrypt){
		if((err = cbc_encrypt(input,output,length,&cbc_state)) != CRYPT_OK){
			printf("cbc_encrypt error: %s\n", error_to_string(err));
		}
	}
	else{
		if((err = cbc_decrypt(input,output,length,&cbc_state)) != CRYPT_OK){
			printf("cbc_encrypt error: %s\n", error_to_string(err));
		}
	}
	if((err = cbc_done(&cbc_state)) != CRYPT_OK){
		printf("cbc_done error: %s\n", error_to_string(err));
	}
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
	int err;
	symmetric_CBC cbc_state;
	char longkey[24];
	char IV[8];

	memcpy(longkey,key,16);
	memcpy(longkey+16,key,8);
	memset(IV,0,8);

	if(register_cipher(&des3_desc) == -1){
		printf("Error registering cipher\n");
		exit(-1);
	}
	if((err = cbc_start(find_cipher("3des"),IV,longkey,24,0,&cbc_state)) != CRYPT_OK){
		printf("cbc_start error: %s\n", error_to_string(err));
		exit(-1);
	}
	if(encrypt){
		if((err = cbc_encrypt(input,output,length,&cbc_state)) != CRYPT_OK){
			printf("cbc_encrypt error: %s\n", error_to_string(err));
			exit(-1);
		}
	}
	else{
		if((err = cbc_decrypt(input,output,length,&cbc_state)) != CRYPT_OK){
			printf("cbc_encrypt error: %s\n", error_to_string(err));
			exit(-1);
		}
	}
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
void mrtd_crypto_padding_remove(uint8_t *input, uint8_t *output, int length, int *newlength)
{
	int i;
	int pos;
	char found = 0;
	for(i=length-1;i>=0;i--){
		if(input[i] == 0x00) {
			continue;
		}
		else if(input[i] == 0x80) {
			pos = i;
			found = 1;
			break;
		}
		else {
			goto failed;
		}
	}
	if(found){
		*newlength = pos;
		memcpy(output,input,*newlength);
	}
	else{
		goto failed;
	}

	return;

	failed:
		*newlength = 0;
		return;
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

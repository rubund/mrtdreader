/*
 *   bachelper.c - functions that implement basic algorithms that are
 *     part of the BAC procedure
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
#include "crypto.h"


static int endianness(){
	int i = 1;
	char *p = (char *)&i;
	if(p[0] == 1)
		return 0;
	else
		return 1;
}

void mrtd_bac_kenc_kmac(uint8_t *input, uint8_t *kenc, uint8_t *kmac)
{
	uint8_t hash[20];
	uint8_t k[20];
	int tmp;
	memcpy(hash,input,16);
	memcpy(hash+16,"\x00\x00\x00\x01",4);
	mrtd_crypto_sha1(hash,20,k);
	mrtd_crypto_fix_parity(k,kenc,20,&tmp);

	hash[19] = 0x02;
	mrtd_crypto_sha1(hash,20,k);
	mrtd_crypto_fix_parity(k,kmac,20,&tmp);
}

void mrtd_bac_kmrz_to_kenc_kmac(uint8_t *kmrz, uint8_t *kenc, uint8_t *kmac)
{
	uint8_t hash[20];
	mrtd_crypto_sha1(kmrz,24,hash);
	mrtd_bac_kenc_kmac(hash,kenc,kmac);
}

void mrtd_bac_eifd_mifd(uint8_t *rnd_ifd, uint8_t *kifd, uint8_t *remote_challenge, uint8_t *kenc, uint8_t *kmac, uint8_t *eifd, uint8_t *mifd)
{
	uint8_t S[32];
	memcpy(S,rnd_ifd,8);
	memcpy(S+8,remote_challenge,8);
	memcpy(S+16,kifd,16);

	mrtd_crypto_encrypt_3des(S,eifd,32,kenc);
	mrtd_crypto_mac_padding(eifd,mifd,32,kmac);
}

void mrtd_bac_cmd_data(uint8_t *rnd_ifd, uint8_t *kifd, uint8_t *remote_challenge, uint8_t *kenc, uint8_t *kmac, uint8_t *cmd_data)
{
	mrtd_bac_eifd_mifd(rnd_ifd,kifd,remote_challenge,kenc,kmac,cmd_data,cmd_data+32);
}


char mrtd_bac_challenge_ok(uint8_t *rx_data, uint8_t *kenc, uint8_t *rnd_ifd, uint8_t *rnd_icc, uint8_t *kicc)
{
	int i;
	uint8_t decryptedresp[32];
	uint8_t *resp;
	uint8_t *mac_received;
	uint8_t *rec_ifd;

	resp = rx_data;
	mac_received = rx_data+32;

	mrtd_crypto_decrypt_3des(resp,decryptedresp,32,kenc);

	if(rnd_icc != NULL)
		memcpy(rnd_icc,decryptedresp,8);
	if(kicc != NULL)
		memcpy(kicc,decryptedresp+16,16);
	rec_ifd = decryptedresp+8;
	for(i=0;i<8;i++){
		if(rec_ifd[i] != rnd_ifd[i]){
			return 0;
		}
	}
	return 1;
}

uint64_t mrtd_bac_get_ssc(uint8_t *remote_challenge, uint8_t *rnd_ifd)
{
	char ssc[8];
	uint64_t ssc_long;

	memcpy(ssc,remote_challenge+4,4);
	memcpy(ssc+4,rnd_ifd+4,4);

	if(endianness()){
		*(((uint8_t*)(&ssc_long))+0) = ssc[0];
		*(((uint8_t*)(&ssc_long))+1) = ssc[1];
		*(((uint8_t*)(&ssc_long))+2) = ssc[2];
		*(((uint8_t*)(&ssc_long))+3) = ssc[3];
		*(((uint8_t*)(&ssc_long))+4) = ssc[4];
		*(((uint8_t*)(&ssc_long))+5) = ssc[5];
		*(((uint8_t*)(&ssc_long))+6) = ssc[6];
		*(((uint8_t*)(&ssc_long))+7) = ssc[7];
	}
	else {
		*(((uint8_t*)(&ssc_long))+7) = ssc[0];
		*(((uint8_t*)(&ssc_long))+6) = ssc[1];
		*(((uint8_t*)(&ssc_long))+5) = ssc[2];
		*(((uint8_t*)(&ssc_long))+4) = ssc[3];
		*(((uint8_t*)(&ssc_long))+3) = ssc[4];
		*(((uint8_t*)(&ssc_long))+2) = ssc[5];
		*(((uint8_t*)(&ssc_long))+1) = ssc[6];
		*(((uint8_t*)(&ssc_long))+0) = ssc[7];
	}

	return ssc_long;
}


void mrtd_bac_protected_apdu(uint8_t *input, uint8_t *output, int length, int *outputlength, uint8_t *ksenc, uint8_t *ksmac, uint64_t ssc_long)
{
	int datalength;
	char has_le;
	uint8_t *do87 = NULL;
	uint8_t do8e[10];
	uint8_t padded_command[8];
	uint8_t *A;
	int padded_data_length;
	int do87_length;
	uint8_t *do97 = NULL;
	int do97_length;
	uint8_t le;

	if(length > 5){
		datalength = (int)input[4];
	}
	else{
		datalength = 0;
	}
	if(datalength != 0 ? length > (5+datalength) : length == 5){
		le = input[length-1];
		has_le = 1;
	}
	else{
		le = 0;
		has_le = 0;
	}

	//printf("datalength: %d\n",datalength);
	//printf("hasle: %d\n",has_le);
	int i;

	if(datalength != 0){
		uint8_t *padded_data;
		padded_data = malloc(((datalength+8)/8)*8);
		mrtd_crypto_padding(input+5,padded_data,datalength,&padded_data_length);
		do87 = malloc(padded_data_length+3);
		mrtd_crypto_encrypt_3des(padded_data,do87+3,padded_data_length,ksenc);
		do87[0] = 0x87;
		do87[1] = 0x09;
		do87[2] = 0x01;
		do87_length = padded_data_length+3;

		free(padded_data);
	}
	else{
		do87_length = 0;
		padded_data_length = 0;
	}

	if(has_le){
		do97_length = 3;
		do97 = malloc(do97_length);
		do97[0] = 0x97;
		do97[1] = 0x01;
		do97[2] = le;
	}
	else{
		do97_length = 0;
	}

	int padded_command_length;
	mrtd_crypto_padding(input,padded_command,4,&padded_command_length);
	padded_command[0] = 0x0c;


	A = malloc(16+do87_length+do97_length);
	if(endianness()){
		A[0] = *(((uint8_t*)(&ssc_long))+0);
		A[1] = *(((uint8_t*)(&ssc_long))+1);
		A[2] = *(((uint8_t*)(&ssc_long))+2);
		A[3] = *(((uint8_t*)(&ssc_long))+3);
		A[4] = *(((uint8_t*)(&ssc_long))+4);
		A[5] = *(((uint8_t*)(&ssc_long))+5);
		A[6] = *(((uint8_t*)(&ssc_long))+6);
		A[7] = *(((uint8_t*)(&ssc_long))+7);
	}
	else {
		A[0] = *(((uint8_t*)(&ssc_long))+7);
		A[1] = *(((uint8_t*)(&ssc_long))+6);
		A[2] = *(((uint8_t*)(&ssc_long))+5);
		A[3] = *(((uint8_t*)(&ssc_long))+4);
		A[4] = *(((uint8_t*)(&ssc_long))+3);
		A[5] = *(((uint8_t*)(&ssc_long))+2);
		A[6] = *(((uint8_t*)(&ssc_long))+1);
		A[7] = *(((uint8_t*)(&ssc_long))+0);
	}
	memcpy(A+8,padded_command,8);
	if(do87 != NULL)
		memcpy(A+16,do87,do87_length);
	if(do97 != NULL)
		memcpy(A+16+do87_length,do97,do97_length);


	do8e[0] = 0x8e;
	do8e[1] = 0x08;

	mrtd_crypto_mac_padding(A,do8e+2,16+do87_length+do97_length,ksmac);

	(*outputlength) = 5+do87_length+do97_length+10+1;
	memcpy(output,padded_command,4);
	output[4] = (*outputlength)-6;
	if(do87 != NULL)
		memcpy(output+5,do87,do87_length);
	if(do97 != NULL)
		memcpy(output+5+do87_length,do97,do97_length);
	memcpy(output+5+do87_length+do97_length,do8e,10);
	output[(*outputlength)-1] = 0x00;

	//printf("tot_length: %d\n",*outputlength);

	free(A);
	if(do87 != NULL)
		free(do87);
	if(do97 != NULL)
		free(do97);

	return ;
}

void mrtd_bac_decrypt_response(uint8_t *input, uint8_t *output, int length, int *outputlength, uint8_t *ksenc)
{
	uint8_t *tmp;
	int tmplength;
	char *tobedecrypted = input+3;
	tmplength = length-16-3;
	if(tmplength > 0){
		tmp = malloc(tmplength);

		mrtd_crypto_decrypt_3des(tobedecrypted,tmp,tmplength,ksenc);

		mrtd_crypto_padding_remove(tmp,output,tmplength,outputlength);

		free(tmp);
	}
	else {
		(*outputlength) = 0;
	}
}

static int mrtd_get_mrz_weight(int i)
{
	switch(i){
	case(0): return 7;
	case(1): return 3;
	case(2): return 1;
	}
}

int mrtd_bac_check_digit(uint8_t *input, int length)
{
	int i;
	int tmp;
	int out_value;
	int check_digit;
	check_digit = 0;
	for(i=0;i<length;i++){
		if (input[i] >= 'A' && input[i] <= 'Z')
			tmp = input[i] - 55;
		else if (input[i] == '<')
			tmp = 0;
		else
			tmp = input[i] - 0x30;
		check_digit += tmp * mrtd_get_mrz_weight(i % 3);
	}
	return (check_digit % 10);
}

void mrtd_bac_get_kmrz(uint8_t *pn, uint8_t *dob, uint8_t *eov, uint8_t *output)
{
	uint8_t tmp[20];
	int cd;
	int len;

	printf("pn[0]: %c\n",pn[0]);
	len = strlen(pn);
	printf("len %d\n",len);
	if (len < 9){
		memcpy(output,pn,len);
		memset(output+len,'<',9-len);
	}
	else {
		memcpy(output,pn,9);
	}
	
	cd = mrtd_bac_check_digit(output,9);
	output[9] = (uint8_t)(cd+0x30);

	memcpy(output+10,dob,6);
	cd = mrtd_bac_check_digit(dob,6);
	output[16] = (uint8_t)(cd+0x30);

	memcpy(output+17,eov,6);
	cd = mrtd_bac_check_digit(eov,6);
	output[23] = (uint8_t)(cd+0x30);
	output[24] = 0;
	
}

void mrtd_bac_get_kmrz_from_mrz(uint8_t *mrz, uint8_t *kmrz)
{
	uint8_t pn[9];
	uint8_t dob[6];
	uint8_t eov[6];

	memcpy(pn,mrz,9);
	memcpy(dob,mrz+13,6);
	memcpy(eov,mrz+21,6);
	
	mrtd_bac_get_kmrz(pn,dob,eov,kmrz);

}



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

/*
 *  The following function only works for little-endian systems
 *
 */
uint64_t mrtd_bac_get_ssc(uint8_t *remote_challenge, uint8_t *rnd_ifd)
{
	char ssc[8];
	uint64_t ssc_long;

	memcpy(ssc,remote_challenge+4,4);
	memcpy(ssc+4,rnd_ifd+4,4);

	*(((unsigned char*)(&ssc_long))+7) = ssc[0];
	*(((unsigned char*)(&ssc_long))+6) = ssc[1];
	*(((unsigned char*)(&ssc_long))+5) = ssc[2];
	*(((unsigned char*)(&ssc_long))+4) = ssc[3];
	*(((unsigned char*)(&ssc_long))+3) = ssc[4];
	*(((unsigned char*)(&ssc_long))+2) = ssc[5];
	*(((unsigned char*)(&ssc_long))+1) = ssc[6];
	*(((unsigned char*)(&ssc_long))+0) = ssc[7];

	return ssc_long;
}


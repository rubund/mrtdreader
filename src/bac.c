/*
 *   bac.c - Basic Access Control 
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
#include <string.h>
#include <stdint.h>
#include <nfc/nfc.h>
#include "bachelper.h"

static char rnd_ifd[8] = {0x78,0x17,0x23,0x86,0x0c,0x06,0xc2,0x26};
static char kifd[16] = {0x0b,0x79,0x52,0x40,0xcb,0x70,0x49,0xb0,0x1c,0x19,0xb3,0x3e,0x32,0x80,0x4f,0x0b};

int mrtd_bac_keyhandshake(nfc_device *pnd, uint8_t *kmrz, uint8_t *ksenc, uint8_t *ksmac, uint64_t *ssc_long)
{
	int i;
	int res;
	uint8_t txbuffer[300];
	int txlen;
	uint8_t rxbuffer[300];
	int rxlen;

	txlen = 5;
	memcpy(txbuffer, "\x00\x84\x00\x00\x08", txlen);
	rxlen = sizeof(rxbuffer);
	if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
		fprintf(stderr,"Unable to send");
		goto failed;
	}
	else{
		rxlen = res;
	}

	uint8_t remotechallenge[8];
	memcpy(remotechallenge,rxbuffer,8);

	txlen = 12;
	memcpy(txbuffer, "\x00\xa4\x04\x0c\x07\xa0\x00\x00\x02\x47\x10\x01", txlen);
	rxlen = sizeof(rxbuffer);
	if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
		fprintf(stderr,"Unable to send");
		goto failed;
	}
	else{
		rxlen = res;
	}

	uint8_t kenc[16];
	uint8_t kmac[16];

	mrtd_bac_kmrz_to_kenc_kmac(kmrz,kenc,kmac);

	uint8_t cmd_data[40];

	mrtd_bac_cmd_data(rnd_ifd,kifd,remotechallenge,kenc,kmac,cmd_data);

	txlen = 46;
	memcpy(txbuffer, "\x00\x82\x00\x00\x28", 5);
	memcpy(txbuffer+5,cmd_data,40);
	txbuffer[45] = 0x28;
	rxlen = sizeof(rxbuffer);
	if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
		fprintf(stderr,"Unable to send");
		goto failed;
	}
	else{
		rxlen = res;
	}

	uint8_t rnd_icc[8];
	uint8_t kicc[16];

	if(mrtd_bac_challenge_ok(rxbuffer,kenc,rnd_ifd,rnd_icc,kicc)){
		printf("======================\nChallenge successful!\n======================\n");
	}
	else {
		printf("======================\nChallenge failed...\n======================\n");
		goto challengefailed;
	}
	uint8_t xored[16];

	for(i=0;i<16;i++){
		xored[i] = kifd[i] ^ kicc[i];
	}


	mrtd_bac_kenc_kmac(xored,ksenc,ksmac);

	//printhex("ksenc",ksenc,16);
	//printhex("ksmac",ksmac,16);

	(*ssc_long) = mrtd_bac_get_ssc(remotechallenge,rnd_ifd);

	//printf("ssc: %lx\n",ssc_long);

	return 0;

	failed:
		return -1;
	challengefailed:
		return -2;
}


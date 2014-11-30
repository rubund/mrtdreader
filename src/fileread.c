/*
 *   fileread.c - Functions for reading secure files from MRTD
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
#include "crypto.h"
#include "bac.h"
#include "bachelper.h"


#define MAXREAD 100

static int endianness(){
	int i = 1;
	char *p = (char *)&i;
	if(p[0] == 1)
		return 0;
	else
		return 1;
}

int mrtd_fileread_read(nfc_device *pnd, uint8_t *file_index, uint8_t *output, int *outputlength, uint8_t *ksenc, uint8_t *ksmac, uint64_t *ssc_long)
{
	int res;
	uint8_t txbuffer[300];
	int txlen;
	uint8_t rxbuffer[300];
	int rxlen;
	int already_received;

	uint8_t unprotected[300];
	int unprotectedlength;
	unprotectedlength = 7;
	memcpy(unprotected,"\x00\xa4\x02\x0c\x02\x01\x1e",5);
	memcpy(unprotected+5,file_index,2);
	(*ssc_long)++;
	mrtd_bac_protected_apdu(unprotected,txbuffer,unprotectedlength,&txlen,ksenc,ksmac,*ssc_long);

	//printhex("Transmit",txbuffer,txlen);
	rxlen = sizeof(rxbuffer);
	if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
		fprintf(stderr,"Unable to send");
		goto failed;
	}
	else{
		rxlen = res;
	}
	//printhex("Received (encrypted)",rxbuffer,rxlen);
	(*ssc_long)++;
	mrtd_bac_decrypt_response(rxbuffer,unprotected,rxlen,&unprotectedlength,ksenc);
	//printhex("Received (decrypted)",unprotected,unprotectedlength);

	already_received=0;

	unprotectedlength = 5;
	memcpy(unprotected,"\x00\xb0\x00\x00\x04",unprotectedlength);
	(*ssc_long)++;
	mrtd_bac_protected_apdu(unprotected,txbuffer,unprotectedlength,&txlen,ksenc,ksmac,*ssc_long);
	//printhex("Transmit",txbuffer,txlen);
	rxlen = sizeof(rxbuffer);
	if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
		fprintf(stderr,"Unable to send");
		goto failed;
	}
	else{
		rxlen = res;
	}
	//printhex("Received (encrypted)",rxbuffer,rxlen);
	(*ssc_long)++;
	mrtd_bac_decrypt_response(rxbuffer,unprotected,rxlen,&unprotectedlength,ksenc);
	//printhex("Received (decrypted)",unprotected,unprotectedlength);
	memcpy(output+already_received,unprotected,unprotectedlength);
	already_received += unprotectedlength;

	uint16_t numberbytes;
	int field_length;
	if(unprotected[1] <= 0x7f){
		numberbytes = (uint16_t)unprotected[1];
		field_length = 1;
	}
	else if(unprotected[1] == 0x81){
		numberbytes = (uint16_t)unprotected[2];
		field_length = 2;
	}
	else if(unprotected[1] == 0x82){
		*(((uint8_t*)(&numberbytes))+1) = unprotected[2];
		*(((uint8_t*)(&numberbytes))+0) = unprotected[3];
		field_length = 3;
	}
	else {
		fprintf(stderr,"Not correct field length");
		goto failed;
	}
	//printf("numberbytes: %d\n",numberbytes);
	
	int left_to_read;
	int readnow;
	left_to_read = numberbytes - (3-field_length);

	while (left_to_read > 0){
		if(left_to_read > MAXREAD)
			readnow = MAXREAD;
		else
			readnow = left_to_read;
		unprotectedlength = 5;
		memcpy(unprotected,"\x00\xb0\x00\x00\x00",unprotectedlength);
			/* FIXME: This only works on little-endian systems */
		if(endianness()){
			unprotected[2] = *(((uint8_t*)&already_received)+0);
			unprotected[3] = *(((uint8_t*)&already_received)+1);
		}
		else {
			unprotected[2] = *(((uint8_t*)&already_received)+1);
			unprotected[3] = *(((uint8_t*)&already_received)+0);
		}
		unprotected[4] = readnow;
		(*ssc_long)++;
		mrtd_bac_protected_apdu(unprotected,txbuffer,unprotectedlength,&txlen,ksenc,ksmac,*ssc_long);
		//printhex("Transmit",txbuffer,txlen);
		rxlen = sizeof(rxbuffer);
		if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
			fprintf(stderr,"Unable to send");
			goto failed;
		}
		else{
			rxlen = res;
		}
		//printhex("Received (encrypted)",rxbuffer,rxlen);
		(*ssc_long)++;
		mrtd_bac_decrypt_response(rxbuffer,unprotected,rxlen,&unprotectedlength,ksenc);
		//printhex("Received (decrypted)",unprotected,unprotectedlength);
		memcpy(output+already_received,unprotected,unprotectedlength);
		already_received += unprotectedlength;
		left_to_read -= unprotectedlength;
	}
	(*outputlength) = already_received;

	return 0;

	failed:
		return -1;
}

void mrtd_fileread_write_image_to_file(uint8_t *file_content, int file_size, char *filename)
{
	FILE *out;
	out = fopen(filename,"w");
	int offset = 84;
	fwrite(file_content+offset,1,file_size-offset,out);

	fclose(out);
}



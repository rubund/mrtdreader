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

	printhex("Transmit",txbuffer,txlen);
	rxlen = sizeof(rxbuffer);
	if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
		fprintf(stderr,"Unable to send");
		goto failed;
	}
	else{
		rxlen = res;
	}
	printhex("Received (encrypted)",rxbuffer,rxlen);
	(*ssc_long)++;
	mrtd_bac_decrypt_response(rxbuffer,unprotected,rxlen,&unprotectedlength,ksenc);
	printhex("Received (decrypted)",unprotected,unprotectedlength);

	already_received=0;

	unprotectedlength = 5;
	memcpy(unprotected,"\x00\xb0\x00\x00\x04",unprotectedlength);
	(*ssc_long)++;
	mrtd_bac_protected_apdu(unprotected,txbuffer,unprotectedlength,&txlen,ksenc,ksmac,*ssc_long);
	printhex("Transmit",txbuffer,txlen);
	rxlen = sizeof(rxbuffer);
	if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
		fprintf(stderr,"Unable to send");
		goto failed;
	}
	else{
		rxlen = res;
	}
	printhex("Received (encrypted)",rxbuffer,rxlen);
	(*ssc_long)++;
	mrtd_bac_decrypt_response(rxbuffer,unprotected,rxlen,&unprotectedlength,ksenc);
	printhex("Received (decrypted)",unprotected,unprotectedlength);
	memcpy(output+already_received,unprotected,unprotectedlength);
	already_received += unprotectedlength;

	uint8_t numberbytes = unprotected[1] + 2;

	unprotectedlength = 5;
	memcpy(unprotected,"\x00\xb0\x00\x04\x00",unprotectedlength);
	unprotected[4] = (numberbytes-already_received);
	(*ssc_long)++;
	mrtd_bac_protected_apdu(unprotected,txbuffer,unprotectedlength,&txlen,ksenc,ksmac,*ssc_long);
	printhex("Transmit",txbuffer,txlen);
	rxlen = sizeof(rxbuffer);
	if((res = nfc_initiator_transceive_bytes(pnd,txbuffer,txlen,rxbuffer,rxlen,500)) < 0){
		fprintf(stderr,"Unable to send");
		goto failed;
	}
	else{
		rxlen = res;
	}
	printhex("Received (encrypted)",rxbuffer,rxlen);
	(*ssc_long)++;
	mrtd_bac_decrypt_response(rxbuffer,unprotected,rxlen,&unprotectedlength,ksenc);
	printhex("Received (decrypted)",unprotected,unprotectedlength);
	memcpy(output+already_received,unprotected,unprotectedlength);
	already_received += unprotectedlength;
	(*outputlength) = already_received;

	return 0;

	failed:
		return -1;
}

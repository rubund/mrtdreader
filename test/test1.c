#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../src/crypto.h"
#include "../src/bachelper.h"

void printhex(char *description, uint8_t *input, int length)
{
	int i;
	printf("%s: ",description);
	for(i=0;i<length;i++){
		printf("%02x",input[i]);
	}
	printf("\n");
}

int main()
{
	int i;
	char *mrp_number = "L898902C<";
	char *mrp_numbercd = "3";
	char *mrp_dob = "690806";
	char *mrp_dobcd = "1";
	char *mrp_expiry = "940623";
	char *mrp_expirycd = "6";

	char remotechallenge[8] = {0x46,0x08,0xf9,0x19,0x88,0x70,0x22,0x12};
	char rnd_ifd[8] = {0x78,0x17,0x23,0x86,0x0c,0x06,0xc2,0x26};
	char kifd[16] = {0x0b,0x79,0x52,0x40,0xcb,0x70,0x49,0xb0,0x1c,0x19,0xb3,0x3e,0x32,0x80,0x4f,0x0b};
	char rx_data[40] = {0x46,0xB9,0x34,0x2A,0x41,0x39,0x6C,0xD7,0x38,0x6B,0xF5,0x80,0x31,0x04,0xD7,0xCE,0xDC,0x12,0x2B,0x91,0x32,0x13,0x9B,0xAF,0x2E,0xED,0xC9,0x4E,0xE1,0x78,0x53,0x4F,0x2f,0x2D,0x23,0x5D,0x07,0x4D,0x74,0x49};

	char kmrz[25];
	char kenc[16];
	char kmac[16];
	char cmd_data[40];
	char rnd_icc[8];
	char kicc[16];
	char xored[16];
	char ksenc[16];
	char ksmac[16];
	uint64_t ssc_long;

	strncpy(kmrz,mrp_number,9);
	strncpy(kmrz+9,mrp_numbercd,1);
	strncpy(kmrz+10,mrp_dob,6);
	strncpy(kmrz+16,mrp_dobcd,1);
	strncpy(kmrz+17,mrp_expiry,6);
	strncpy(kmrz+23,mrp_expirycd,1);

	mrtd_bac_kmrz_to_kenc_kmac(kmrz,kenc,kmac);
	printhex("kenc",kenc,16);
	printhex("kmac",kmac,16);

	mrtd_bac_cmd_data(rnd_ifd,kifd,remotechallenge,kenc,kmac,cmd_data);
	printhex("cmd_data",cmd_data,40);

	if(mrtd_bac_challenge_ok(rx_data,kenc,rnd_ifd,rnd_icc,kicc)){
		printf("======================\nChallenge successful!\n======================\n");
	}
	else {
		printf("======================\nChallenge failed...\n======================\n");
	}
	printhex("rnd_ifd",rnd_ifd,8);
	printhex("kicc",kicc,16);

	for(i=0;i<16;i++){
		xored[i] = kifd[i] ^ kicc[i];
	}
	mrtd_bac_kenc_kmac(xored,ksenc,ksmac);
	printhex("ksenc",ksenc,16);
	printhex("ksmac",ksmac,16);

	ssc_long = mrtd_bac_get_ssc(remotechallenge,rnd_ifd);
	printf("ssc: %lx\n",ssc_long);

	return 0;
}


/*
 *   mrtd.h - Header file for libmrtd.so
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

#ifndef INC_MRTD_H
#define INC_MRTD_H


#include <stdint.h>

#define RET_CHALLENGE_FAILED -2

/* bac */
int mrtd_bac_keyhandshake(nfc_device *pnd, uint8_t *kmrz, uint8_t *ksenc, uint8_t *ksmac, uint64_t *ssc_long);

/* bachelper */
void mrtd_bac_kmrz_to_kenc_kmac(uint8_t *kmrz, uint8_t *kenc, uint8_t *kmac);

void mrtd_bac_kenc_kmac(uint8_t *input, uint8_t *kenc, uint8_t *kmac);

void mrtd_bac_eifd_mifd(uint8_t *rnd_ifd, uint8_t *kifd, uint8_t *remote_challenge, uint8_t *kenc, uint8_t *kmac, uint8_t *eifd, uint8_t *mifd);

void mrtd_bac_cmd_data(uint8_t *rnd_ifd, uint8_t *kifd, uint8_t *remote_challenge, uint8_t *kenc, uint8_t *kmac, uint8_t *cmd_data);

char mrtd_bac_challenge_ok(uint8_t *rx_data, uint8_t *kenc, uint8_t *rnd_ifd, uint8_t *rnd_icc, uint8_t *kicc);

uint64_t mrtd_bac_get_ssc(uint8_t *remote_challenge, uint8_t *rnd_ifd);

void mrtd_bac_protected_apdu(uint8_t *input, uint8_t *output, int length, int *outputlength, uint8_t *ksenc, uint8_t *ksmac, uint64_t ssc_long);

void mrtd_bac_decrypt_response(uint8_t *input, uint8_t *output, int length, int *outputlength, uint8_t *ksenc);

int mrtd_bac_check_digit(uint8_t *input, int length);

void mrtd_bac_get_kmrz(uint8_t *pn, uint8_t *dob, uint8_t *eov, uint8_t *output);

/* crypto */
void mrtd_crypto_sha1(uint8_t *input, int length, uint8_t *output);

void mrtd_crypto_encrypt_3des(uint8_t *input, uint8_t *output, int length, uint8_t *key);

void mrtd_crypto_decrypt_3des(uint8_t *input, uint8_t *output, int length, uint8_t *key);

void mrtd_crypto_encrypt_des(uint8_t *input, uint8_t *output, int length, uint8_t *key);

void mrtd_crypto_decrypt_des(uint8_t *input, uint8_t *output, int length, uint8_t *key);

void mrtd_crypto_fix_parity(uint8_t *input, uint8_t *output, int length, int *newlength);

void mrtd_crypto_mac_padding(uint8_t *input, uint8_t *output, int length, uint8_t *key);

void mrtd_crypto_mac(uint8_t *input, uint8_t *output, int length, uint8_t *key);

void mrtd_crypto_padding(uint8_t *input, uint8_t *output, int length, int *newlength);

void mrtd_crypto_padding_remove(uint8_t *input, uint8_t *output, int length, int *newlength);

/* fileread */
int mrtd_fileread_read(nfc_device *pnd, uint8_t *file_index, uint8_t *output, int *outputlength, uint8_t *ksenc, uint8_t *ksmac, uint64_t *ssc_long);

void mrtd_fileread_write_image_to_file(uint8_t *file_content, int file_size, char *filename);



#endif /* INC_MRTD_H */


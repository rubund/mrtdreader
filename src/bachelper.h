/*
 *   header for bachelper.c 
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

#ifndef INC_BAC_HELPER_H
#define INC_BAC_HELPER_H

#include <stdint.h>

void mrtd_bac_kmrz_to_kenc_kmac(const uint8_t *kmrz, uint8_t *kenc, uint8_t *kmac);

void mrtd_bac_kenc_kmac(const uint8_t *input, uint8_t *kenc, uint8_t *kmac);

void mrtd_bac_eifd_mifd(const uint8_t *rnd_ifd, const uint8_t *kifd, const uint8_t *remote_challenge, const uint8_t *kenc, const uint8_t *kmac, uint8_t *eifd, uint8_t *mifd);

void mrtd_bac_cmd_data(const uint8_t *rnd_ifd, const uint8_t *kifd, const uint8_t *remote_challenge, const uint8_t *kenc, const uint8_t *kmac, uint8_t *cmd_data);

char mrtd_bac_challenge_ok(const uint8_t *rx_data, const uint8_t *kenc, const uint8_t *rnd_ifd, uint8_t *rnd_icc, uint8_t *kicc);

uint64_t mrtd_bac_get_ssc(const uint8_t *remote_challenge, const uint8_t *rnd_ifd);

void mrtd_bac_protected_apdu(const uint8_t *input, uint8_t *output, const int length, int *outputlength, const uint8_t *ksenc, const uint8_t *ksmac, const uint64_t ssc_long);

void mrtd_bac_decrypt_response(const uint8_t *input, uint8_t *output, const int length, int *outputlength, const uint8_t *ksenc);

int mrtd_bac_check_digit(const uint8_t *input, const int length);

void mrtd_bac_get_kmrz(const uint8_t *pn, const uint8_t *dob, const uint8_t *eov, uint8_t *output);

void mrtd_bac_get_kmrz_from_mrz(const uint8_t *mrz, uint8_t *kmrz);

#endif /* INC_BAC_HELPER_H */

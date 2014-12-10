/*
 *   header for crypto_*.c - this header makes the higher-level code
 *     independent of which crypto-library that is used.
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

#ifndef INC_BAC_CRYPTO_H
#define INC_BAC_CRYPTO_H

#include <stdint.h>

void mrtd_crypto_sha1(const uint8_t *input, const int length, uint8_t *output);

void mrtd_crypto_encrypt_3des(const uint8_t *input, uint8_t *output, const int length, const uint8_t *key);

void mrtd_crypto_decrypt_3des(const uint8_t *input, uint8_t *output, const int length, const uint8_t *key);

void mrtd_crypto_encrypt_des(const uint8_t *input, uint8_t *output, const int length, const uint8_t *key);

void mrtd_crypto_decrypt_des(const uint8_t *input, uint8_t *output, const int length, const uint8_t *key);

void mrtd_crypto_fix_parity(const uint8_t *input, uint8_t *output, const int length, int *newlength);

void mrtd_crypto_mac_padding(const uint8_t *input, uint8_t *output, const int length, const uint8_t *key);

void mrtd_crypto_mac(const uint8_t *input, uint8_t *output, const int length, const uint8_t *key);

void mrtd_crypto_padding(const uint8_t *input, uint8_t *output, const int length, int *newlength);

void mrtd_crypto_padding_remove(const uint8_t *input, uint8_t *output, const int length, int *newlength);

#endif /* INC_BAC_CRYPTO_H */

/*
 *   header for bac.c
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


#ifndef INC_BAC_H
#define INC_BAC_H

#include <stdint.h>

#define RET_CHALLENGE_FAILED -2

int mrtd_bac_keyhandshake(nfc_device *pnd, uint8_t *kmrz, uint8_t *ksenc, uint8_t *ksmac, uint64_t *ssc_long);

void mrtd_bac_set_rndifd_kifd(uint8_t *rnd_ifd, uint8_t *kifd);

void mrtd_bac_randomize_rndifd_kifd();

#endif /* INC_BAC_H */


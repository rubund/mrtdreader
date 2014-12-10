/*
 *   header for fileread.c
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

#ifndef INC_FILEREAD_H
#define INC_FILEREAD_H

int mrtd_fileread_read(nfc_device *pnd, const uint8_t *file_index, uint8_t *output, int *outputlength, const uint8_t *ksenc, const uint8_t *ksmac, uint64_t *ssc_long);

void mrtd_fileread_write_image_to_file(const uint8_t *file_content, const int file_size, const char *filename);

void mrtd_fileread_decode_ef_com(const uint8_t *file_content, const int file_size, uint8_t *datagroups, int *numdatagroups);

void mrtd_fileread_get_datagroup_name(const uint8_t dg, char *name);

#endif /* INC_FILEREAD_H */

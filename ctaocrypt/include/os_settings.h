/* os_settings.h
 *
 * Copyright (C) 2006-2010 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* Place OS specific preprocessor flags or defines here, will be included into
   every file because type.h includes it */

#ifndef CTAO_CRYPT_OS_SETTINGS_H
#define CTAO_CRYPT_OS_SETTINGS_H

#ifdef __cplusplus
    extern "C" {
#endif

/* Uncomment next line if using ThreadX */
/* #define THREADX */

/* Uncomment next line if using Micrium ucOS */
/* #define MICRIUM */

/* Place any other flags or defines here */


#ifdef __cplusplus
    }   /* extern "C" */
#endif


#endif /* CTAO_CRYPT_OS_SETTINGS_H */


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

/* Place OS specific preprocessor flags, defines, includes here, will be
   included into every file because types.h includes it */

#ifndef CTAO_CRYPT_OS_SETTINGS_H
#define CTAO_CRYPT_OS_SETTINGS_H

#ifdef __cplusplus
    extern "C" {
#endif


/* Uncomment next line if using ThreadX */
/* #define THREADX */

/* Uncomment next line if using Micrium ucOS */
/* #define MICRIUM */

#ifdef MICRIUM

    #include "net_secure_cfg.h"
    #include "net_secure_os.h"

    #if (NET_SECURE_CFG_DEBUG_EN == DEF_ENABLED)
        #define DEBUG_CYASSL
    #else
        #undef  DEBUG_CYASSL
    #endif

    #if (NET_SECURE_CFG_FS_EN == DEF_DISABLED)
        #define NO_FILESYSTEM
    #else
        #undef  NO_FILESYSTEM
    #endif

    #if (NET_SECURE_CFG_OPENSSL_EXTRA_EN == DEF_ENABLED)
        #define OPENSSL_EXTRA
    #else
        #undef  OPENSSL_EXTRA
    #endif

    #define NO_WRITEV
    #define CYASSL_USER_IO

#endif /* MICRIUM */

/* Place any other flags or defines here */


#ifdef __cplusplus
    }   /* extern "C" */
#endif


#endif /* CTAO_CRYPT_OS_SETTINGS_H */


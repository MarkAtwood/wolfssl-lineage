/* cyassl_callbacks.h
 *
 * Copyright (C) 2008 Sawtooth Consulting Ltd.
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



#ifndef CYASSL_CALLBACKS_H
#define CYASSL_CALLBACKS_H


#ifdef __cplusplus
    extern "C" {
#endif


#ifdef CYASSL_CALLBACKS

enum { /* CALLBACK CONTSTANTS */
    MAX_PACKETNAME_SZ = 24,
    MAX_CIPHERNAME_SZ = 24,
    MAX_PACKETS_HANDSHAKE = 16,
};


typedef struct handShakeInfo {
    char   cipherName[MAX_CIPHERNAME_SZ + 1];    /* negotiated cipher */
    char   packetNames[MAX_PACKETS_HANDSHAKE][MAX_PACKETNAME_SZ + 1];
                                                 /* SSL packet names  */ 
    int    numberPackets;                        /* actual # of packets */
    int    negotiationError;                     /* cipher/parameter err */
} HandShakeInfo;

#endif /* CYASSL_CALLBACKS */



#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* CyaSSL_CALLBACKS_H */


/* cyassl_error.h
 *
 * Copyright (C) 2006 Sawtooth Consulting Ltd.
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



#ifndef CyaSSL_ERROR_H
#define CyaSSL_ERROR_H


#ifdef __cplusplus
    extern "C" {
#endif

enum CyaSSL_ErrorCodes {
    UNSUPPORTED_SUITE      = -201,            /* unsupported cipher suite */
    PREFIX_ERROR           = -202,            /* bad index to key rounds  */
    MEMORY_ERROR           = -203,            /* out of memory            */
    VERIFY_FINISHED_ERROR  = -204,            /* verify problem on finished */
    VERIFY_MAC_ERROR       = -205,            /* verify mac problem       */
    PARSE_ERROR            = -206,            /* parse error on header    */
    UNKNOWN_HANDSHAKE_TYPE = -207,            /* weird handshake type     */
    SOCKET_ERROR_E         = -208,            /* error state on socket    */
    SOCKET_NODATA          = -209,            /* expected data, not there */
    INCOMPLETE_DATA        = -210,            /* don't have enough data to 
                                                 complete task            */
    UNKOWN_RECORD_TYPE     = -211,            /* unknown type in record hdr */
    DECRYPT_ERROR          = -212,            /* error during decryption  */
    FATAL_ERROR            = -213,            /* revcd alert fatal error  */
    ENCRYPT_ERROR          = -214,            /* error during encryption  */
    FREAD_ERROR            = -215,            /* fread problem            */
    NO_PEER_KEY            = -216,            /* need peer's key          */
    NO_PRIVATE_KEY         = -217,            /* need the private key     */
    RSA_PRIVATE_ERROR      = -218,            /* error during rsa priv op */
    MATCH_SUITE_ERROR      = -219,            /* can't match cipher suite */
    BUILD_MSG_ERROR        = -220             /* build message failure    */
};


#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* CyaSSL_ERROR_H */


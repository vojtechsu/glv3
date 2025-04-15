/**
 * \file ecdsa.h
 *
 * \brief This file contains ECDSA definitions and functions.
 *
 * The Elliptic Curve Digital Signature Algorithm (ECDSA) is defined in
 * <em>Standards for Efficient Cryptography Group (SECG):
 * SEC1 Elliptic Curve Cryptography</em>.
 * The use of ECDSA for TLS is defined in <em>RFC-4492: Elliptic Curve
 * Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)</em>.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_MYECDSA_H
#define MBEDTLS_MYECDSA_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/ecp.h"
#include "glvecp.h"

#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "lattice.h"



/**
 * \brief           Maximum ECDSA signature size for a given curve bit size
 *
 * \param bits      Curve size in bits
 * \return          Maximum signature size in bytes
 *
 * \note            This macro returns a compile-time constant if its argument
 *                  is one. It may evaluate its argument multiple times.
 */
/*
 *     Ecdsa-Sig-Value ::= SEQUENCE {
 *         r       INTEGER,
 *         s       INTEGER
 *     }
 *
 * For each of r and s, the value (V) may include an extra initial "0" bit.
 */
#define MBEDTLS_ECDSA_MAX_SIG_LEN(bits)                               \
    (/*T,L of SEQUENCE*/ ((bits) >= 61 * 8 ? 3 : 2) +              \
     /*T,L of r,s*/ 2 * (((bits) >= 127 * 8 ? 3 : 2) +     \
                         /*V of r,s*/ ((bits) + 8) / 8))

/** The maximal size of an ECDSA signature in Bytes. */
#define MBEDTLS_ECDSA_MAX_LEN  MBEDTLS_ECDSA_MAX_SIG_LEN(MBEDTLS_ECP_MAX_BITS)


// API
int mbedtls_ecdsa_glv_verify_restartable(mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const mbedtls_ecp_point *Q,
                                     const mbedtls_mpi *r,
                                     const mbedtls_mpi *s, struct glvpackage *glvpackage);


// API
int mbedtls_ecdsa_glv3_verify_restartable(mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const mbedtls_ecp_point *Q,
                                     const mbedtls_mpi *r,
                                     const mbedtls_mpi *s, struct glvpackage *glvpackage);



// API
int mbedtls_ecdsa_shamir_verify_restartable(mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const mbedtls_ecp_point *Q,
                                     const mbedtls_mpi *r,
                                     const mbedtls_mpi *s);





#endif /* ecdsa.h */

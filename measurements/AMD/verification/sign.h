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

#ifndef MBEDTLS_SIGN_H
#define MBEDTLS_SIGN_H
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


// Sign API
int oddmbedtls_ecdsa_write_signature(mbedtls_ecdsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng);


int oddmbedtls_ecdsa_sign_restartable(mbedtls_ecp_group *grp,
                                   mbedtls_mpi *r, mbedtls_mpi *s,
                                   const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                   int (*f_rng_blind)(void *, unsigned char *, size_t),
                                   void *p_rng_blind);

int oddmbedtls_ecdsa_sign_det_restartable(mbedtls_ecp_group *grp,
                                       mbedtls_mpi *r, mbedtls_mpi *s,
                                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                       mbedtls_md_type_t md_alg,
                                       int (*f_rng_blind)(void *, unsigned char *, size_t),
                                       void *p_rng_blind);

#endif /* ecdsa.h */

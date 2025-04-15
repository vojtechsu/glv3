
#include "common.h"

#include "glvecdsa.h"
#include "glvecp.h"
#include "mbedtls/ecp.h"
#include "sign.h"
#include "mbedtls/asn1write.h"

#include <string.h>

#include "mbedtls/hmac_drbg.h"

#include "mbedtls/platform.h"

#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#define ECDSA_RS_ECP    NULL

#define ECDSA_BUDGET(ops)     /* no-op; for compatibility */

#define NONCEATTEMPTS 1000000


//Actual signing with odd Ry
int oddmbedtls_ecdsa_sign_restartable(mbedtls_ecp_group *grp,
                                   mbedtls_mpi *r, mbedtls_mpi *s,
                                   const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                   int (*f_rng_blind)(void *, unsigned char *, size_t),
                                   void *p_rng_blind)
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;
    mbedtls_mpi *pk = &k, *pr = r;


    /* Make sure d is in range 1..n-1 */
    if (mbedtls_mpi_cmp_int(d, 1) < 0 || mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&k); mbedtls_mpi_init(&e); mbedtls_mpi_init(&t);


    *p_sign_tries = 0;
    do {
        if ((*p_sign_tries)++ > NONCEATTEMPTS) {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        *p_key_tries = 0;

        do {
            if ((*p_key_tries)++ > NONCEATTEMPTS) {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }

            MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, pk, f_rng, p_rng));
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &R, pk, &grp->G,
                                                        f_rng_blind,
                                                        p_rng_blind,
                                                        ECDSA_RS_ECP));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pr, &R.X, &grp->N));
        } while ((mbedtls_mpi_cmp_int(pr, 0) == 0) || mbedtls_mpi_get_bit(&R.Y,0)==0);

        /*
         * Accounting for everything up to the end of the loop
         * (step 6, but checking now avoids saving e and t)
         */
        ECDSA_BUDGET(MBEDTLS_ECP_OPS_INV + 4);

        /*
         * Step 5: derive MPI from hashed message
         */
        MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

        /*
         * Generate a random value to blind inv_mod in next step,
         * avoiding a potential timing leak.
         */
        MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, &t, f_rng_blind,
                                                p_rng_blind));

        /*
         * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
         */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, pr, d));
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&e, &e, s));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&e, &e, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pk, pk, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pk, pk, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(s, pk, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, s, &e));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(s, s, &grp->N));
    } while (mbedtls_mpi_cmp_int(s, 0) == 0);


cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&k); mbedtls_mpi_free(&e); mbedtls_mpi_free(&t);

    return ret;
}



// Some signing wrapper
int oddmbedtls_ecdsa_sign_det_restartable(mbedtls_ecp_group *grp,
                                       mbedtls_mpi *r, mbedtls_mpi *s,
                                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                       mbedtls_md_type_t md_alg,
                                       int (*f_rng_blind)(void *, unsigned char *, size_t),
                                       void *p_rng_blind)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_hmac_drbg_context rng_ctx;
    mbedtls_hmac_drbg_context *p_rng = &rng_ctx;
    unsigned char data[2 * MBEDTLS_ECP_MAX_BYTES];
    size_t grp_len = (grp->nbits + 7) / 8;
    const mbedtls_md_info_t *md_info;
    mbedtls_mpi h;

    if ((md_info = mbedtls_md_info_from_type(md_alg)) == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&h);
    mbedtls_hmac_drbg_init(&rng_ctx);


    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, data, grp_len));
    MBEDTLS_MPI_CHK(derive_mpi(grp, &h, buf, blen));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&h, data + grp_len, grp_len));
    MBEDTLS_MPI_CHK(mbedtls_hmac_drbg_seed_buf(p_rng, md_info, data, 2 * grp_len));


    ret = oddmbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                         mbedtls_hmac_drbg_random, p_rng,
                                         f_rng_blind, p_rng_blind);

cleanup:
    mbedtls_hmac_drbg_free(&rng_ctx);
    mbedtls_mpi_free(&h);

    return ret;
}


// Outer API for signing
int oddmbedtls_ecdsa_write_signature(mbedtls_ecdsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r, s;
    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // printf("AAA\n");
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    MBEDTLS_MPI_CHK(oddmbedtls_ecdsa_sign_det_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                       hash, hlen, md_alg, f_rng,
                                                       p_rng));
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */
    // printf("==\n");
    // printf_mpi(&r);
    // printf_mpi(&s);
    // printf("==\n");
    MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, sig_size, slen));

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}




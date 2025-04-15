
#include "common.h"

#ifndef MBEDTLS_LATTICE_H
#define MBEDTLS_LATTICE_H

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include <mbedtls/bignum.h>

struct GramMatrix {

    mbedtls_mpi matrix[3][3];
    int p[3];
    int crop;
};



struct glvpackage{

    mbedtls_mpi lambda;
    mbedtls_mpi beta;
    mbedtls_mpi a1;
    mbedtls_mpi a2;
    mbedtls_mpi b1;
    mbedtls_mpi b2;
    mbedtls_mpi a12b12;
    mbedtls_mpi a22b22;
    mbedtls_mpi a1a2b1b2;
    mbedtls_ecp_point g1;
    mbedtls_ecp_point g2;
    size_t window;
};
typedef struct glvpackage glvpackage ;

void simple_rounded_div(mbedtls_mpi *q, mbedtls_mpi *a0, mbedtls_mpi *b0);

void scalar_decomposition(mbedtls_mpi *m0, mbedtls_mpi *m1, const mbedtls_mpi *m, glvpackage *glvpackage, const mbedtls_mpi *N);

void small_3(struct glvpackage *pkg, const mbedtls_mpi *k, const mbedtls_mpi *N, mbedtls_mpi result[3]);

void small_3_semaev(struct glvpackage *pkg, const mbedtls_mpi *k, const mbedtls_mpi *N, mbedtls_mpi result[3]);

void printf_mpi(mbedtls_mpi *X);

void init_glvpackage(glvpackage *pckg, mbedtls_ecp_group_id gid);

mbedtls_mpi_sint fast_rounded_div(mbedtls_mpi *a, mbedtls_mpi *b, size_t size_a, size_t size_b);

#endif /* ecp.h */

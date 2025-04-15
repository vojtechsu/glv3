#ifndef MBEDTLS_JSF_H
#define MBEDTLS_JSF_H
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "lattice.h"


int jsf(mbedtls_mpi *k0orig, mbedtls_mpi *k1orig, int *us, int *vs);

int jsf3(mbedtls_mpi xs[3], int **us);

#endif 



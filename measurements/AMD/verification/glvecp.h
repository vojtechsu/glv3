#ifndef MBEDTLS_MYECP_H
#define MBEDTLS_MYECP_H
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "lattice.h"



void printf_point(mbedtls_ecp_point *R);

void muladd_glv(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *Q, glvpackage *pckg);


void muladd_glv3(mbedtls_ecp_group *grp, mbedtls_ecp_point *res,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *G,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *P, glvpackage *pckg, const mbedtls_mpi *r);


void muladd_shamir(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *Q);

void doubleandadd(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P);

int doubleandadd_ver(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P, double *time);

int mul_glv_ver(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *ok, const mbedtls_ecp_point *oP, glvpackage *glvpackage, double *time);


int mul_glv3_ver(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *P, glvpackage *glvpackage, double *time);

void my_set_point(mbedtls_ecp_point *P, const char *X,const char *Y,const char *Z);


void ecp_add(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                          mbedtls_ecp_point *P,  mbedtls_ecp_point *Q,
                         mbedtls_mpi tmp[9]);

void muladd_glv_timing(
    mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
    const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
    glvpackage *glvpackage, double *time);

void muladd_glv3_timing(
    mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
    const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
    const mbedtls_mpi *r, glvpackage *glvpackage, double *time);


void muladd_shamir_timing(
    mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
    const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
    double *time);




#endif 




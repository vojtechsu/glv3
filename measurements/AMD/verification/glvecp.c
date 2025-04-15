#include "common.h"
#include "glvecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "lattice.h"
#include "jsf.h"



#define MPI_ECP_ADD(X, A, B)                                                  \
    mbedtls_mpi_add_mod(grp, X, A, B)

#define MPI_ECP_SUB(X, A, B)                                                 \
    mbedtls_mpi_sub_mod(grp, X, A, B)

#define MPI_ECP_MUL(X, A, B)                                                  \
    mbedtls_mpi_mul_mod(grp, X, A, B)

#define MPI_ECP_SQR(X, A)                                                     \
    mbedtls_mpi_mul_mod(grp, X, A, A)

#define MPI_ECP_MUL_INT(X, A, c)                                              \
    mbedtls_mpi_mul_int_mod(grp, X, A, c)

#define MPI_ECP_INV(dst, src)                                                 \
    mbedtls_mpi_inv_mod((dst), (src), &grp->P)

#define MPI_ECP_MOV(X, A)                                                     \
    mbedtls_mpi_copy(X, A)

#define MPI_ECP_SHIFT_L(X, count)                                             \
    mbedtls_mpi_shift_l_mod(grp, X, count)

#define MPI_ECP_LSET(X, c)                                                    \
    mbedtls_mpi_lset(X, c)

#define MPI_ECP_CMP_INT(X, c)                                                 \
    mbedtls_mpi_cmp_int(X, c)

#define MPI_ECP_CMP(X, Y)                                                     \
    mbedtls_mpi_cmp_mpi(X, Y)



static void ecp_sub_mixed_0(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q,
                         mbedtls_mpi tmp[4])
{


    /* NOTE: Aliasing between input and output is allowed, so one has to make
     *       sure that at the point X,Y,Z are written, {P,Q}->{X,Y,Z} are no
     *       longer read from. */
    mbedtls_mpi * const X = &R->X;
    mbedtls_mpi * const Y = &R->Y;
    mbedtls_mpi * const Z = &R->Z;


    /*
     * Trivial cases: P == 0 or Q == 0 (case 1)
     */
    if (MPI_ECP_CMP_INT(&P->Z, 0) == 0) {
        mbedtls_ecp_copy(R, Q);
        return;
    }

    if (MPI_ECP_CMP_INT(&Q->Z, 0) == 0) {
        mbedtls_ecp_copy(R, P);
        return;
    }

    /*
     * Make sure Q coordinates are normalized
     */
    if (MPI_ECP_CMP_INT(&Q->Z, 1) != 0) {
        return;
    }

    MPI_ECP_SQR(&tmp[0], &P->Z);
    MPI_ECP_MUL(&tmp[1], &tmp[0], &P->Z);
    MPI_ECP_MUL(&tmp[0], &tmp[0], &Q->X);
    MPI_ECP_MUL(&tmp[1], &tmp[1], &Q->Y); 
    MPI_ECP_SUB(&tmp[0], &tmp[0], &P->X);
    MPI_ECP_ADD(&tmp[1], &tmp[1], &P->Y);

    /* Special cases (2) and (3) */
    if (MPI_ECP_CMP_INT(&tmp[0], 0) == 0) {
        if (MPI_ECP_CMP_INT(&tmp[1], 0) == 0) {
            ecp_double_jac(grp, R, P, tmp);
            return;
        } else {
            mbedtls_ecp_set_zero(R);
            return;
        }
    }

    /* {P,Q}->Z no longer used, so OK to write to Z even if there's aliasing. */
    MPI_ECP_MUL(Z,        &P->Z,    &tmp[0]);
    MPI_ECP_SQR(&tmp[2],  &tmp[0]);
    MPI_ECP_MUL(&tmp[3],  &tmp[2],  &tmp[0]);
    MPI_ECP_MUL(&tmp[2],  &tmp[2],  &P->X);

    MPI_ECP_MOV(&tmp[0], &tmp[2]);
    MPI_ECP_SHIFT_L(&tmp[0], 1);

    /* {P,Q}->X no longer used, so OK to write to X even if there's aliasing. */
    MPI_ECP_SQR(X,        &tmp[1]); 
    MPI_ECP_SUB(X,        X,        &tmp[0]);
    MPI_ECP_SUB(X,        X,        &tmp[3]);
    MPI_ECP_SUB(&tmp[2],  &tmp[2],  X);
    MPI_ECP_MUL(&tmp[2],  &tmp[2],  &tmp[1]); 
    MPI_ECP_MUL(&tmp[3],  &tmp[3],  &P->Y);
    /* {P,Q}->Y no longer used, so OK to write to Y even if there's aliasing. */
    MPI_ECP_ADD(Y,     &tmp[2],     &tmp[3]);
}



static void ecp_sub_mixed(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q,
                         mbedtls_mpi tmp[4])
{
    ecp_sub_mixed_0(grp, R, P, Q, tmp);
    ecp_safe_invert_jac(grp,R,1);
}


void printf_point(mbedtls_ecp_point *R){
    printf("X=");
    printf_mpi(&(R->X));
    printf("Y=");
    printf_mpi(&(R->Y));
    printf("Z=");
    printf_mpi(&(R->Z));
}





//add-2007-bl
void ecp_add(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                          mbedtls_ecp_point *P,  mbedtls_ecp_point *Q,
                         mbedtls_mpi tmp[9])
{

    /* NOTE: Aliasing between input and output is allowed, so one has to make
     *       sure that at the point X,Y,Z are written, {P,Q}->{X,Y,Z} are no
     *       longer read from. */
    mbedtls_mpi *  X = &R->X;
    mbedtls_mpi *  Y = &R->Y;
    mbedtls_mpi *  Z = &R->Z;


    /*
     * Trivial cases: P == 0 or Q == 0 (case 1)
     */
    if (MPI_ECP_CMP_INT(&P->Z, 0) == 0) {
        mbedtls_ecp_copy(R, Q);
        return;
    }

    if (MPI_ECP_CMP_INT(&Q->Z, 0) == 0) {
        mbedtls_ecp_copy(R, P);
        return;
    }

    MPI_ECP_SQR(&tmp[0], &P->Z); // Z1Z1 = Z1^2
    //[Z1Z1]

    MPI_ECP_SQR(&tmp[1], &Q->Z); // Z2Z2 = Z2^2
    //[Z1Z1,Z2Z2]
    MPI_ECP_MUL(&tmp[2], &tmp[1], &P->X); // U1 = X1*Z2Z2
    //[Z1Z1,Z2Z2,U1]
    MPI_ECP_MUL(&tmp[3], &tmp[0], &Q->X); // U2 = X2*Z1Z1
    //[Z1Z1,Z2Z2,U1,U2]
    MPI_ECP_MUL(&tmp[4], &tmp[1], &Q->Z); // t0 = Z2*Z2Z2
    //[Z1Z1,Z2Z2,U1,U2,t0]
    MPI_ECP_MUL(&tmp[4], &tmp[4], &P->Y); // S1 = Y1*t0
    //[Z1Z1,Z2Z2,U1,U2,S1]
    MPI_ECP_MUL(&tmp[5], &tmp[0], &P->Z); // t1 = Z1*Z1Z1
    //[Z1Z1,Z2Z2,U1,U2,S1,t1]
    MPI_ECP_MUL(&tmp[5], &tmp[5], &Q->Y); // S2 = Y2*t1
    //[Z1Z1,Z2Z2,U1,U2,S1,S2]
    MPI_ECP_SUB(&tmp[3], &tmp[3], &tmp[2]); // H = U2-U1
    //[Z1Z1,Z2Z2,U1,H,S1,S2]


    MPI_ECP_SQR(&tmp[6], &tmp[3]); // t2 = 2*H, I = t2^2 --> t2 = H^2, I=4*t2
    //[Z1Z1,Z2Z2,U1,H,S1,S2,t2]
    MPI_ECP_SHIFT_L(&tmp[6], 2); // t2 = 2*H, I = t2^2 --> t2 = H^2, I=4*t2
    //[Z1Z1,Z2Z2,U1,H,S1,S2,I]

    MPI_ECP_MUL(&tmp[7], &tmp[3], &tmp[6]); // J = H*I
    //[Z1Z1,Z2Z2,U1,H,S1,S2,I,J]
    MPI_ECP_SUB(&tmp[5], &tmp[5], &tmp[4]); //t3 = S2-S1
    //[Z1Z1,Z2Z2,U1,H,S1,t3,I,J]


        /* Special cases */
    if (MPI_ECP_CMP_INT(&tmp[3], 0) == 0) {
        if (MPI_ECP_CMP_INT(&tmp[5], 0) == 0) {
            ecp_double_jac(grp, R, P, tmp);
            return;
        } else {
            mbedtls_ecp_set_zero(R);
            return;
        }
    }

    MPI_ECP_SHIFT_L(&tmp[5], 1); //r = 2*t3
    //[Z1Z1,Z2Z2,U1,H,S1,r,I,J]
    MPI_ECP_MUL(&tmp[2], &tmp[2], &tmp[6]); // V = U1*I
    //[Z1Z1,Z2Z2,V,H,S1,r,I,J]
    MPI_ECP_SQR(&tmp[6], &tmp[5]); // t4 = r^2
    //[Z1Z1,Z2Z2,V,H,S1,r,t4,J]

    MPI_ECP_MOV(&tmp[8],&tmp[2]); // t5 = 2*V
    MPI_ECP_SHIFT_L(&tmp[8], 1);
    //[Z1Z1,Z2Z2,V,H,S1,r,t4,J,t5]

    MPI_ECP_SUB(&tmp[6], &tmp[6], &tmp[7]); // t6 = t4-J
    //[Z1Z1,Z2Z2,V,H,S1,r,t6,J,t5]
    MPI_ECP_SUB(X, &tmp[6], &tmp[8]); // X3 = t6-t5
    //[Z1Z1,Z2Z2,V,H,S1,r,t6,J,t5]
    MPI_ECP_SUB(&tmp[2], &tmp[2], X); // t7 = V-X3
    //[Z1Z1,Z2Z2,t7,H,S1,r,t6,J,t5]
    MPI_ECP_MUL(&tmp[4], &tmp[4], &tmp[7]); // t8 = S1*J
    //[Z1Z1,Z2Z2,t7,H,t8,r,t6,J,t5]
    MPI_ECP_SHIFT_L(&tmp[4], 1); // t9 = 2*t8
    //[Z1Z1,Z2Z2,t7,H,t9,r,t6,J,t5]
    MPI_ECP_MUL(&tmp[2], &tmp[5], &tmp[2]); // t10 = r*t7
    //[Z1Z1,Z2Z2,t10,H,t9,r,t6,J,t5]
    MPI_ECP_SUB(Y, &tmp[2], &tmp[4]); // Y3 = t10-t9
    //[Z1Z1,Z2Z2,t10,H,t9,r,t6,J,t5]
    MPI_ECP_ADD(&tmp[2], &P->Z, &Q->Z); // t11 = Z1+Z2
    //[Z1Z1,Z2Z2,t11,H,t9,r,t6,J,t5]
    MPI_ECP_SQR(&tmp[2],&tmp[2]); // t12 = t11^2
    //[Z1Z1,Z2Z2,t12,H,t9,r,t6,J,t5]
    MPI_ECP_SUB(&tmp[2],&tmp[2],&tmp[0]); // t13 = t12-Z1Z1
    //[Z1Z1,Z2Z2,t13,H,t9,r,t6,J,t5]
    MPI_ECP_SUB(&tmp[2],&tmp[2],&tmp[1]); // t14 = t13-Z2Z2
    //[Z1Z1,Z2Z2,t14,H,t9,r,t6,J,t5]
    MPI_ECP_MUL(Z,&tmp[2],&tmp[3]); // Z3 = t14*H
    //[Z1Z1,Z2Z2,t14,H,t9,r,t6,J,t5]
}



static void ecp_sub(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         mbedtls_ecp_point *P, mbedtls_ecp_point *Q,
                         mbedtls_mpi tmp[9])
{
    mbedtls_ecp_point mQ;
    mbedtls_ecp_point_init(&mQ);
    mbedtls_ecp_copy(&mQ,Q);
    ecp_safe_invert_jac(grp,&mQ,1);
    ecp_add(grp,R,P,&mQ,tmp);
}



void apply_beta(mbedtls_ecp_group *grp, mbedtls_ecp_point *P, mbedtls_mpi *beta){

    mbedtls_mpi_mul_mod(grp, &P->X, &P->X, beta);

}

void muladd_glv(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *Q, glvpackage *pckg)
{
    // Decompose
    mbedtls_mpi m0, m1, k0, k1;
    mbedtls_mpi_init(&m0);
    mbedtls_mpi_init(&m1);
    mbedtls_mpi_init(&k0);
    mbedtls_mpi_init(&k1);
    scalar_decomposition(&m0,&m1,m,pckg,&grp->N);
    scalar_decomposition(&k0,&k1,k,pckg,&grp->N);
    // Prepare points
    mbedtls_ecp_point lamP,lamQ,subP, subQ, sumP, sumQ;
    mbedtls_ecp_point_init(&lamP);
    mbedtls_ecp_point_init(&lamQ);
    mbedtls_ecp_point_init(&subP);
    mbedtls_ecp_point_init(&subQ);
    mbedtls_ecp_point_init(&sumP);
    mbedtls_ecp_point_init(&sumQ);
    mbedtls_ecp_copy(&lamP,P);
    apply_beta(grp,&lamP,&pckg->beta);
    mbedtls_ecp_copy(&sumP,&lamP);
    apply_beta(grp,&sumP,&pckg->beta);
    ecp_safe_invert_jac(grp,&sumP,1);
    mbedtls_ecp_copy(&lamQ,Q);
    apply_beta(grp,&lamQ,&pckg->beta);
    mbedtls_ecp_copy(&sumQ,&lamQ);
    apply_beta(grp,&sumQ,&pckg->beta);
    ecp_safe_invert_jac(grp,&sumQ,1);
    mbedtls_mpi tmp[9];
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    ecp_sub_mixed(grp,&subP,P,&lamP,tmp);
    ecp_sub_mixed(grp,&subQ,Q,&lamQ,tmp);
    mbedtls_ecp_point *to_norm[2] = {&subP,&subQ};
    ecp_normalize_jac_many(grp,to_norm,2);
    mbedtls_ecp_point *table0[3] = {&subP,(mbedtls_ecp_point *) P,&sumP}; 
    mbedtls_ecp_point *table1[3] = {&subQ,(mbedtls_ecp_point *) Q,&sumQ};

    // Transform scalars to jsf
    int s0 = m0.s;
    int s1 = m1.s;
    int s2 = k0.s;
    int s3 = k1.s;
    m0.s = 1;
    m1.s = 1;
    k0.s = 1;
    k1.s = 1;
    int m0bits = mbedtls_mpi_bitlen(&m0);
    int m1bits = mbedtls_mpi_bitlen(&m1);
    int k0bits = mbedtls_mpi_bitlen(&k0);
    int k1bits = mbedtls_mpi_bitlen(&k1);
    int bm = (m0bits > m1bits ? m0bits : m1bits);
    int u0[bm+2], u1[bm+2];  
    int lenu = jsf(&m0,&m1,u0,u1);
    bm = (k0bits > k1bits ? k0bits : k1bits);
    int v0[bm+2], v1[bm+2];
    int lenv = jsf(&k0,&k1,v0,v1);
    int loop = (lenu > lenv ? lenu : lenv);    

    mbedtls_ecp_set_zero(R);
    int i0,i1,j0,j1;
    for(int i=loop-1;i>=0;i--){
        if(!mbedtls_ecp_is_zero(R))ecp_double_jac(grp, R, R, tmp);

        if(i<lenu){i0 = s0*u0[i];i1 = s1*u1[i];}
        else {i0=0;i1=0;}

        if(i<lenv){j0 = s2*v0[i];j1 = s3*v1[i];}
        else {j0=0;j1=0;}
 
        if(i0==1) ecp_add_mixed(grp,R,R,table0[i1+1],tmp);
        else if(i0==-1) ecp_sub_mixed(grp,R,R,table0[-i1+1],tmp);
        else if (i1==1) ecp_add_mixed(grp,R,R,&lamP,tmp);
        else if (i1==-1) ecp_sub_mixed(grp,R,R,&lamP,tmp);

        if(j0==1) ecp_add_mixed(grp,R,R,table1[j1+1],tmp);
        else if(j0==-1) ecp_sub_mixed(grp,R,R,table1[-j1+1],tmp);
        else if (j1==1) ecp_add_mixed(grp,R,R,&lamQ,tmp);
        else if (j1==-1) ecp_sub_mixed(grp,R,R,&lamQ,tmp);
    }
    ecp_normalize_jac(grp,R);
}


void muladd_glv3(mbedtls_ecp_group *grp, mbedtls_ecp_point *res,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *G,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *P, glvpackage *pckg, const mbedtls_mpi *r)
{
    // Recover R
    // m*oG+k*oP=recR
    mbedtls_ecp_point recR;
    mbedtls_ecp_point_init(&recR);
    mbedtls_mpi_copy(&recR.X,r);
    mbedtls_ecp_sw_derive_y(grp,&recR.X,&recR.Y,1);
    mbedtls_mpi_lset(&recR.Z,1);

    // Decompose 0 = l0+l1*lam+l2*k
    mbedtls_mpi ls[3];
    mpi_init_many(ls, sizeof(ls) / sizeof(mbedtls_mpi));
    // printf_mpi(k);
    small_3(pckg,k,&grp->N,ls);
    // printf("%lu,%lu,%lu\n",mbedtls_mpi_size(&ls[0]),mbedtls_mpi_size(&ls[1]),mbedtls_mpi_size(&ls[2]));
    // printf_mpi(&ls[0]);
    // printf_mpi(&ls[1]);
    // printf_mpi(&ls[2]);

    // The verification eq is now l2*m*oG-l0*oP-l1*lam*oP-l2*recR = 0
    //Decompose l2*m = m0+m1*2**w+m2*2**(2w)
    mbedtls_mpi l2m;
    mbedtls_mpi_init(&l2m);
    mbedtls_mpi_mul_mpi(&l2m,m,&ls[2]);
    mbedtls_mpi_mod_mpi(&l2m,&l2m,&grp->N);
    mbedtls_mpi tmpval,shift;
    mbedtls_mpi ms[3];
    mpi_init_many(ms, sizeof(ms) / sizeof(mbedtls_mpi));
    mbedtls_mpi_init(&tmpval);
    mbedtls_mpi_init(&shift);
    mbedtls_mpi_lset(&shift,1);
    mbedtls_mpi_shift_l(&shift,pckg->window);
    mbedtls_mpi_div_mpi(&tmpval,&ms[0],&l2m,&shift);
    mbedtls_mpi_div_mpi(&ms[2],&ms[1],&tmpval,&shift);

    // Prepare the G points
    //  m0*G0+m1*G1+m2*G2-l0*oP-l1*lam*oP-l2*recR = 0
    mbedtls_ecp_point *G0 = (mbedtls_ecp_point *) G, *G1, *G2;
    G1 = &pckg->g1;
    G2 = &pckg->g2;

    // Change the signs
    // m0*G0+m1*G1+m2*G2+l0*oP+l1*lam*oP+l2*recR = 0
    ls[0].s = (-1)*ls[0].s;
    ls[1].s = (-1)*ls[1].s;
    ls[2].s = (-1)*ls[2].s; 
    // Prepare scalars for JSF3 transform
    // firstly collect the signs
    int s3= ls[0].s;
    int s4= ls[1].s;
    int s5= ls[2].s;
    mbedtls_mpi ams[3];
    mpi_init_many(ams, sizeof(ams) / sizeof(mbedtls_mpi));
    mbedtls_mpi als[3];
    mpi_init_many(als, sizeof(als) / sizeof(mbedtls_mpi));
    int ams_bits[3], als_bits[3];
    for(int i=0;i<3;i++){
    mbedtls_mpi_copy(&als[i],&ls[i]);
    als[i].s = 1;
    mbedtls_mpi_copy(&ams[i],&ms[i]);
    ams[i].s = 1;
    als_bits[i] = mbedtls_mpi_bitlen(&als[i]);
    ams_bits[i] = mbedtls_mpi_bitlen(&ams[i]);
    }
    
    int bm = (ams_bits[1] > ams_bits[2] ? ams_bits[1] : ams_bits[2]);
    bm = (ams_bits[0] > bm ? ams_bits[0] : bm); 
    int u0[bm+3], u1[bm+3], u2[bm+3];
    int *us[3] = {u0,u1,u2};
    int lenu = jsf3(ams,us);
    bm = (als_bits[1] > als_bits[2] ? als_bits[1] : als_bits[2]);
    bm = (als_bits[0] > bm ? als_bits[0] : bm);     
    int v0[bm+3], v1[bm+3], v2[bm+3];
    int *vs[3] = {v0,v1,v2};
    int lenv = jsf3(als,vs);


    //======== PREPARE G table
    mbedtls_ecp_point G1p2,G1m2,tmppoint;
    mbedtls_ecp_point_init(&G1p2);
    mbedtls_ecp_point_init(&G1m2);
    mbedtls_ecp_point_init(&tmppoint);
    mbedtls_mpi tmp[9];
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    ecp_add_mixed(grp,&G1p2,G1,G2,tmp);
    ecp_sub_mixed(grp,&G1m2,G1,G2,tmp);
    mbedtls_ecp_point *table0G[3] = {&G1m2,&pckg->g1,&G1p2}; //01-1,010,011,
    mbedtls_ecp_point tableG[3][3]; // contains all 1xy for x,y\in{0,1,-1}
    for(int i=0;i<3;i++) for(int j=0;j<3;j++) mbedtls_ecp_point_init(&tableG[i][j]);
    mbedtls_ecp_copy(&tableG[1][1],G0);//100
    ecp_add_mixed(grp,&tableG[1][2],G0,G2,tmp); //101
    ecp_add_mixed(grp,&tableG[2][1],G0,G1,tmp); //110
    ecp_add(grp,&tableG[2][2],G0,&G1p2,tmp); //111
    ecp_add(grp,&tableG[2][0],G0,&G1m2,tmp); //11-1
    ecp_sub_mixed(grp,&tableG[1][0],G0,G2,tmp); //10-1
    ecp_sub_mixed(grp,&tableG[0][1],G0,G1,tmp); //1-10
    ecp_sub(grp,&tableG[0][0],G0,&G1p2,tmp); //1-1-1
    ecp_sub(grp,&tableG[0][2],G0,&G1m2,tmp); //1-11


    // ============= PREPARE P table
    mbedtls_ecp_point lamP, sumP, subP;
    mbedtls_ecp_point_init(&lamP);
    mbedtls_ecp_point_init(&sumP);
    mbedtls_ecp_point_init(&subP);
    mbedtls_ecp_copy(&lamP,P);
    apply_beta(grp,&lamP,&pckg->beta);
    mbedtls_ecp_copy(&sumP,&lamP);
    apply_beta(grp,&sumP,&pckg->beta);
    ecp_safe_invert_jac(grp,&sumP,1);
    ecp_sub_mixed(grp,&subP,P,&lamP,tmp);
    mbedtls_ecp_point *table0[3] = {&subP,(mbedtls_ecp_point *) P,&sumP};//1-10,100,110
    mbedtls_ecp_point table[3][3];
    for(int i=0;i<3;i++) for(int j=0;j<3;j++) mbedtls_ecp_point_init(&table[i][j]);
    mbedtls_ecp_copy(&table[1][1],&recR); //001
    ecp_add_mixed(grp,&table[1][2],&recR,&lamP,tmp); //011 
    ecp_add_mixed(grp,&table[2][1],&recR,P,tmp); //101
    ecp_add_mixed(grp,&table[2][2],&recR,&sumP,tmp); //111
    ecp_add(grp,&table[2][0],&recR,&subP,tmp); //1-11
    ecp_sub_mixed(grp,&table[1][0],&recR,&lamP,tmp); //0-11
    ecp_sub_mixed(grp,&table[0][1],&recR,P,tmp); //-101
    ecp_sub_mixed(grp,&table[0][0],&recR,&sumP,tmp); //-1-11
    ecp_sub(grp,&table[0][2],&recR,&subP,tmp); //-111

    mbedtls_ecp_point *to_norm[20] = {&G1m2,&G1p2, &tableG[1][2], &tableG[2][1], &tableG[2][2], &tableG[2][0], &tableG[1][0], &tableG[0][1],&tableG[0][0],&tableG[0][2],&subP,&sumP,&table[1][2],&table[2][1],&table[2][2],&table[2][0],&table[1][0],&table[0][1],&table[0][0],&table[0][2]};
    ecp_normalize_jac_many(grp,to_norm, 20);

    int loop = (lenv > lenu ? lenv : lenu);
    mbedtls_ecp_set_zero(res);
    int i0,i1,i2,j0,j1,j2;
    for(int i=loop-1;i>=0;i--){

        if(!mbedtls_ecp_is_zero(res))ecp_double_jac(grp, res, res, tmp);


        if(i<lenu){i0 = u0[i];i1 = u1[i];i2 = u2[i];}
        else {i0=0;i1=0;i2=0;}

        if(i<lenv){j0 = s3*v0[i];j1 = s4*v1[i];j2=s5*v2[i];}
        else {j0=0;j1=0;j2=0;}

        if(i0==0){
            if(i1==1) ecp_add_mixed(grp,res,res,table0G[i2+1],tmp);
            if((i1==0) & (i2==1)) ecp_add_mixed(grp,res,res,G2,tmp);
            if((i1==0) & (i2==-1)) ecp_sub_mixed(grp,res,res,G2,tmp);
            if(i1==-1) ecp_sub_mixed(grp,res,res,table0G[-i2+1],tmp);
        }
        if(i0==1) ecp_add_mixed(grp,res,res,&tableG[i1+1][i2+1],tmp);
        if(i0==-1) ecp_sub_mixed(grp,res,res,&tableG[-i1+1][-i2+1],tmp);


        if(j2==0){
            if(j0==1) ecp_add_mixed(grp,res,res,table0[j1+1],tmp);
            if((j0==0) & (j1==1)) ecp_add_mixed(grp,res,res,&lamP,tmp);
            if((j0==0) & (j1==-1)) ecp_sub_mixed(grp,res,res,&lamP,tmp);
            if(j0==-1) ecp_sub_mixed(grp,res,res,table0[-j1+1],tmp);
        }
        if(j2==1) ecp_add_mixed(grp,res,res,&table[j0+1][j1+1],tmp);
        if(j2==-1) ecp_sub_mixed(grp,res,res,&table[-j0+1][-j1+1],tmp);
    
    }
}




void muladd_shamir(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *Q)
{
    // assumes positive m and k
    mbedtls_ecp_point sum;
    mbedtls_ecp_point_init(&sum);
    mbedtls_mpi tmp[9];
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    ecp_add_mixed(grp,&sum,P,Q,tmp);
    ecp_normalize_jac(grp,&sum);

    int mbits = mbedtls_mpi_bitlen(m);
    int kbits = mbedtls_mpi_bitlen(k);
    int loop = (mbits > kbits ? mbits : kbits);

    mbedtls_ecp_set_zero(R);
    int mi,ki;
    for(int i=loop-1;i>=0;i--){

        if(!mbedtls_ecp_is_zero(R))ecp_double_jac(grp, R, R, tmp);
        mi = mbedtls_mpi_get_bit(m,i);
        ki = mbedtls_mpi_get_bit(k,i);
        if(mi==1 && ki==1) ecp_add_mixed(grp,R,R,&sum,tmp);
        if(mi==1 && ki!=1) ecp_add_mixed(grp,R,R,P,tmp);
        if(mi!=1 && ki==1) ecp_add_mixed(grp,R,R,Q,tmp);

    }
    ecp_normalize_jac(grp,R);
}


void doubleandadd(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P)
{
    mbedtls_ecp_set_zero(R);
    int bits = grp->nbits;
    mbedtls_mpi tmp[4];
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    for(int i=bits-1;i>=0;i--){
        ecp_double_jac(grp,R,R,tmp);
        if(mbedtls_mpi_get_bit(m,i)==1) ecp_add_mixed(grp,R,R,P,tmp);
    }
    ecp_normalize_jac(grp,R);

}


int doubleandadd_ver(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P, double *time)
{

    clock_t begin, end;
    begin = clock();
    mbedtls_ecp_point res;
    mbedtls_ecp_point_init(&res);
    mbedtls_ecp_set_zero(&res);
    int bits = grp->nbits;
    mbedtls_mpi tmp[4];
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    for(int i=bits-1;i>=0;i--){
        ecp_double_jac(grp,&res,&res,tmp);
        if(mbedtls_mpi_get_bit(m,i)==1) ecp_add_mixed(grp,&res,&res,P,tmp);
    }
    ecp_sub_mixed(grp,&res,&res,R,tmp);
    end = clock();
    *time=(double)(end - begin) / CLOCKS_PER_SEC;
    return mbedtls_ecp_is_zero(&res);
}


int mul_glv_ver(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *P, glvpackage *pckg, double *time)
{
    clock_t begin, end;
    begin = clock();

    mbedtls_ecp_point res;
    mbedtls_ecp_point_init(&res);
    mbedtls_ecp_set_zero(&res);


    mbedtls_mpi k0, k1;
    mbedtls_mpi_init(&k0);
    mbedtls_mpi_init(&k1);
    scalar_decomposition(&k0,&k1,k,pckg,&grp->N);

    mbedtls_ecp_point lamP,sumP,subP;
    mbedtls_ecp_point_init(&lamP);
    mbedtls_ecp_point_init(&subP);
    mbedtls_ecp_point_init(&sumP);

    mbedtls_ecp_copy(&lamP,P);
    apply_beta(grp,&lamP,&pckg->beta);
    mbedtls_ecp_copy(&sumP,&lamP);
    apply_beta(grp,&sumP,&pckg->beta);
    ecp_safe_invert_jac(grp,&sumP,1);
    mbedtls_mpi tmp[9];
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    ecp_sub_mixed(grp,&subP,P,&lamP,tmp);
    ecp_normalize_jac(grp,&subP);

    int s0 = k0.s;
    int s1 = k1.s;
    k0.s = 1;
    k1.s = 1;
    int k0bits = mbedtls_mpi_bitlen(&k0);
    int k1bits = mbedtls_mpi_bitlen(&k1);
    int bm = (k0bits > k1bits ? k0bits : k1bits);
    int v0[bm+2], v1[bm+2];
    int loop = jsf(&k0,&k1,v0,v1);
    mbedtls_ecp_point *table[3] = {&subP,(mbedtls_ecp_point *) P,&sumP}; 


    int i0,i1;
    for(int i=loop-1;i>=0;i--){
        if(!mbedtls_ecp_is_zero(&res))ecp_double_jac(grp, &res, &res, tmp);

        i0 = s0*v0[i];
        i1 = s1*v1[i];

        if(i0==1) ecp_add_mixed(grp,&res,&res,table[i1+1],tmp);
        else if(i0==-1) ecp_sub_mixed(grp,&res,&res,table[-i1+1],tmp);
        else if (i1==1) ecp_add_mixed(grp,&res,&res,&lamP,tmp);
        else if (i1==-1) ecp_sub_mixed(grp,&res,&res,&lamP,tmp);
    }
    ecp_sub_mixed(grp,&res,&res,R,tmp);
    end = clock();
    *time=(double)(end - begin) / CLOCKS_PER_SEC;
    return mbedtls_ecp_is_zero(&res);
}



int mul_glv3_ver(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *k, const mbedtls_ecp_point *P, glvpackage *pckg, double *time)
{
    clock_t begin, end;
    begin = clock();


    mbedtls_ecp_point res;
    mbedtls_ecp_point_init(&res);
    mbedtls_ecp_set_zero(&res);


    mbedtls_mpi ls[3];
    mpi_init_many(ls, sizeof(ls) / sizeof(mbedtls_mpi));
    small_3(pckg,k,&grp->N,ls);

    int s0= ls[0].s;
    int s1= ls[1].s;
    int s2= ls[2].s;

    mbedtls_mpi als[3];
    mpi_init_many(als, sizeof(als) / sizeof(mbedtls_mpi));
    int als_bits[3];


    for(int i=0;i<3;i++){
    mbedtls_mpi_copy(&als[i],&ls[i]);
    als[i].s = 1;
    als_bits[i] = mbedtls_mpi_bitlen(&als[i]);
    }
    
    int bm = (als_bits[1] > als_bits[2] ? als_bits[1] : als_bits[2]);
    bm = (als_bits[0] > bm ? als_bits[0] : bm);     
    int v0[bm+3], v1[bm+3], v2[bm+3];
    int *vs[3] = {v0,v1,v2};
    int loop = jsf3(als,vs);

    mbedtls_mpi tmp[9];
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    mbedtls_ecp_point lamP, sumP, subP;
    mbedtls_ecp_point_init(&lamP);
    mbedtls_ecp_point_init(&sumP);
    mbedtls_ecp_point_init(&subP);
    mbedtls_ecp_copy(&lamP,P);
    apply_beta(grp,&lamP,&pckg->beta);
    mbedtls_ecp_copy(&sumP,&lamP);
    apply_beta(grp,&sumP,&pckg->beta);
    ecp_safe_invert_jac(grp,&sumP,1);
    ecp_sub_mixed(grp,&subP,P,&lamP,tmp);


    mbedtls_ecp_point *table0[3] = {&subP,(mbedtls_ecp_point *) P,&sumP};//1-10,100,110
    mbedtls_ecp_point table[3][3];
    for(int i=0;i<3;i++) for(int j=0;j<3;j++) mbedtls_ecp_point_init(&table[i][j]);

    mbedtls_ecp_copy(&table[1][1],R); //001
    ecp_add_mixed(grp,&table[1][2],R,&lamP,tmp); //011 
    ecp_add_mixed(grp,&table[2][1],R,P,tmp); //101
    ecp_add_mixed(grp,&table[2][2],R,&sumP,tmp); //111
    ecp_add(grp,&table[2][0],R,&subP,tmp); //1-11
    ecp_sub_mixed(grp,&table[1][0],R,&lamP,tmp); //0-11
    ecp_sub_mixed(grp,&table[0][1],R,P,tmp); //-101
    ecp_sub_mixed(grp,&table[0][0],R,&sumP,tmp); //-1-11
    ecp_sub(grp,&table[0][2],R,&subP,tmp); //-111



    mbedtls_ecp_point *to_norm[10] = {&subP,&sumP,&table[1][2],&table[2][1],&table[2][2],&table[2][0],&table[1][0],&table[0][1],&table[0][0],&table[0][2]};
    ecp_normalize_jac_many(grp,to_norm, 10);



    int i0,i1,i2;

    for(int i=loop-1;i>=0;i--){
        if(!mbedtls_ecp_is_zero(&res))ecp_double_jac(grp, &res, &res, tmp);

        i0 = s0*v0[i];
        i1 = s1*v1[i];
        i2 = s2*v2[i];


       if(i2==0){
            if(i0==1) {ecp_add_mixed(grp,&res,&res,table0[i1+1],tmp);}
            if((i0==0) & (i1==1)) {ecp_add_mixed(grp,&res,&res,&lamP,tmp);}
            if((i0==0) & (i1==-1)) {ecp_sub_mixed(grp,&res,&res,&lamP,tmp);}
            if(i0==-1) {ecp_sub_mixed(grp,&res,&res,table0[-i1+1],tmp);}
        }
        if(i2==1) {ecp_add_mixed(grp,&res,&res,&table[i0+1][i1+1],tmp);}
        if(i2==-1) {ecp_sub_mixed(grp,&res,&res,&table[-i0+1][-i1+1],tmp);}


    }
    end = clock();
    *time=(double)(end - begin) / CLOCKS_PER_SEC;
    return mbedtls_ecp_is_zero(&res);
}


//timing wrapper
void muladd_glv_timing(mbedtls_ecp_group *grp,
                                     mbedtls_ecp_point *R,
                                     const mbedtls_mpi *m,
                                     const mbedtls_ecp_point *G,
                                     const mbedtls_mpi *n,
                                     const mbedtls_ecp_point *Q, glvpackage *pckg, double *time)
{
    clock_t begin, end;
    begin = clock();
    muladd_glv(grp, R, m, G,n,Q,pckg);
    end = clock();
    *time=(double)(end - begin) / CLOCKS_PER_SEC;

}


//timing wrapper
void muladd_glv3_timing(mbedtls_ecp_group *grp,
                                     mbedtls_ecp_point *R,
                                     const mbedtls_mpi *m,
                                     const mbedtls_ecp_point *G,
                                     const mbedtls_mpi *n,
                                     const mbedtls_ecp_point *Q,
                                     const mbedtls_mpi *r, glvpackage *pckg, double *time)
{
    clock_t begin, end;
    begin = clock();
    muladd_glv3(grp, R, m, G,n,Q,pckg, r);
    end = clock();
    *time=(double)(end - begin) / CLOCKS_PER_SEC;
}

//timing wrapper
void muladd_shamir_timing(mbedtls_ecp_group *grp,
                                     mbedtls_ecp_point *R,
                                     const mbedtls_mpi *m,
                                     const mbedtls_ecp_point *G,
                                     const mbedtls_mpi *n,
                                     const mbedtls_ecp_point *Q,
                                     double *time)
{
    clock_t begin, end;
    begin = clock();
    muladd_shamir(grp, R, m, G,n,Q);
    end = clock();
    *time=(double)(end - begin) / CLOCKS_PER_SEC;
}




void my_set_point(mbedtls_ecp_point *P, const char *X,const char *Y,const char *Z){
    mbedtls_mpi_read_string(&P->X,10,X);
    mbedtls_mpi_read_string(&P->Y,10,Y);
    mbedtls_mpi_read_string(&P->Z,10,Z);

}


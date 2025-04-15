#include "common.h"
#include "jsf.h"
#include "mbedtls/ecp.h"
#include "lattice.h"


int mods(mbedtls_mpi *a){
    if((mbedtls_mpi_get_bit(a,0) == 0) & (mbedtls_mpi_get_bit(a,1) == 0)) return 0;
    if((mbedtls_mpi_get_bit(a,0) == 1) & (mbedtls_mpi_get_bit(a,1) == 0)) return 1;
    if((mbedtls_mpi_get_bit(a,0) == 0) & (mbedtls_mpi_get_bit(a,1) == 1)) return 2;
    if((mbedtls_mpi_get_bit(a,0) == 1) & (mbedtls_mpi_get_bit(a,1) == 1)) return -1;
    return -2;
}


void test_jsf(mbedtls_mpi *k0orig, mbedtls_mpi *k1orig,int *us, int *vs,int l){
    mbedtls_mpi newk0, newk1;
    mbedtls_mpi_init(&newk0);
    mbedtls_mpi_init(&newk1);
    mbedtls_mpi_lset(&newk0, 0);
    mbedtls_mpi_lset(&newk1, 0);
    for(int i=l-1;i>=0;i--){
        mbedtls_mpi_shift_l(&newk0,1);
        mbedtls_mpi_shift_l(&newk1,1);
        if(us[i]<0)mbedtls_mpi_sub_int(&newk0,&newk0,1);
        else mbedtls_mpi_add_int(&newk0,&newk0,us[i]);
        if(vs[i]<0)mbedtls_mpi_sub_int(&newk1,&newk1,1);
        else mbedtls_mpi_add_int(&newk1,&newk1,vs[i]);

    }
    mbedtls_mpi dif;
    mbedtls_mpi_init(&dif);
    mbedtls_mpi_sub_mpi(&dif,&newk0,k0orig);
    printf_mpi(&dif);
    printf("test=%d\n",mbedtls_mpi_cmp_int(&dif,0)==0);
    mbedtls_mpi_sub_mpi(&dif,&newk1,k1orig);
    printf_mpi(&dif);
    printf("test=%d\n",mbedtls_mpi_cmp_int(&dif,0)==0);
}


int jsf(mbedtls_mpi *k0orig, mbedtls_mpi *k1orig, int *us, int *vs){
    int d0 = 0;
    int d1 = 0;
    mbedtls_mpi k0,k1,l0,l1;
    mbedtls_mpi_init(&k0);
    mbedtls_mpi_init(&k1);
    mbedtls_mpi_init(&l0);
    mbedtls_mpi_init(&l1);
    int u0, u1;
    mbedtls_mpi_copy(&k0, k0orig);
    mbedtls_mpi_copy(&k1, k1orig);
    int j = 0;
    while(1){
        mbedtls_mpi_add_int(&l0,&k0,d0);
        mbedtls_mpi_add_int(&l1,&k1,d1);
        if((mbedtls_mpi_cmp_int(&l0,0)<=0) & (mbedtls_mpi_cmp_int(&l1,0)<=0)) break;
        if(mbedtls_mpi_get_bit(&l0,0) == 0){u0=0;}
        else{u0 = mods(&l0);
            if((mbedtls_mpi_get_bit(&l0,0) == 1) & (mbedtls_mpi_get_bit(&l0,1) == 1) & (mbedtls_mpi_get_bit(&l0,2) == 0) & (mbedtls_mpi_get_bit(&l1,0) == 0) & (mbedtls_mpi_get_bit(&l1,1) == 1)) u0=-u0;       
        }
        if(mbedtls_mpi_get_bit(&l1,0) == 0){u1=0;}
        else{u1 = mods(&l1);
            if((mbedtls_mpi_get_bit(&l1,0) == 1) & (mbedtls_mpi_get_bit(&l1,1) == 1) & (mbedtls_mpi_get_bit(&l1,2) == 0) & (mbedtls_mpi_get_bit(&l0,0) == 0) & (mbedtls_mpi_get_bit(&l0,1) == 1)) u1=-u1;
        }
        if((d0<<1)==1+u0) d0 = 1-d0;
        if((d1<<1)==1+u1) d1 = 1-d1;
        mbedtls_mpi_shift_r(&k0,1);
        mbedtls_mpi_shift_r(&k1,1);
        us[j] = u0;
        vs[j] = u1;
        j+=1;
    }
    // test_jsf(k0orig,k1orig,us,vs,j);
    return j;
    
}



void test_jsf3(mbedtls_mpi *xs, int **us,int l){
    mbedtls_mpi newxs[3];
    mpi_init_many(newxs,3);
    for(int i=0;i<3;i++){
        mbedtls_mpi_lset(&newxs[i],0);
    }
    for(int i=l-1;i>=0;i--){
        for(int j=0;j<3;j++){
            mbedtls_mpi_mul_int(&newxs[j],&newxs[j],2);
            if(us[j][i]<0) mbedtls_mpi_sub_int(&newxs[j],&newxs[j],1);
            else mbedtls_mpi_add_int(&newxs[j],&newxs[j],us[j][i]);
        }
    }
    for(int j=0;j<3;j++){
        printf_mpi(&newxs[j]);
        printf_mpi(&xs[j]);
    }
}



int jsf3(mbedtls_mpi xs[3], int **us){

    int j = 0;
    int cas;
    int dobreak = 0;
    mbedtls_mpi tmp;
    // mbedtls_mpi xs_copy[3];
    // mpi_init_many(xs_copy,3);
    // for(int i=0;i<3;i++ )mbedtls_mpi_copy(&xs_copy[i],&xs[i]);
    mbedtls_mpi_init(&tmp);
    int A[3],A1[3];
    for(int i=0;i<3;i++){
        A[i] = (int) (mbedtls_mpi_get_bit(&xs[i],0)==1);
        A1[i] =0;
        if(mbedtls_mpi_cmp_int(&xs[i],0)!=0) dobreak = 1;
    }
    while(dobreak){
        cas = 0;
        for(int i=0;i<3;i++){
            us[i][j]=mbedtls_mpi_get_bit(&xs[i],0);
            if(mbedtls_mpi_get_bit(&xs[i],1)==1){
                cas = cas || (A[i]==0);
                A1[i]=1;
            }
        }
        dobreak = 0;
        for(int i=0;i<3;i++) {
            
            if(((!cas) & (A1[i]==1)) || (cas & (A1[i]==0) & (A[i]==1)))  us[i][j] = -us[i][j];
            A[i]=cas&(A[i]||A1[i]);
            if(us[i][j]< 0) {
                mbedtls_mpi_add_int(&xs[i],&xs[i],-us[i][j]);

            }
            mbedtls_mpi_shift_r(&xs[i],1);
            if (mbedtls_mpi_cmp_int(&xs[i],0)!=0) dobreak = 1;
            A1[i]=0;
            
        }
        j+=1;
    }
    // test_jsf3(xs_copy,us,j);
    // for(int i=0;i<j;i++) printf("%d,%d,%d\n",us[0][i],us[1][i],us[2][i]);
    return j;


}


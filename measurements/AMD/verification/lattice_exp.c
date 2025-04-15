
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "glvecdsa.h"
#include "glvecp.h"
#include "lattice.h"
#include "sign.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

#include <string.h>


#define ECPARAMS    MBEDTLS_ECP_DP_SECP256K1


void check_correctness(struct glvpackage *pkg, mbedtls_mpi *k, const mbedtls_mpi* N, mbedtls_mpi ls[3]) {


    mbedtls_mpi t1,t2;
    mbedtls_mpi_init(&t1);
    mbedtls_mpi_init(&t2);
    mbedtls_mpi_mul_mpi(&t1,k,&ls[2]);
    mbedtls_mpi_mul_mpi(&t2,&pkg->lambda,&ls[1]);
    mbedtls_mpi_add_mpi(&t1,&t1,&t2);
    mbedtls_mpi_add_mpi(&t1,&t1,&ls[0]);
    mbedtls_mpi_div_mpi(NULL,&t2,&t1,N);
    if (mbedtls_mpi_cmp_int(&t2,0)!=0) {printf("Error!\n");printf_mpi(&t2);printf_mpi(k);exit(1);}


}


void small_one(){

    glvpackage glvpackage;
    init_glvpackage(&glvpackage,ECPARAMS);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, 
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));

    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    // mbedtls_mpi_read_string(&k,10,"557073415843455186786046191312039577462134098663458688126717814594317292459372200179122660950544547983431586620085");
    // mbedtls_mpi_read_string(&k,10,"25574193097230713156982222478766144648026755149411407326285324493346314376598388899230930306277033615724192126048801");
    mbedtls_mpi_read_string(&k,10,"7786508318662384835139515788000633935535037991301736967013221013560781901534388071358146525934088774634747167003653");

    mbedtls_mpi ls[3];
    mpi_init_many(ls, sizeof(ls) / sizeof(mbedtls_mpi));
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);


    int b0,b1,b2;


  

    small_3_semaev(&glvpackage,&k,&grp.N,ls);
        
    check_correctness(&glvpackage,&k,&grp.N,ls);
    b0 = mbedtls_mpi_bitlen(&ls[0]);
    b1 = mbedtls_mpi_bitlen(&ls[1]);
    b2 = mbedtls_mpi_bitlen(&ls[2]);
    printf_mpi(&grp.N);
    printf_mpi(&k);
    printf_mpi(&ls[0]);
    printf_mpi(&ls[1]);
    printf_mpi(&ls[2]);

    

}


void smallmany(){
    glvpackage glvpackage;
    init_glvpackage(&glvpackage,ECPARAMS);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsa";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, 
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));

    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    mbedtls_mpi ls[3], ds[3];
    mpi_init_many(ls, sizeof(ls) / sizeof(mbedtls_mpi));
    mpi_init_many(ds, sizeof(ds) / sizeof(mbedtls_mpi));
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);


    int max_g = 0, sum_g = 0, max_s = 0, sum_s = 0;
    int b0,b1,b2,b_g,b_s;
    int count = 10000;
    double time_gauss=0, time_semaev=0;
    clock_t begin, end;
    int counter = 0;
    for(int i=0;i<count;i++){

    mbedtls_mpi_random(&k, 1, &grp.N, mbedtls_ctr_drbg_random, &ctr_drbg);
    begin = clock();
    small_3(&glvpackage,&k,&grp.N,ls);
    end = clock();
    time_gauss+=(double)(end - begin) / CLOCKS_PER_SEC;
    check_correctness(&glvpackage,&k,&grp.N,ls);
    // if(ds[0]->s!=1) {ds[0]->s=1;ds[0]->s=-ds[1]->s;ds[2]->s=-ds[2]->s;}
    if(ls[0].private_s!=1) {ls[0].private_s=1;ls[1].private_s=-ls[1].private_s;ls[2].private_s=-ls[2].private_s;}


    b0 = mbedtls_mpi_bitlen(&ls[0]);
    b1 = mbedtls_mpi_bitlen(&ls[1]);
    b2 = mbedtls_mpi_bitlen(&ls[2]);
    b_g = b0 > b1 ? b0 : b1;
    b_g = b_g > b2 ? b_g : b2;
    sum_g+=b_g;
    max_g = b_g > max_g ? b_g : max_g;

    begin = clock();
    small_3_semaev(&glvpackage,&k,&grp.N,ds);
    end = clock();
    time_semaev+=(double)(end - begin) / CLOCKS_PER_SEC;
    check_correctness(&glvpackage,&k,&grp.N,ds);
    if(ds[0].private_s!=1) {ds[0].private_s=1;ds[1].private_s=-ds[1].private_s;ds[2].private_s=-ds[2].private_s;}

    if (mbedtls_mpi_cmp_mpi(&ls[0],&ds[0])!=0) {counter+=1;}//printf("Errordif!\n");printf_mpi(&ds[0]);printf_mpi(&ls[0]);exit(1);}

    b0 = mbedtls_mpi_bitlen(&ds[0]);
    b1 = mbedtls_mpi_bitlen(&ds[1]);
    b2 = mbedtls_mpi_bitlen(&ds[2]);
    b_s = b0 > b1 ? b0 : b1;
    b_s = b_s > b2 ? b_s : b2;
    sum_s+=b_s;
    max_s = b_s > max_s ? b_s : max_s;
    //if(b_s!=b_g) printf("dif:%d, %d\n",b_s,b_g);

    if(b_s>86) {

    printf("--\n");
    printf_mpi(&grp.N);
    printf_mpi(&k);
    printf_mpi(&ls[0]);
    printf_mpi(&ls[1]);
    printf_mpi(&ls[2]);
    }

    }

    printf("Greedy: max: %d, avg: %f, time: %f\n",max_g,sum_g/(float)count,time_gauss);
    printf("Semaev: max: %d, avg: %f, time: %f\n",max_s,sum_s/(float)count,time_semaev);
    printf("Greedy worse: %d\n",counter);
}


int main(){

    // small_one();
    smallmany();
    return 0;

}



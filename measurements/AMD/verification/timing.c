
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "glvecdsa.h"
#include "glvecp.h"
#include "lattice.h"
#include "sign.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"

#include <string.h>


#define ECPARAMS    MBEDTLS_ECP_DP_SECP384K1


typedef struct signature_data{

    mbedtls_ecp_point Q;
    mbedtls_mpi r;
    mbedtls_mpi s;
    mbedtls_mpi k;
} signature_data;


void load_256_sigs(signature_data sigs[10]){
mbedtls_ecp_point_init(&sigs[0].Q);
mbedtls_mpi_read_string(&sigs[0].Q.private_X,10,"10800874784868573868540378829958983102010089428298838356857863372525767762755");
mbedtls_mpi_read_string(&sigs[0].Q.private_Y,10,"232583774182809312650414785348945626334456782831600636710151726511195510162");
mbedtls_mpi_read_string(&sigs[0].Q.private_Z,10,"1");
mbedtls_mpi_init(&sigs[0].r);
mbedtls_mpi_init(&sigs[0].s);
mbedtls_mpi_init(&sigs[0].k);
mbedtls_mpi_read_string(&sigs[0].r,10,"76146094778675038688855670475433266023868510846579217288814822140097676788958");
mbedtls_mpi_read_string(&sigs[0].s,10,"63961280243626221066795943123600148069931790188002517316949212539270031246004");
mbedtls_mpi_read_string(&sigs[0].k,10,"80265505103910903221122338656799874939541626511492070311493610464825529293647");

mbedtls_ecp_point_init(&sigs[1].Q);
mbedtls_mpi_read_string(&sigs[1].Q.private_X,10,"78567784653555644059408949843439384948794262213083823729254832074632750248178");
mbedtls_mpi_read_string(&sigs[1].Q.private_Y,10,"5384318187260238623909156227878511243301448858672427753698986784130477294485");
mbedtls_mpi_init(&sigs[1].r);
mbedtls_mpi_init(&sigs[1].s);
mbedtls_mpi_init(&sigs[1].k);
mbedtls_mpi_read_string(&sigs[1].r,10,"85295667112535799804082721379103932810573508683359071530845651383175540359168");
mbedtls_mpi_read_string(&sigs[1].s,10,"64123357889805975514015446820638546375836812965214590279947434958587840609645");
mbedtls_mpi_read_string(&sigs[1].k,10,"112637414655101494652995131209236284859255221217715432657395023436050708673650");

mbedtls_ecp_point_init(&sigs[2].Q);
mbedtls_mpi_read_string(&sigs[2].Q.private_X,10,"85741029218899886078573471253640264624914790258401513591382683997361269011268");
mbedtls_mpi_read_string(&sigs[2].Q.private_Y,10,"47490382543055139411928187139956153618177892138000471257502142346558253134203");
mbedtls_mpi_init(&sigs[2].r);
mbedtls_mpi_init(&sigs[2].s);
mbedtls_mpi_init(&sigs[2].k);
mbedtls_mpi_read_string(&sigs[2].r,10,"57172549828892880445068830181022847855501456674152164872510181097515450517915");
mbedtls_mpi_read_string(&sigs[2].s,10,"25471426425001867979231162683454637490794111886190191378536892854608464503170");
mbedtls_mpi_read_string(&sigs[2].k,10,"77648876024168344219968580869218706296677004706323656130322352039470179469061");

mbedtls_ecp_point_init(&sigs[3].Q);
mbedtls_mpi_read_string(&sigs[3].Q.private_X,10,"65869992379801101367213402729993125829622678455924253477885383430921495247387");
mbedtls_mpi_read_string(&sigs[3].Q.private_Y,10,"97470199508484815468985379835414721139949552526555095019391081184032070531351");
mbedtls_mpi_init(&sigs[3].r);
mbedtls_mpi_init(&sigs[3].s);
mbedtls_mpi_init(&sigs[3].k);
mbedtls_mpi_read_string(&sigs[3].r,10,"112622902096605922684511069403335321936987056304619533707870467097029844398535");
mbedtls_mpi_read_string(&sigs[3].s,10,"16838122227687962677035918187823875637373711349373963431570303876777784206556");
mbedtls_mpi_read_string(&sigs[3].k,10,"41539698889131679910349607628869784200672182772510471979179955417894859322606");

mbedtls_ecp_point_init(&sigs[4].Q);
mbedtls_mpi_read_string(&sigs[4].Q.private_X,10,"46998450711258423557208511196405668634118441254267266000279036154582476331759");
mbedtls_mpi_read_string(&sigs[4].Q.private_Y,10,"74057364382869736170506706728225265618161592662686849846577568764807816886034");
mbedtls_mpi_init(&sigs[4].r);
mbedtls_mpi_init(&sigs[4].s);
mbedtls_mpi_init(&sigs[4].k);
mbedtls_mpi_read_string(&sigs[4].r,10,"15989891536667818011482264133237803974962834080487953848682497428720545899471");
mbedtls_mpi_read_string(&sigs[4].s,10,"89742627176893563220520309961035109077847351458486501754250904958312782031939");
mbedtls_mpi_read_string(&sigs[4].k,10,"28452255965589284424169403598182037400264099240874801517955341085020082737159");

mbedtls_ecp_point_init(&sigs[5].Q);
mbedtls_mpi_read_string(&sigs[5].Q.private_X,10,"2399888530637199487104558142529617155450111392788803978247248581975665505850");
mbedtls_mpi_read_string(&sigs[5].Q.private_Y,10,"792666559182674650505827193194916517244169055232989505073184984842265886381");
mbedtls_mpi_init(&sigs[5].r);
mbedtls_mpi_init(&sigs[5].s);
mbedtls_mpi_init(&sigs[5].k);
mbedtls_mpi_read_string(&sigs[5].r,10,"4219112875450038484502291468968579162208396598981761473643676814474410762309");
mbedtls_mpi_read_string(&sigs[5].s,10,"8065744957226773980331425572107515721520766245541125426150157195878976000866");
mbedtls_mpi_read_string(&sigs[5].k,10,"30907862788745967323289404462901595142734902198383807591434739817909503676951");

mbedtls_ecp_point_init(&sigs[6].Q);
mbedtls_mpi_read_string(&sigs[6].Q.private_X,10,"56676688054357480219680452469954173247117280024701720372857819902157854259590");
mbedtls_mpi_read_string(&sigs[6].Q.private_Y,10,"32084844008906376125676807036233503410863537617786147917674819838504103651624");
mbedtls_mpi_init(&sigs[6].r);
mbedtls_mpi_init(&sigs[6].s);
mbedtls_mpi_init(&sigs[6].k);
mbedtls_mpi_read_string(&sigs[6].r,10,"115509089816998606520319735532959996524933617346594646643903025949966171775778");
mbedtls_mpi_read_string(&sigs[6].s,10,"59113554484880745829289538618390871023321522143700869853347744769433976249718");
mbedtls_mpi_read_string(&sigs[6].k,10,"80921705801496451141446016080356563019622495283393390304816626536497447721129");

mbedtls_ecp_point_init(&sigs[7].Q);
mbedtls_mpi_read_string(&sigs[7].Q.private_X,10,"30437550720956446088958623492899301207424879100544208517742918237693793016114");
mbedtls_mpi_read_string(&sigs[7].Q.private_Y,10,"36242739947813880904385238928647016073120510464722075756524324937515170679431");
mbedtls_mpi_init(&sigs[7].r);
mbedtls_mpi_init(&sigs[7].s);
mbedtls_mpi_init(&sigs[7].k);
mbedtls_mpi_read_string(&sigs[7].r,10,"70829219914534428634051136006446511181951046056031211449983933729358655446082");
mbedtls_mpi_read_string(&sigs[7].s,10,"81238264025200593382302365185032658941740731926675696330688370846902008521721");
mbedtls_mpi_read_string(&sigs[7].k,10,"101528049118094551664531093478677747559146123509585090468521046400044462397469");

mbedtls_ecp_point_init(&sigs[8].Q);
mbedtls_mpi_read_string(&sigs[8].Q.private_X,10,"35229542688927145915284988731052376834235044359499260508346245492805292063577");
mbedtls_mpi_read_string(&sigs[8].Q.private_Y,10,"40852042384815623854479853495989557521298840138184758822614932666071607588937");
mbedtls_mpi_init(&sigs[8].r);
mbedtls_mpi_init(&sigs[8].s);
mbedtls_mpi_init(&sigs[8].k);
mbedtls_mpi_read_string(&sigs[8].r,10,"16875772278110436520583762334386992789036805563313805606684693601759253181013");
mbedtls_mpi_read_string(&sigs[8].s,10,"7423268834196202996325262707634890920207765314683603904171398825672105616074");
mbedtls_mpi_read_string(&sigs[8].k,10,"13473391511925233919035677444376361574531241515670079672195875618449028099332");

mbedtls_ecp_point_init(&sigs[9].Q);
mbedtls_mpi_read_string(&sigs[9].Q.private_X,10,"97637850267093336937782341209198008916930561485307483323572002333774799092566");
mbedtls_mpi_read_string(&sigs[9].Q.private_Y,10,"46017529380618172499568948961660509768571163220333337357325992830098626691095");
mbedtls_mpi_init(&sigs[9].r);
mbedtls_mpi_init(&sigs[9].s);
mbedtls_mpi_init(&sigs[9].k);
mbedtls_mpi_read_string(&sigs[9].r,10,"8824403024934751278837544897060100240844110165080258487377087745640014444461");
mbedtls_mpi_read_string(&sigs[9].s,10,"66704705775218696104830184870755608567336632509459682769318080817667256736901");
mbedtls_mpi_read_string(&sigs[9].k,10,"22470932837504497980691191258878363746843376428227400893350083603448589061628");



}






int measure_exp()
{
    int ret = 0;
    char str[100];
    mbedtls_ecp_group_id grp_id = MBEDTLS_ECP_DP_SECP256K1;

    glvpackage pckg;
    init_glvpackage(&pckg,MBEDTLS_ECP_DP_SECP256K1);

    mbedtls_mpi ls[3];
    mpi_init_many(ls, sizeof(ls) / sizeof(mbedtls_mpi));
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
    unsigned char hash[32] = {2,244,204,240,157,31,87,64,226,136,100,196,48,248,102,180,107,105,118,70,211,118,231,129,61,18,184,115,219,225,108,198};

    signature_data sigs[10];
    load_256_sigs(sigs);
    size_t m1,m2,m3,m;
    for(int i=0;i<10;i++){

      // small_3_semaev(&pckg,&sigs[i].k,&grp.N,ls);
      // m1 = mbedtls_mpi_size(&ls[0]);
      // m2 = mbedtls_mpi_size(&ls[1]);
      // m3 = mbedtls_mpi_size(&ls[2]);
      // m = m1>m2 ? m1 : m2;
      // m = m3>m ? m3 : m;
      // ret+=(m>140);
    // small_3(&pckg,&sigs[i].k,&grp.N,ls);
    printf_mpi(&sigs[i].Q.private_X);
    printf_mpi(&sigs[i].Q.private_Y);
    printf_mpi(&sigs[i].r);
    printf_mpi(&sigs[i].s);

    ret = mbedtls_ecdsa_shamir_verify_restartable(&grp, hash, sizeof(hash),&sigs[i].Q, &sigs[i].r, &sigs[i].s);
      // ret = mbedtls_ecdsa_glv3_verify_restartable(&grp, hash, sizeof(hash), &sigs[i].Q, &sigs[i].r, &sigs[i].s, &pckg);

    printf("Ret %d\n", ret);

    }
    printf("Ret %d\n", ret);
    //sprintf(str, "Ret4 %d", ret);


}



void generate_signatures()
{
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";
    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    memset(sig, 0, sizeof(sig));
    memset(message, 0x25, sizeof(message));
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    mbedtls_ecdsa_genkey(&ctx_sign, ECPARAMS,mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(&ctx_sign);
    mbedtls_sha256(message, sizeof(message), hash, 0);

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    oddmbedtls_ecdsa_sign_det_restartable(&ctx_sign.private_grp, &r, &s, &ctx_sign.private_d,hash, sizeof(hash), MBEDTLS_MD_SHA256, mbedtls_ctr_drbg_random, &ctr_drbg);



    mbedtls_ecp_export(&ctx_sign, NULL, NULL, &Q);
    mbedtls_ecp_set_public_key(grp_id, &ctx_verify, &Q);

    // for(int i=0;i<32;i++) printf("%d,",hash[i]);
    // printf("\n");
    printf_mpi(&Q.private_X);
    printf_mpi(&Q.private_Y);
    printf_mpi(&r);
    printf_mpi(&s);

    double time;
    glvpackage pckg;
    init_glvpackage(&pckg,ECPARAMS);

    int ret = mbedtls_ecdsa_glv3_verify_restartable(&ctx_verify.private_grp, hash, sizeof(hash),
                                                &Q, &r, &s, &pckg);

    ret = mbedtls_ecdsa_shamir_verify_restartable(&ctx_verify.private_grp, hash, sizeof(hash),&Q, &r, &s);


    if (ret!=0) printf("\nError\n");

}


double time_verify_glv3()
{
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";
    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    memset(sig, 0, sizeof(sig));
    memset(message, 0x25, sizeof(message));
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    mbedtls_ecdsa_genkey(&ctx_sign, ECPARAMS,mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(&ctx_sign);
    mbedtls_sha256(message, sizeof(message), hash, 0);

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    oddmbedtls_ecdsa_sign_det_restartable(&ctx_sign.private_grp, &r, &s, &ctx_sign.private_d,hash, sizeof(hash), MBEDTLS_MD_SHA256, mbedtls_ctr_drbg_random, &ctr_drbg);

    // printf_mpi(&Q.private_X);
    // printf_mpi(&Q.private_Y);
    // printf_mpi(&r);
    // printf_mpi(&s);

    mbedtls_ecp_export(&ctx_sign, NULL, NULL, &Q);
    mbedtls_ecp_set_public_key(grp_id, &ctx_verify, &Q);





    double time;
    glvpackage pckg;
    init_glvpackage(&pckg,ECPARAMS);
    clock_t begin, end;
    begin = clock();
    int ret = mbedtls_ecdsa_glv3_verify_restartable(&ctx_verify.private_grp, hash, sizeof(hash),
                                                &Q, &r, &s, &pckg);
    end = clock();
    time=(double)(end - begin) / CLOCKS_PER_SEC;

    if (ret!=0) {printf("\nError\n");

        printf("\nbegin signature\n");
    for(int i=0;i<MBEDTLS_ECDSA_MAX_LEN;i++)printf("%u,",sig[i]);
    // printf("\n%lu",sig_len);
    printf("\nend signature\n");


    printf("\nbegin pubkey\n");
    printf_point(&Q);
    printf("\nend epubkey\n");

    exit(1);}
    return time;


}


double time_verify_glv()
{
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";
    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    memset(sig, 0, sizeof(sig));
    memset(message, 0x25, sizeof(message));
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    mbedtls_ecdsa_genkey(&ctx_sign, ECPARAMS,mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(&ctx_sign);
    mbedtls_sha256(message, sizeof(message), hash, 0);

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    oddmbedtls_ecdsa_sign_det_restartable(&ctx_sign.private_grp, &r, &s, &ctx_sign.private_d,hash, sizeof(hash), MBEDTLS_MD_SHA256, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ecp_export(&ctx_sign, NULL, NULL, &Q);
    mbedtls_ecp_set_public_key(grp_id, &ctx_verify, &Q);


    double time;
    glvpackage pckg;
    init_glvpackage(&pckg,ECPARAMS);
    clock_t begin, end;
    begin = clock();
    int ret = mbedtls_ecdsa_glv_verify_restartable(&ctx_verify.private_grp, hash, sizeof(hash),
                                                &Q, &r, &s, &pckg);
    end = clock();
    time=(double)(end - begin) / CLOCKS_PER_SEC;
    if (ret!=0) {printf("\nError\n");}

    return time;


}


double time_verify_shamir()
{
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len;
    const char *pers = "ecdsa";
    mbedtls_ecdsa_init(&ctx_sign);
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    memset(sig, 0, sizeof(sig));
    memset(message, 0x25, sizeof(message));
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    mbedtls_ecdsa_genkey(&ctx_sign, ECPARAMS,mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(&ctx_sign);
    mbedtls_sha256(message, sizeof(message), hash, 0);

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    oddmbedtls_ecdsa_sign_det_restartable(&ctx_sign.private_grp, &r, &s, &ctx_sign.private_d,hash, sizeof(hash), MBEDTLS_MD_SHA256, mbedtls_ctr_drbg_random, &ctr_drbg);


    mbedtls_ecp_export(&ctx_sign, NULL, NULL, &Q);
    mbedtls_ecp_set_public_key(grp_id, &ctx_verify, &Q);

    double time;
    clock_t begin, end;
    begin = clock();
    int ret = mbedtls_ecdsa_shamir_verify_restartable(&ctx_verify.private_grp, hash, sizeof(hash),
                                                &Q, &r, &s);
    end = clock();
    time=(double)(end - begin) / CLOCKS_PER_SEC;
    if (ret!=0) {printf("\nError\n");}

    return time;

}


double time_add(){


    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "bls";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    mbedtls_mpi n;
    mbedtls_mpi_init(&n);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);

    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    mbedtls_ecp_point Q1,Q2,R;
    mbedtls_mpi tmp[9];
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    mbedtls_ecp_point_init(&Q1);
    mbedtls_ecp_point_init(&Q2);
    mbedtls_ecp_point_init(&R);
    double time;
    clock_t begin, end;

    for(int i=0;i<1000;i++){
    mbedtls_mpi_random(&k, 1, &grp.N, mbedtls_ctr_drbg_random, &ctr_drbg);
    doubleandadd(&grp,&Q1,&k, &grp.G);
    doubleandadd(&grp,&Q2,&k, &grp.G);
    begin = clock();
    ecp_add(&grp,&R,&Q1,&Q2,tmp);
    end = clock();
    time+=(double)(end - begin) / CLOCKS_PER_SEC;
    }
    return time;


}


void scalarmul_gen(){


    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "bls";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    mbedtls_mpi n;
    mbedtls_mpi_init(&n);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);

    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    mbedtls_mpi_random(&k, 1, &grp.N, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    doubleandadd(&grp,&Q,&k, &grp.G);


    printf_mpi(&Q.private_X);
    printf_mpi(&Q.private_Y);
    printf_mpi(&k);

}



double scalarmul_ver(){


    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "bls";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    mbedtls_mpi n;
    mbedtls_mpi_init(&n);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);

    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    mbedtls_mpi_random(&k, 1, &grp.N, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    doubleandadd(&grp,&Q,&k, &grp.G);

    double time;
    if(!doubleandadd_ver(&grp,&Q,&k,&grp.G,&time)) {printf("Error\n");exit(1);}
    return time;

}



double glvmul_ver(){


    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "bls";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    glvpackage pckg;
    init_glvpackage(&pckg,ECPARAMS);

    mbedtls_mpi n;
    mbedtls_mpi_init(&n);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);


    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    mbedtls_mpi_random(&k, 1, &grp.N, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    doubleandadd(&grp,&Q,&k, &grp.G);
    double time;
    if(!mul_glv_ver(&grp,&Q,&k,&grp.G,&pckg,&time)) {printf("Error\n");exit(1);}
    return time;

}




double glv3mul_ver(){


    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "bls";

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers));
    glvpackage pckg;
    init_glvpackage(&pckg,ECPARAMS);

    mbedtls_mpi n;
    mbedtls_mpi_init(&n);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, ECPARAMS);


    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    mbedtls_mpi_random(&k, 1, &grp.N, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    doubleandadd(&grp,&Q,&k, &grp.G);
    double time;
    if(!mul_glv3_ver(&grp,&Q,&k,&grp.G,&pckg,&time)) {printf("Error\n");exit(1);}
    return time;

}


int main(){

    double tt = 0;
    int N = 10;


    // for (int i=0;i<N;i++) generate_signatures();

    // for (int i=0;i<N;i++) scalarmul_gen();

    // printf("Add: %f\n",time_add());

    for (int i=0;i<N;i++) tt+=time_verify_shamir();
    printf("Shamir: %f\n",tt);
    tt = 0;

    for (int i=0;i<N;i++) tt+=time_verify_glv();
    printf("GLV Shamir: %f\n",tt);
    tt = 0;

    for (int i=0;i<N;i++) tt+=time_verify_glv3();
    printf("GLV3: %f\n",tt);
    tt = 0;

    for (int i=0;i<N;i++) tt+=scalarmul_ver();
    printf("BLS simple: %f\n",tt);
    tt = 0;

    for (int i=0;i<N;i++) tt+=glvmul_ver();
    printf("BLSGLV: %f\n",tt);
    tt = 0;

    for (int i=0;i<N;i++) tt+=glv3mul_ver();
    printf("BLSGLV3: %f\n",tt);
    tt = 0;

    return 0;

}

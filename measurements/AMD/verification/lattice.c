#include "common.h"
#include "lattice.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform.h"


#define WORDBITS 64
#define WORDBYTES 8
#define DIV_PRECISION_BITS 32


void printf_mpi(mbedtls_mpi *X){

    unsigned short size = X->n;
    for(int i=0;i<size;i++){
        printf("%lu,",X->p[i]);
    }
    printf("s=%d",X->s);
    printf("\n");

}


void print_gram_matrix(struct GramMatrix *gm) {

    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            printf_mpi(&gm->matrix[gm->p[i]][gm->p[j]]);
        }
        printf("\n");
    }
    printf("\n");
}


void simple_rounded_div(mbedtls_mpi *q, mbedtls_mpi *a0, mbedtls_mpi *b0){


    int sgn = (a0->s)*(b0->s);
    mbedtls_mpi b,a,r;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_copy(&a,a0);
    mbedtls_mpi_copy(&b,b0);
    a.s = 1;
    b.s = 1;
    
    mbedtls_mpi_init(&r);

    mbedtls_mpi_div_mpi(q,&r,&a,&b);
    mbedtls_mpi_shift_l(&r,1);
    if(mbedtls_mpi_cmp_mpi(&r,&b)>0){
        mbedtls_mpi_add_int(q,q,1);
    }
    if(sgn<0){
        q->s = (-1)*(q->s);
    }

}



static void init_secp256k1_package(glvpackage * pckg){

    mbedtls_mpi_init(&pckg->beta);
    mbedtls_mpi_init(&pckg->lambda);
    mbedtls_mpi_init(&pckg->a1);
    mbedtls_mpi_init(&pckg->a2);
    mbedtls_mpi_init(&pckg->b1);
    mbedtls_mpi_init(&pckg->b2);
    mbedtls_mpi_init(&pckg->a12b12);
    mbedtls_mpi_init(&pckg->a22b22);
    mbedtls_mpi_init(&pckg->a1a2b1b2);
    mbedtls_ecp_point_init(&pckg->g1);
    mbedtls_ecp_point_init(&pckg->g2);
    mbedtls_mpi_read_string(&pckg->beta,10,"60197513588986302554485582024885075108884032450952339817679072026166228089408");
    mbedtls_mpi_read_string(&pckg->lambda,10,"78074008874160198520644763525212887401909906723592317393988542598630163514318");
    mbedtls_mpi_read_string(&pckg->a1,10,"303414439467246543595250775667605759171");
    mbedtls_mpi_read_string(&pckg->a2,10,"64502973549206556628585045361533709077");
    mbedtls_mpi_read_string(&pckg->b1,10,"64502973549206556628585045361533709077");
    pckg->b1.s = -1;
    mbedtls_mpi_read_string(&pckg->b2,10,"367917413016453100223835821029139468248");
    mbedtls_mpi_read_string(&pckg->a12b12,10,"96220955673913057706504473090856247813623979764298516566772194457260122799170");
    mbedtls_mpi_read_string(&pckg->a22b22,10,"139523856397408973829538523188664328269760886368182900531510661554749072381433");
    mbedtls_mpi_read_string(&pckg->a1a2b1b2,10,"4160633596689640688901026262144760377709737574331608333072529728972872191929");
    pckg->a1a2b1b2.s=-1;
    mbedtls_mpi_read_string(&pckg->g1.X,10,"6636410774506556864774005162061951749450537962799954397758090215581031792446");
    mbedtls_mpi_read_string(&pckg->g1.Y,10,"33193850663848721154507883351096416412681014543344176760472364118972599175560");
    mbedtls_mpi_lset(&pckg->g1.Z,1);
    mbedtls_mpi_read_string(&pckg->g2.X,10,"75928542468193195488721590741574481272714198891253064800438184108329627778720");
    mbedtls_mpi_read_string(&pckg->g2.Y,10,"75192750551909937947468929249355987104463312649195251159923289612823008422826");
    mbedtls_mpi_lset(&pckg->g2.Z,1);
    pckg->window = 85;
}


static void init_secp384k1_package(glvpackage * pckg){

    mbedtls_mpi_init(&pckg->beta);
    mbedtls_mpi_init(&pckg->lambda);
    mbedtls_mpi_init(&pckg->a1);
    mbedtls_mpi_init(&pckg->a2);
    mbedtls_mpi_init(&pckg->b1);
    mbedtls_mpi_init(&pckg->b2);
    mbedtls_mpi_init(&pckg->a12b12);
    mbedtls_mpi_init(&pckg->a22b22);
    mbedtls_mpi_init(&pckg->a1a2b1b2);
    mbedtls_ecp_point_init(&pckg->g1);
    mbedtls_ecp_point_init(&pckg->g2);
    mbedtls_mpi_read_string(&pckg->beta,10,"27637671073554685952928814352336503487892936145408050271036471944878042415305815595678036889427268327932408724605390");
    mbedtls_mpi_read_string(&pckg->lambda,10,"9029383845458153580887594847106592614538015099517773642634444564519521376708800974172569052493327610745929520901058");
    mbedtls_mpi_read_string(&pckg->a1,10,"5256164817148179441505043377045145550171016348406569208843");
    mbedtls_mpi_read_string(&pckg->a2,10,"1694134008685082326610872089003789974893466677546126350621");
    mbedtls_mpi_read_string(&pckg->b1,10,"1694134008685082326610872089003789974893466677546126350621");
    pckg->b1.s = -1;
    mbedtls_mpi_read_string(&pckg->b2,10,"6950298825833261768115915466048935525064483025952695559464");
    mbedtls_mpi_read_string(&pckg->a12b12,10,"30497358624409741223156815571125077989076213316372143626019915165114833064176841481899331932505674355983834376484290");
    mbedtls_mpi_read_string(&pckg->a22b22,10,"51176743807762603801453086000435362115415797002204924796437776688228902542597534709581545794693458529899035387052937");
    mbedtls_mpi_read_string(&pckg->a1a2b1b2,10,"2870090039383386600051821371273212494332531777646175086578393910521328751969408543762450668429217503676611427085641");
    pckg->a1a2b1b2.s=-1;
    mbedtls_mpi_read_string(&pckg->g1.X,10,"13350435881144260053110935877525926138455839945158896094870635238271319164533960143452543493890968536432730897075912");
    mbedtls_mpi_read_string(&pckg->g1.Y,10,"2810490595363053396134184311320058541036627779808339698353816426131799190668245878589648502635196218583400013006023");
    mbedtls_mpi_lset(&pckg->g1.Z,1);
    mbedtls_mpi_read_string(&pckg->g2.X,10,"13242228010250538831482496669076134555370992878857295784243463744680427973464379135438385698330134782940128988313150");
    mbedtls_mpi_read_string(&pckg->g2.Y,10,"13227647921482556740271134287547060285218721466279419109582684453018575264580349462815959185057099524219649488042161");
    mbedtls_mpi_lset(&pckg->g2.Z,1);
    pckg->window = 128;
}



static void init_secp521k1_package(glvpackage * pckg){
    mbedtls_mpi_init(&pckg->beta);
    mbedtls_mpi_init(&pckg->lambda);
    mbedtls_mpi_init(&pckg->a1);
    mbedtls_mpi_init(&pckg->a2);
    mbedtls_mpi_init(&pckg->b1);
    mbedtls_mpi_init(&pckg->b2);
    mbedtls_mpi_init(&pckg->a12b12);
    mbedtls_mpi_init(&pckg->a22b22);
    mbedtls_mpi_init(&pckg->a1a2b1b2);
    mbedtls_ecp_point_init(&pckg->g1);
    mbedtls_ecp_point_init(&pckg->g2);
    mbedtls_mpi_read_string(&pckg->beta,10,"2766250995803656133741396920585987521495417076279737819413810565476794069665554448158247282748188520611596258199760380876033019049139192886964099132276417702");
    mbedtls_mpi_read_string(&pckg->lambda,10,"4532168091295951778672694677937080126920418569685070937783661161346905075711953714455092417172881526094153458954915617959112058071378687341124729825623803864");
    mbedtls_mpi_read_string(&pckg->a1,10,"1968663187427730012579589982187102317595963877325717471881175243627143536591213");
    mbedtls_mpi_read_string(&pckg->a2,10,"1005158693013058798593648229699477562617190396350355372398933538128018285425617");
    mbedtls_mpi_read_string(&pckg->b1,10,"1005158693013058798593648229699477562617190396350355372398933538128018285425617");
    pckg->b1.s = -1;
    mbedtls_mpi_read_string(&pckg->b2,10,"2973821880440788811173238211886579880213154273676072844280108781755161822016830");
    mbedtls_mpi_read_string(&pckg->a12b12,10,"4885978743672830207517178292186495130343041411970766960994930560008496219668230466349482739860522324782548894819424454010120948073745162056858861042708642058");
    mbedtls_mpi_read_string(&pckg->a22b22,10,"9853960574728109801299877223529982072423895081588018365668167662095862669553147481244350821612179322160723812632188841246012488157562935689445172923643079589");
    mbedtls_mpi_read_string(&pckg->a1a2b1b2,10,"1010343998139720578853253917553690768228065893272174507874171303733272522426075728318850017187440042645068232033047197418191463812507132689206741994839830689");
    pckg->a1a2b1b2.s=-1;
    mbedtls_mpi_read_string(&pckg->g1.X,10,"6531078016862390245526851865632470985904601559686589827196132264899116154287944462723937106487050613767622183773114886864429626558790394681892471123534895294");
    mbedtls_mpi_read_string(&pckg->g1.Y,10,"5238069597496772969798186276654528136233716042750023995465425195661642480553461093387268172696467835834771716883463234903331027886292073856913791143314363118");
    mbedtls_mpi_lset(&pckg->g1.Z,1);
    mbedtls_mpi_read_string(&pckg->g2.X,10,"789568755642246860219518713224992848582345306081278811894807011291237850880592099294151778271445299245816302876028860361513043002331606587513336878193639958");
    mbedtls_mpi_read_string(&pckg->g2.Y,10,"1409975731973170512344501516116681395851350948205401453097378230801533606943654127887542414359705909350055887182948117203922425497227853615739304648287700707");
    mbedtls_mpi_lset(&pckg->g2.Z,1);
    pckg->window = 174;
}


void init_glvpackage(glvpackage *pckg, mbedtls_ecp_group_id gid){

    if (gid==MBEDTLS_ECP_DP_SECP384K1)
    init_secp384k1_package(pckg);

    if (gid==MBEDTLS_ECP_DP_SECP256K1)
    init_secp256k1_package(pckg);

    if (gid==MBEDTLS_ECP_DP_SECP521K1)
    init_secp521k1_package(pckg);

}



void scalar_decomposition(mbedtls_mpi *m0, mbedtls_mpi *m1, const mbedtls_mpi *m, glvpackage *pckg, const mbedtls_mpi *N){

    mbedtls_mpi c1, c2;
    mbedtls_mpi b1k, b2k, tmp;
    mbedtls_mpi_init(&c1);
    mbedtls_mpi_init(&c2);
    mbedtls_mpi_init(&b1k);
    mbedtls_mpi_init(&b2k);
    mbedtls_mpi_mul_mpi(&b1k,&pckg->b1,m);
    mbedtls_mpi_mul_mpi(&b2k,&pckg->b2,m);

    b1k.s = (-1)*(b1k.s);

    simple_rounded_div(&c1, &b2k,(mbedtls_mpi *) N);
    simple_rounded_div(&c2, &b1k, (mbedtls_mpi *) N);


    mbedtls_mpi_copy(m0, m);
    mbedtls_mpi_init(&tmp);
    mbedtls_mpi_mul_mpi(&tmp,&c1,&pckg->a1);
    mbedtls_mpi_sub_mpi(m0,m0,&tmp);
    mbedtls_mpi_mul_mpi(&tmp,&c2,&pckg->a2);
    mbedtls_mpi_sub_mpi(m0,m0,&tmp);
    mbedtls_mpi_mul_mpi(m1, &c1, &pckg->b1);
    m1->s = (-1)*(m1->s);
    mbedtls_mpi_mul_mpi(&tmp,&c2,&pckg->b2);
    mbedtls_mpi_sub_mpi(m1,m1,&tmp);

}


//=================================================================================================================

int mbedtls_mpi_muladd_mpi(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B, mbedtls_mpi *tmp){
    mbedtls_mpi_mul_mpi(tmp,A,B);
    mbedtls_mpi_add_mpi(X,X,tmp);
}

int mbedtls_mpi_muladd_uint(mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_uint B, mbedtls_mpi *tmp){
    mbedtls_mpi_mul_int(tmp,A,B);
    mbedtls_mpi_add_mpi(X,X,tmp);
}


int mbedtls_mpi_mulsub_uint(mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_uint B, mbedtls_mpi *tmp){
    mbedtls_mpi_mul_int(tmp,A,B);
    mbedtls_mpi_sub_mpi(X,X,tmp);
}


int mbedtls_mpi_muladd_sint(mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_sint B, mbedtls_mpi *tmp){
    if(B>=0){mbedtls_mpi_muladd_uint(X,A,B,tmp);}
    else {mbedtls_mpi_mulsub_uint(X,A,-B,tmp);}

}


static void matrix_init(mbedtls_mpi matrix[3][3]) {
    mpi_init_many(matrix[0], 3);
    mpi_init_many(matrix[1], 3);
    mpi_init_many(matrix[2], 3);
    for (int i = 0; i < 3; i++) for (int j = 0; j < 3; j++)  mbedtls_mpi_lset(&matrix[i][j], 0);
}


static void dot(mbedtls_mpi *r, mbedtls_mpi *u, mbedtls_mpi *v, mbedtls_mpi *tmp) {
    mbedtls_mpi_lset(r, 0);
    for (int i = 0; i < 3; i++) mbedtls_mpi_muladd_mpi(r,&u[i],&v[i], tmp);
}


static void compute_gram_matrix3x3_precomputed(mbedtls_mpi matrix[3][3],
                                        struct GramMatrix *gm, const mbedtls_mpi *n,
                                        struct glvpackage *pkg, mbedtls_mpi *tmp) {

    matrix_init(gm->matrix);
    gm->crop = 0;
    dot(&gm->matrix[0][0], matrix[0], matrix[0], tmp);
    dot(&gm->matrix[0][1], matrix[0], matrix[1], tmp);
    mbedtls_mpi_copy(&gm->matrix[1][0], &gm->matrix[0][1]);
    dot(&gm->matrix[0][2], matrix[0], matrix[2], tmp);
    mbedtls_mpi_copy(&gm->matrix[2][0], &gm->matrix[0][2]);
    mbedtls_mpi_copy(&gm->matrix[1][1], &pkg->a12b12);
    mbedtls_mpi_copy(&gm->matrix[1][2], &pkg->a1a2b1b2);
    mbedtls_mpi_copy(&gm->matrix[2][1], &pkg->a1a2b1b2);
    mbedtls_mpi_copy(&gm->matrix[2][2], &pkg->a22b22);
    gm->p[0] = 0;
    gm->p[1] = 1;
    gm->p[2] = 2;
}

static void compute_gram_sizes_bytes(size_t sizes[3][3], struct GramMatrix *gm) {

    for(int i = 0; i < 3; i++) for(int j = 0; j < 3; j++) sizes[i][j] = mbedtls_mpi_size(&gm->matrix[i][j]);
}


static void recompute_lattice_matrix(mbedtls_mpi bs[3][3], mbedtls_mpi bsc[3][3],
                              mbedtls_mpi bso[3][3], mbedtls_mpi *tmp) {
    for (int l = 0; l < 3; l++) 
        for (int k = 0; k < 3; k++) 
            for (int i = 0; i < 3; i++)
                mbedtls_mpi_muladd_mpi(&bs[l][i],&bsc[l][k], &bso[k][i], tmp);
            
}

static void vector_size_max(mbedtls_mpi *size, mbedtls_mpi vector[3]) {
    mbedtls_mpi max, tmp;
    mbedtls_mpi_init(&max);
    mbedtls_mpi_init(&tmp);

    mbedtls_mpi_copy(&max, &vector[0]);
    max.s = 1;
    for (int i = 0; i < 3; i++) {
        mbedtls_mpi_copy(&tmp, &vector[i]);
        tmp.s = 1;
        if (mbedtls_mpi_cmp_mpi(&max, &tmp) < 0)
            mbedtls_mpi_copy(&max, &tmp);
    }
    mbedtls_mpi_copy(size, &max);
}


static void smallest_vector(mbedtls_mpi matrix[3][3], mbedtls_mpi smallest[3]) {
    int index = 0;
    mbedtls_mpi size, cursize;
    mbedtls_mpi_init(&size);
    mbedtls_mpi_init(&cursize);
    vector_size_max(&size, matrix[0]);
    for (int l = 0; l < 3; l++) {
        vector_size_max(&cursize, matrix[l]);
        if (mbedtls_mpi_cmp_mpi(&cursize, &size) <= 0) {
            index = l;
            mbedtls_mpi_copy(&size, &cursize);
        }
    }
    for (int l = 0; l < 3; l++) {
        mbedtls_mpi_copy(&smallest[l], &matrix[index][l]);
    }
}


static void switch_columns(struct GramMatrix *gm, int i, int j) {
    int tmp = gm->p[i];
    gm->p[i] = gm->p[j];
    gm->p[j] = tmp;
}

static int sort_pair(struct GramMatrix *gm, int i, int j){
    if (mbedtls_mpi_cmp_mpi(&gm->matrix[gm->p[i]][gm->p[i]],
                &gm->matrix[gm->p[j]][gm->p[j]]) > 0){
            switch_columns(gm, i, j);
            return 1;
                }
    return 0;
}

static void sort_basis(struct GramMatrix *gm){
    sort_pair(gm,0,1);
    if(sort_pair(gm,1,2)) sort_pair(gm,0,1);
}


mbedtls_mpi_sint fast_rounded_div(mbedtls_mpi *a, mbedtls_mpi *b, size_t size_a, size_t size_b) {

    // printf_mpi(a);
    // printf_mpi(b);
    // printf("%u,%u\n",size_a,size_b);
    size_t pos_a = 0;
    size_t pos_b = 0;
    if (size_a > WORDBYTES) {
        pos_a = size_a - WORDBYTES;
        size_a = WORDBYTES;
    }
    if (size_b > WORDBYTES) {
        pos_b = size_b - WORDBYTES;
        size_b = WORDBYTES;
    }


    int sgn = a->s;
    mbedtls_mpi_uint la = *((mbedtls_mpi_uint *)((char *)a->p + pos_a));
    mbedtls_mpi_uint lb = *((mbedtls_mpi_uint *)((char *)b->p + pos_b));

    size_t d;
    if (pos_a > pos_b){
        d = pos_a - pos_b;
        lb = lb >> (d * 8);
        size_b -= d;
    }
    else{
        d = pos_b - pos_a;
        la = la >> (d * 8);
        size_a -= d;

    }

    size_t min = size_a > size_b ? size_b : size_a;
    min *= 8;
    if(min>DIV_PRECISION_BITS)
        min = min - DIV_PRECISION_BITS;
    else
        min = 0;
    la >>= min;
    lb >>= min;
    float flq = la / (float)lb;
    mbedtls_mpi_sint lq = (mbedtls_mpi_sint)flq;
    if ((flq - lq) > 0.5)
        lq += 1;
    return lq * sgn;
}



static mbedtls_mpi_sint fast_rounded_div2(mbedtls_mpi *a, mbedtls_mpi *b, size_t size_a, size_t size_b) {


    size_t pos_a = 0;
    size_t pos_b = 0;
    if (size_a > WORDBYTES) {
        pos_a = size_a - WORDBYTES;
        size_a = WORDBYTES;
    }
    if (size_b > WORDBYTES) {
        pos_b = size_b - WORDBYTES;
        size_b = WORDBYTES;
    }


    int sgn = a->s;
    mbedtls_mpi_uint la = *((mbedtls_mpi_uint *)((char *)a->p + pos_a));
    mbedtls_mpi_uint lb = *((mbedtls_mpi_uint *)((char *)b->p + pos_b));

    size_t d = pos_a - pos_b;
    size_t min = 0;
    if (d > 0) {
        lb = lb >> (d * 8);
        size_b -= d;
    }

    if (d < 0) {
        la = la >> (-d * 8);
        size_a -= -d;
    }
    min = size_a > size_b ? size_b : size_a;
    min = 8 * min - DIV_PRECISION_BITS;
    la >>= min;
    lb >>= min;

    float flq = la / (float)lb;
    mbedtls_mpi_sint lq = (mbedtls_mpi_sint)flq;
    if ((flq - lq) > 0.5)
        lq += 1;
    return lq * sgn;
}


static mbedtls_mpi_sint slow_rounded_div(mbedtls_mpi *a0, const mbedtls_mpi *b0) {

    mbedtls_mpi b, a;
    mbedtls_mpi r, q;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&q);


    int sgn = (a0->s) * (b0->s);
    mbedtls_mpi_copy(&a,a0);
    mbedtls_mpi_copy(&b,b0);
    b.s = 1;
    a.s = 1;

    mbedtls_mpi_div_mpi(&q, &r, &a, &b);
    mbedtls_mpi_sint lq = q.p[q.n-1];
    mbedtls_mpi_shift_l(&r, 1);
    if (mbedtls_mpi_cmp_mpi(&r, &b) > 0) {
        lq+=1;
    }
    if (sgn < 0) {
        lq=-lq;
    }
    return lq;
}

static mbedtls_mpi_sint compute_m(struct GramMatrix *gm, int i, int j, size_t sizes[3][3]) {

    // return slow_rounded_div(&gm->matrix[gm->p[i]][gm->p[j]], &gm->matrix[gm->p[i]][gm->p[i]]);

    return fast_rounded_div(&gm->matrix[gm->p[i]][gm->p[j]], &gm->matrix[gm->p[i]][gm->p[i]], sizes[gm->p[i]][gm->p[j]],sizes[gm->p[i]][gm->p[i]]);
}

static void apply_m3x3(struct GramMatrix *gm, mbedtls_mpi_sint m, int i, int j, mbedtls_mpi *tmp) {
    if (m > 0) {
        for (int l = 0; l < 3; l++) mbedtls_mpi_mulsub_uint(&gm->matrix[gm->p[j]][gm->p[l]],&gm->matrix[gm->p[i]][gm->p[l]],m, tmp);
        for (int l = 0; l < 3; l++) mbedtls_mpi_copy(&gm->matrix[gm->p[l]][gm->p[j]],&gm->matrix[gm->p[j]][gm->p[l]]);
        mbedtls_mpi_mulsub_uint(&gm->matrix[gm->p[j]][gm->p[j]],&gm->matrix[gm->p[j]][gm->p[i]],m, tmp);
    } else {
        for (int l = 0; l < 3; l++) mbedtls_mpi_muladd_uint(&gm->matrix[gm->p[j]][gm->p[l]],&gm->matrix[gm->p[i]][gm->p[l]],-m, tmp);
        for (int l = 0; l < 3; l++) mbedtls_mpi_copy(&gm->matrix[gm->p[l]][gm->p[j]], &gm->matrix[gm->p[j]][gm->p[l]]);
        mbedtls_mpi_muladd_uint(&gm->matrix[gm->p[j]][gm->p[j]],&gm->matrix[gm->p[j]][gm->p[i]],-m, tmp);
    }
}



static void update_gram_sizes_bytes(size_t sizes[3][3], struct GramMatrix *gm, int j) {
    for (int i = 0; i < 3; i++) {
        sizes[i][gm->p[j]] = mbedtls_mpi_size(&gm->matrix[i][gm->p[j]]);
        sizes[gm->p[j]][i] = sizes[i][gm->p[j]];
    }
}


static void mchange(struct GramMatrix *gm, mbedtls_mpi_sint m, mbedtls_mpi bsc[3][3], int i, int j,
             size_t sizes[3][3], mbedtls_mpi *tmp) {

    if (m > 0)
        for (int l = 0; l < 3; l++) mbedtls_mpi_mulsub_uint(&bsc[gm->p[j]][l],&bsc[gm->p[i]][l],m, tmp);
    else
        for (int l = 0; l < 3; l++) mbedtls_mpi_muladd_uint(&bsc[gm->p[j]][l],&bsc[gm->p[i]][l],-m,tmp);
    apply_m3x3(gm, m, i, j, tmp);
    update_gram_sizes_bytes(sizes, gm, j);
}


static int gauss_reduction(struct GramMatrix *gm, mbedtls_mpi bsc[3][3], int i, int j,
                    int changes[3][3], size_t sizes[3][3], mbedtls_mpi *tmp) {
    mbedtls_mpi_sint m;
    int change = 0;
    if (mbedtls_mpi_cmp_mpi(&gm->matrix[gm->p[j]][gm->p[j]],
                &gm->matrix[gm->p[i]][gm->p[i]]) < 0)
        switch_columns(gm, i, j);

    while (1) {
        m = compute_m(gm, i, j, sizes);
        // printf("m=%d\n",m);
        if (m == 0) return change;
        mchange(gm, m, bsc, i, j, sizes, tmp);
        change = 1;
        for (int l = 0; l < 3; l++) {
            changes[l][gm->p[j]] = 1;
            changes[gm->p[j]][l] = 1;
        }
        switch_columns(gm, i, j);
    }
}



static void greedy_gauss_prec(mbedtls_mpi bso[3][3], mbedtls_mpi smallest[3], const mbedtls_mpi *n,
                       struct glvpackage *pkg) {

    mbedtls_mpi bsc[3][3], bs[3][3];

    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    size_t sizes[3][3];

    matrix_init(bs); 
    matrix_init(bsc); 
    for (int i = 0; i < 3; i++)
        mbedtls_mpi_lset(&bsc[i][i], 1);

    struct GramMatrix gm;
    compute_gram_matrix3x3_precomputed(bso, &gm, n, pkg, &tmp);
    compute_gram_sizes_bytes(sizes, &gm);

    int change;
    int counter = 1;
    int chs[3][3] = {{1, 1, 1}, {1, 0, 0}, {1, 0, 0}};

    while (1) {
        change = 0;
        for (int i = 0; i < 2; i++) {
            for (int j = i + 1; j < 3; j++) {
                if (chs[gm.p[i]][gm.p[j]] == 0)
                    continue;
                change += gauss_reduction(&gm, bsc, i, j, chs, sizes, &tmp); 
                chs[gm.p[i]][gm.p[j]] = 0;
                chs[gm.p[j]][gm.p[i]] = 0;
                counter += 1;
            }
        }
        if (change == 0)
            break;
    }

    recompute_lattice_matrix(bs, bsc, bso, &tmp);
    smallest_vector(bs, smallest);


}


void small_3(struct glvpackage *pkg, const mbedtls_mpi *k, const mbedtls_mpi* N, mbedtls_mpi result[3]) {

    // printf_mpi(k);
    // printf_mpi(N);
    mbedtls_mpi k0, k1, u0, u1, u, v;
    mbedtls_mpi_init(&k0);
    mbedtls_mpi_init(&k1);
    mbedtls_mpi_init(&u0);
    mbedtls_mpi_init(&u1);
    mbedtls_mpi_init(&u);
    mbedtls_mpi_init(&v);

    scalar_decomposition(&k0, &k1, k, pkg, N);
    // printf_mpi(&k0);
    // printf_mpi(&k1);

    mbedtls_mpi bso[3][3];
    mpi_init_many(bso[0], sizeof(bso[0]) / sizeof(mbedtls_mpi));
    mpi_init_many(bso[1], sizeof(bso[1]) / sizeof(mbedtls_mpi));
    mpi_init_many(bso[2], sizeof(bso[2]) / sizeof(mbedtls_mpi));
    
    mbedtls_mpi_copy(&bso[0][0], &k0);
    mbedtls_mpi_copy(&bso[0][1], &k1);
    mbedtls_mpi_lset(&bso[0][2], -1);

    mbedtls_mpi_copy(&bso[1][0], &pkg->a1);
    mbedtls_mpi_copy(&bso[1][1], &pkg->b1);
    mbedtls_mpi_lset(&bso[1][2], 0);
    mbedtls_mpi_copy(&bso[2][0], &pkg->a2);
    mbedtls_mpi_copy(&bso[2][1], &pkg->b2);
    mbedtls_mpi_lset(&bso[2][2], 0);

    greedy_gauss_prec(bso, result, N, pkg);
    // printf_mpi(&result[0]);
    // printf_mpi(&result[1]);
    // printf_mpi(&result[2]);


}



static int gauss_reduction01(struct GramMatrix *gm, mbedtls_mpi bsc[3][3], size_t sizes[3][3], mbedtls_mpi *tmp) {
    mbedtls_mpi_sint m;
    int change = 0;
    while (1) {
        m = compute_m(gm, 0, 1, sizes);
        if (m == 0) return change;
        mchange(gm, m, bsc, 0, 1, sizes, tmp);
        change = 1;
        switch_columns(gm, 0, 1);
    }
}


void compute_ys(struct GramMatrix *gm, mbedtls_mpi_sint *y1, mbedtls_mpi_sint *y2, size_t sizes[3][3]){
    size_t mins = sizes[gm->p[0]][gm->p[0]];
    mins = mins < sizes[gm->p[1]][gm->p[1]] ? mins : sizes[gm->p[1]][gm->p[1]];
    mins = mins < sizes[gm->p[0]][gm->p[1]] ? mins : sizes[gm->p[0]][gm->p[1]];
    mins = mins < sizes[gm->p[0]][gm->p[2]] ? mins : sizes[gm->p[0]][gm->p[2]];
    mins = mins < sizes[gm->p[1]][gm->p[2]] ? mins : sizes[gm->p[1]][gm->p[2]];
    if(mins>0) {
        mins-=1;
    }
    // printf("mins: %u\n",mins);
    mbedtls_mpi_uint b1 = *((mbedtls_mpi_uint *)((char *)(&gm->matrix[gm->p[0]][gm->p[0]])->p + mins));
    mbedtls_mpi_uint b2 = *((mbedtls_mpi_uint *)((char *)(&gm->matrix[gm->p[1]][gm->p[1]])->p + mins));
    int s0 = (&gm->matrix[gm->p[0]][gm->p[1]])->s;
    int s1 = (&gm->matrix[gm->p[0]][gm->p[2]])->s;
    int s2 = (&gm->matrix[gm->p[1]][gm->p[2]])->s;

    mbedtls_mpi_uint b12 = *((mbedtls_mpi_uint *)((char *)(&gm->matrix[gm->p[0]][gm->p[1]])->p + mins));
    mbedtls_mpi_uint b13 = *((mbedtls_mpi_uint *)((char *)(&gm->matrix[gm->p[0]][gm->p[2]])->p + mins));
    mbedtls_mpi_uint b23 = *((mbedtls_mpi_uint *)((char *)(&gm->matrix[gm->p[1]][gm->p[2]])->p + mins));
    // printf("%lu,%lu,%lu,%lu,%lu, %d, %d, %d, %lu\n",b1,b2,b12,b13,b23,s0,s1,s2,mins);
    mbedtls_mpi_sint num = b1*b23*s2-b12*b13*s0*s1;
    mbedtls_mpi_sint den = b1*b2-b12*b12;
    float fy2 = -num/(float)den;
    *y2 = (mbedtls_mpi_sint) fy2;
    if((fy2<0) && (*y2!=fy2)) *y2-=1;
    // printf("numden %ld %ld %ld\n", num,den,*y2);

    num = b2*b13*s1-b12*s0*b23*s2;
    float fy1 = -num/(float)den;
    *y1 = (mbedtls_mpi_sint) fy1;
    if((fy1<0) && (*y1!=fy1)) *y1-=1;

    // printf("%ld %ld %ld %ld\n", *y1,*y2, num,den);

}

mbedtls_mpi_uint mycut(mbedtls_mpi *num, size_t mins){
    mbedtls_mpi_uint b1;
    if((num->n-1)*sizeof(mbedtls_mpi_uint)<mins){
        b1= *((mbedtls_mpi_uint *)(num->p + (num->n-1)));
        return b1>> mins*8-8*(num->n-1)*sizeof(mbedtls_mpi_uint);
    }
    else return *((mbedtls_mpi_uint *)(((char *)num->p) + mins));

}

float bytedivision(mbedtls_mpi *num,  mbedtls_mpi *den, size_t s1, size_t s2){

    if(mbedtls_mpi_cmp_int(num,0)==0) return 0;
    size_t mins = s1 > s2 ? s2 : s1;
    int sign = (num->s)*(den->s);
    mbedtls_mpi_uint b1,b2;
    if(mins>2) {
        mins-=2;
    }
    b1 = mycut(num,mins);
    b2 = mycut(den,mins);
    return sign*(b1/(float) b2);
}

float bytedoubledivision(mbedtls_mpi *num1, mbedtls_mpi *num2,  mbedtls_mpi *den1, mbedtls_mpi *den2, size_t s1, size_t s2, size_t s3, size_t s4){

    if((mbedtls_mpi_cmp_int(num1,0)==0)||(mbedtls_mpi_cmp_int(num2,0)==0)) return 0;
    size_t mins = s1 > s2 ? s2 : s1;
    
    mins = s3 > mins ? mins : s3;
    mins = s4 > mins ? mins : s4;
    if(mins>2) {
        mins-=2;
    }
    mbedtls_mpi_uint b1,b2,b3,b4;
    b1 = mycut(num1,mins);
    b2 = mycut(den1,mins);
    b3 = mycut(num2,mins);
    b4 = mycut(den2,mins);
    // printf("doublediv: %lu, %lu, %lu, %lu\n",b1,b2,b3,b4);  
    int sign = (num1->s)*(num2->s)*(den1->s)*(den2->s);
    float result = b1/(float)b2;
    result*= b3/(float)b4;
    result*=sign;
    // printf("result: %f\n",result);
    return result;
}

void mydiv(mbedtls_mpi *Q, mbedtls_mpi *R,mbedtls_mpi *A, mbedtls_mpi *B){
    // assumes that B is positive
    if(A->s!=-1){
    mbedtls_mpi_div_mpi(Q,R,A,B);
    return;}
    A->s=1;
    mbedtls_mpi_div_mpi(Q,R,A,B);
    A->s=-1;
    Q->s=-1;
    if(mbedtls_mpi_cmp_int(R,0)!=0){
        mbedtls_mpi_sub_int(Q,Q,1);
        mbedtls_mpi_sub_mpi(R,B,R);
    }

}


void compute_ys2(struct GramMatrix *gm, mbedtls_mpi_sint *y1, mbedtls_mpi_sint *y2, size_t sizes[3][3]){
    
    mbedtls_mpi r1,s1,r2,s2,r3,s3,tmp;
    mbedtls_mpi_init(&r1);
    mbedtls_mpi_init(&s1);
    mbedtls_mpi_init(&r2);
    mbedtls_mpi_init(&s2);
    mbedtls_mpi_init(&r3);
    mbedtls_mpi_init(&s3);
    mbedtls_mpi_init(&tmp);
    float delta;
    mydiv(&r1,&s1,&gm->matrix[gm->p[0]][gm->p[2]],&gm->matrix[gm->p[0]][gm->p[0]]);
    mydiv(&r2,&s2,&gm->matrix[gm->p[1]][gm->p[2]],&gm->matrix[gm->p[1]][gm->p[1]]);
    mbedtls_mpi_mul_mpi(&tmp,&gm->matrix[gm->p[0]][gm->p[1]],&r2);
    mydiv(&r3,&s3,&tmp,&gm->matrix[gm->p[0]][gm->p[0]]);
    delta = bytedivision(&s1,&gm->matrix[gm->p[0]][gm->p[0]], mbedtls_mpi_size(&s1),sizes[gm->p[0]][gm->p[0]]);
    delta -= bytedivision(&s3,&gm->matrix[gm->p[0]][gm->p[0]], mbedtls_mpi_size(&s3),sizes[gm->p[0]][gm->p[0]]);
    delta -= bytedoubledivision(&gm->matrix[gm->p[0]][gm->p[1]],&s2,&gm->matrix[gm->p[0]][gm->p[0]],&gm->matrix[gm->p[1]][gm->p[1]],sizes[gm->p[0]][gm->p[1]],mbedtls_mpi_size(&s2),sizes[gm->p[0]][gm->p[0]],sizes[gm->p[1]][gm->p[1]]);
    float y1num = (r1.s)*((mbedtls_mpi_sint)(r1.p[0])) - (r3.s)*((mbedtls_mpi_sint)(r3.p[0])) + delta;
    
    mbedtls_mpi_mul_mpi(&tmp,&gm->matrix[gm->p[0]][gm->p[1]],&r1);
    mydiv(&r3,&s3,&tmp,&gm->matrix[gm->p[1]][gm->p[1]]);
    delta = bytedivision(&s2,&gm->matrix[gm->p[1]][gm->p[1]], mbedtls_mpi_size(&s2),sizes[gm->p[1]][gm->p[1]]);
    delta -= bytedivision(&s3,&gm->matrix[gm->p[1]][gm->p[1]], mbedtls_mpi_size(&s3),sizes[gm->p[1]][gm->p[1]]);
    delta -= bytedoubledivision(&gm->matrix[gm->p[0]][gm->p[1]],&s1,&gm->matrix[gm->p[0]][gm->p[0]],&gm->matrix[gm->p[1]][gm->p[1]],sizes[gm->p[0]][gm->p[1]], mbedtls_mpi_size(&s1),sizes[gm->p[0]][gm->p[0]], sizes[gm->p[1]][gm->p[1]]);
    float y2num = (r2.s)*((mbedtls_mpi_sint)(r2.p[0])) - (r3.s)*((mbedtls_mpi_sint)(r3.p[0])) + delta;
    // printf("y2num: %f\n",y2num);

    mydiv(&r1,&s1,&gm->matrix[gm->p[0]][gm->p[1]],&gm->matrix[gm->p[0]][gm->p[0]]);
    mbedtls_mpi_mul_mpi(&tmp,&gm->matrix[gm->p[0]][gm->p[1]],&r1);
    mydiv(&r2,&s2,&tmp,&gm->matrix[gm->p[1]][gm->p[1]]);    
    delta = bytedivision(&s2,&gm->matrix[gm->p[1]][gm->p[1]], mbedtls_mpi_size(&s2),sizes[gm->p[1]][gm->p[1]]);
    delta -= bytedoubledivision(&gm->matrix[gm->p[0]][gm->p[1]],&s1,&gm->matrix[gm->p[0]][gm->p[0]],&gm->matrix[gm->p[1]][gm->p[1]], sizes[gm->p[0]][gm->p[1]], mbedtls_mpi_size(&s1),sizes[gm->p[0]][gm->p[0]], sizes[gm->p[1]][gm->p[1]]);
    float den = delta-(r2.s)*((mbedtls_mpi_sint)(r2.p[0]))+1;
    // printf("den: %f\n",den);

    float fy2 = -y2num/den;
    *y2 = (mbedtls_mpi_sint) fy2;
    if((fy2<0) && (*y2!=fy2)) *y2-=1;

    float fy1 = -y1num/den;
    *y1 = (mbedtls_mpi_sint) fy1;
    if((fy1<0) && (*y1!=fy1)) *y1-=1;

}



static void compute_asize(mbedtls_mpi *asize, struct GramMatrix *gm, mbedtls_mpi_sint x1, mbedtls_mpi_sint x2, mbedtls_mpi *tmp){

       mbedtls_mpi_copy(asize, &gm->matrix[gm->p[2]][gm->p[2]]);

       mbedtls_mpi_muladd_sint(asize,&gm->matrix[gm->p[1]][gm->p[2]],2*x2,tmp);  

       mbedtls_mpi_muladd_sint(asize,&gm->matrix[gm->p[0]][gm->p[2]],2*x1,tmp); 

       mbedtls_mpi_muladd_sint(asize,&gm->matrix[gm->p[1]][gm->p[1]],x2*x2,tmp); 

       mbedtls_mpi_muladd_sint(asize,&gm->matrix[gm->p[0]][gm->p[1]],2*x1*x2,tmp); 

       mbedtls_mpi_muladd_sint(asize,&gm->matrix[gm->p[0]][gm->p[0]],x1*x1,tmp); 

    
}

static void x12change(struct GramMatrix *gm, mbedtls_mpi bsc[3][3], mbedtls_mpi_sint x1, mbedtls_mpi_sint x2,
             size_t sizes[3][3], mbedtls_mpi *tmp){
    mchange(gm, -x2, bsc, 1, 2, sizes, tmp);
    mchange(gm, -x1, bsc, 0, 2, sizes, tmp);

}

static int semaev_reduction(struct GramMatrix *gm, mbedtls_mpi bsc[3][3], size_t sizes[3][3], mbedtls_mpi *tmp) {
    
    gauss_reduction01(gm,bsc,sizes,tmp);
    // printf("--\n");
    // print_gram_matrix(gm);
    mbedtls_mpi_sint y1,y2,t1,t2,x1,x2;
    compute_ys(gm,&y1,&y2,sizes); 
    // printf("ys: %ld %ld\n",y1,y2);

    mbedtls_mpi asize, smallest_asize;
    mbedtls_mpi_init(&asize);
    mbedtls_mpi_init(&smallest_asize);
    mbedtls_mpi_lset(&smallest_asize,0);

    for(int i=0;i<2;i++){
        for(int j=0;j<2;j++){
            t1 = y1+i;
            t2 = y2+j;
            compute_asize(&asize, gm,t1,t2, tmp);
            // printf_mpi(&asize);
            if((mbedtls_mpi_cmp_int(&smallest_asize,0)==0) || (mbedtls_mpi_cmp_mpi(&smallest_asize,&asize)>0)){
                x1 = t1;
                x2 = t2;
                // printf("ij: %d %d\n",i,j);
                mbedtls_mpi_copy(&smallest_asize,&asize);
            }
        }
    }

    if(mbedtls_mpi_cmp_mpi(&smallest_asize,&gm->matrix[gm->p[2]][gm->p[2]] )>=0) return 0;
    x12change(gm,bsc,x1,x2,sizes,tmp);
    return 1;
}




static void semaev(mbedtls_mpi bso[3][3], mbedtls_mpi smallest[3], const mbedtls_mpi *n,
                       struct glvpackage *pkg) {

    mbedtls_mpi bsc[3][3], bs[3][3];

    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    size_t sizes[3][3];

    matrix_init(bs); 
    matrix_init(bsc); 
    for (int i = 0; i < 3; i++)
        mbedtls_mpi_lset(&bsc[i][i], 1);

    struct GramMatrix gm;
    compute_gram_matrix3x3_precomputed(bso, &gm, n, pkg, &tmp);
    compute_gram_sizes_bytes(sizes, &gm);

    int change;
    int counter = 1;

    // print_gram_matrix(&gm);
    while (1) {
        sort_basis(&gm);
        if(!semaev_reduction(&gm, bsc, sizes, &tmp)) break;
            // print_gram_matrix(&gm);

    }

    recompute_lattice_matrix(bs, bsc, bso, &tmp);
    smallest_vector(bs, smallest);


}





void small_3_semaev(struct glvpackage *pkg, const mbedtls_mpi *k, const mbedtls_mpi* N, mbedtls_mpi result[3]) {

    mbedtls_mpi k0, k1, u0, u1, u, v;
    mbedtls_mpi_init(&k0);
    mbedtls_mpi_init(&k1);
    mbedtls_mpi_init(&u0);
    mbedtls_mpi_init(&u1);
    mbedtls_mpi_init(&u);
    mbedtls_mpi_init(&v);

    scalar_decomposition(&k0, &k1, k, pkg, N);

    mbedtls_mpi bso[3][3];
    mpi_init_many(bso[0], sizeof(bso[0]) / sizeof(mbedtls_mpi));
    mpi_init_many(bso[1], sizeof(bso[1]) / sizeof(mbedtls_mpi));
    mpi_init_many(bso[2], sizeof(bso[2]) / sizeof(mbedtls_mpi));
    
    mbedtls_mpi_copy(&bso[0][0], &k0);
    mbedtls_mpi_copy(&bso[0][1], &k1);
    mbedtls_mpi_lset(&bso[0][2], -1);

    mbedtls_mpi_copy(&bso[1][0], &pkg->a1);
    mbedtls_mpi_copy(&bso[1][1], &pkg->b1);
    mbedtls_mpi_lset(&bso[1][2], 0);
    mbedtls_mpi_copy(&bso[2][0], &pkg->a2);
    mbedtls_mpi_copy(&bso[2][1], &pkg->b2);
    mbedtls_mpi_lset(&bso[2][2], 0);

    semaev(bso, result, N, pkg);


}

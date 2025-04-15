from utils import Cost
from sage.all import *
from lattice import init_package, small_3, scalar_decomposition


def doubleandadd(scalar, point, curve, cost):
    if scalar == 1:
        return point
    Q = curve(0)
    for b in bin(scalar)[2:]:
        if Q != curve(0):
            cost.doubles += 1
        Q *= 2

        if b == "1":
            if Q != curve(0):
                cost.adds += 1
            Q += point
    return Q


def bos_coster(scalars_points, curve, cost):
    scalars_points = [(i, P) if i > 0 else (-i, -P) for i, P in scalars_points]
    # print([i[0] for i in  scalars_points])
    while True:
        scalars_points = [
            i for i in sorted(scalars_points, key=lambda x: x[0]) if i[0] != 0
        ]
        if len(scalars_points) == 1:
            return doubleandadd(*scalars_points[0], curve, cost)
        (k2, P2), (k1, P1) = scalars_points[-2:]
        q, r = k1 // k2, k1 % k2
        # r = k1-k2
        cost.integer_divide(k1, k2)
        scalars_points = scalars_points[:-2]
        newP2 = doubleandadd(q, P1, curve, cost) + P2
        # newP2 = P2+P1
        cost.adds += 1
        scalars_points.append((k2, newP2))
        scalars_points.append((r, P1))
        # k2, q*k2+r
        # k2, r
        # P2+q*P1


def generate_equations(curve, n, G, batch=64, randomized=True, fixed_Q=False):
    equations = []
    Q = curve.random_point()
    for _ in range(batch):
        if not fixed_Q:
            Q = curve.random_point()
        u, v = randint(1, n), randint(1, n)
        z = randint(1, n)
        R = u * G + v * Q
        equations.append([((z * u) % n, G), ((z * v) % n, Q), ((-z) % n, R)])
    return equations


def simple_list(equations, n):
    simple = []
    us = 0
    for eq in equations:
        (u, G), (v, Q), (z, R) = eq
        us = (us + u) % n
        simple.extend([(v, Q), (z, R)])
    simple.append((us, G))
    return simple


def simple_list_fixedQ(equations, n):
    simple = []
    us = 0
    vs = 0
    for eq in equations:
        (u, G), (v, Q), (z, R) = eq
        us = (us + u) % n
        vs = (vs + v) % n
        simple.append((z, R))
    simple.append((us, G))
    simple.append((vs, Q))
    return simple


def glv_list_fixedQ(equations, curve, bits, n):
    glv = []
    pckg = init_package(bits)
    us = 0
    vs = 0
    for eq in equations:
        (u, G), (v, Q), (z, R) = eq
        z0, z1 = scalar_decomposition(z, pckg, n)
        us = (us + u) % n
        vs = (vs + v) % n
        glv.extend([(z0, R), (z1, pckg["lambda"] * R)])
    u0, u1 = scalar_decomposition(us, pckg, n)
    v0, v1 = scalar_decomposition(vs, pckg, n)
    glv.extend([(u0, G), (u1, pckg["lambda"] * G), (v0, Q), (v1, pckg["lambda"] * Q)])
    return glv


def glv_list(equations, curve, bits, n):
    glv = []
    pckg = init_package(bits)
    us = 0
    for eq in equations:
        (u, G), (v, Q), (z, R) = eq
        z0, z1 = scalar_decomposition(z, pckg, n)
        v0, v1 = scalar_decomposition(v, pckg, n)
        us = (us + u) % n
        glv.extend([(v0, Q), (v1, pckg["lambda"] * Q)])
        glv.extend([(z0, R), (z1, pckg["lambda"] * R)])
    u0, u1 = scalar_decomposition(us, pckg, n)
    glv.extend([(u0, G), (u1, pckg["lambda"] * G)])
    return glv


def glv3_list_fixedQ(equations, curve, bits, n, cost):
    glv3 = []
    pckg = init_package(bits)
    us = 0
    vs = 0
    for eq in equations:
        (u, G), (v, Q), (z, R) = eq
        l0, l1, l2 = small_3(pckg, z, n)
        l0 = -l0
        l1 = -l1
        u = (u * l2) % n
        v = (v * l2) % n
        us = (us + u) % n
        vs = (vs + v) % n
        glv3.extend([(l0, R), (l1, pckg["lambda"] * R)])

    Q1 = doubleandadd(1 << pckg["w"], Q, curve, cost)
    Q2 = doubleandadd(1 << pckg["w"], Q1, curve, cost)

    u0 = us % (1 << pckg["w"])
    us >>= pckg["w"]
    u1 = us % (1 << pckg["w"])
    u2 = us >> pckg["w"]
    G1 = curve(pckg["g1x"], pckg["g1y"])
    G2 = curve(pckg["g2x"], pckg["g2y"])
    glv3.extend([(u0, G), (u1, G1), (u2, G2)])

    v0 = vs % (1 << pckg["w"])
    vs >>= pckg["w"]
    v1 = vs % (1 << pckg["w"])
    v2 = vs >> pckg["w"]
    glv3.extend([(v0, Q), (v1, Q1), (v2, Q2)])
    return glv3


def glv3_list(equations, curve, bits, n):
    pckg = init_package(bits)
    us = 0
    smallpart = []
    bigpart = []
    for eq in equations:
        (u, G), (v, Q), (z, R) = eq
        l0, l1, l2 = small_3(pckg, z, n)
        l0 = -l0
        l1 = -l1
        u = (u * l2) % n
        v = (v * l2) % n
        v0, v1 = scalar_decomposition(v, pckg, n)
        us = (us + u) % n
        smallpart.extend([(l0, R), (l1, pckg["lambda"] * R)])
        bigpart.extend([(v0, Q), (v1, pckg["lambda"] * Q)])

    u0 = us % (1 << pckg["w"])
    us >>= pckg["w"]
    u1 = us % (1 << pckg["w"])
    u2 = us >> pckg["w"]
    G1 = curve(pckg["g1x"], pckg["g1y"])
    G2 = curve(pckg["g2x"], pckg["g2y"])
    smallpart.extend([(u0, G), (u1, G1), (u2, G2)])
    return smallpart + bigpart


def experiments(bits):

    if bits == 256:
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        a = 0
        b = 7
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    if bits == 384:
        p = 39402006196394479212279040100143613805079739270465446667948293404245721771497210611414266254884915640806627990135879
        a = 0
        b = 7
        x = 31756387889458008844685268121261518364384865652017503172184556495607902758853682931817969763810726094634169895647739
        y = 10742387381063107083643297287912244794518957335831377345825834664378938820050100246731573620020781426890829093746583
        n = 39402006196394479212279040100143613805079739270465446667939648971411203427402483823859213529384957691103129168225793

    if bits == 521:
        p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291114553523
        a = 0
        b = 7
        x = 4352601156213339664857652289293872863780585532928599735312888289441041770498573902662584972033920369163583403049956166819419910565820072840133634677669470275
        y = 821819758799775147194175046572677140611946852952272272074263771716786660459190141049882875239373171263080517921999257539198458196843925754528053415200824207
        n = 6864797660130609714981900799081393217269435300143305409394463459185543183397651109637491772142630802149102237709283048918970986209400482528548645985755945479

    curve = EllipticCurve(GF(p), [a, b])
    G = curve(x, y)
    cost_simple = Cost()
    cost_glv = Cost()
    cost_glv3 = Cost()
    for _ in range(10):
        equations = generate_equations(curve, n, G)

        simplelist = simple_list(equations, n)
        result = bos_coster(simplelist, curve, cost_simple)
        assert result == curve(0)

        glvlist = glv_list(equations, curve, bits, n)
        result = bos_coster(glvlist, curve, cost_glv)
        assert result == curve(0)

        glv3list = glv3_list(equations, curve, bits, n)
        result = bos_coster(glv3list, curve, cost_glv3)
        assert result == curve(0)

    print(cost_simple.adds, cost_simple.doubles, cost_simple.integer_divisions)
    print(cost_glv.adds, cost_glv.doubles, cost_glv.integer_divisions)
    print(cost_glv3.adds, cost_glv3.doubles, cost_glv3.integer_divisions)


def experiments_fixedQ(bits):

    if bits == 256:
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        a = 0
        b = 7
        x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    if bits == 384:
        p = 39402006196394479212279040100143613805079739270465446667948293404245721771497210611414266254884915640806627990135879
        a = 0
        b = 7
        x = 31756387889458008844685268121261518364384865652017503172184556495607902758853682931817969763810726094634169895647739
        y = 10742387381063107083643297287912244794518957335831377345825834664378938820050100246731573620020781426890829093746583
        n = 39402006196394479212279040100143613805079739270465446667939648971411203427402483823859213529384957691103129168225793

    if bits == 521:
        p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291114553523
        a = 0
        b = 7
        x = 4352601156213339664857652289293872863780585532928599735312888289441041770498573902662584972033920369163583403049956166819419910565820072840133634677669470275
        y = 821819758799775147194175046572677140611946852952272272074263771716786660459190141049882875239373171263080517921999257539198458196843925754528053415200824207
        n = 6864797660130609714981900799081393217269435300143305409394463459185543183397651109637491772142630802149102237709283048918970986209400482528548645985755945479

    curve = EllipticCurve(GF(p), [a, b])
    G = curve(x, y)
    cost_simple = Cost()
    cost_glv = Cost()
    cost_glv3 = Cost()
    for _ in range(10):
        equations = generate_equations(curve, n, G, fixed_Q=True)

        simplelist = simple_list_fixedQ(equations, n)
        result = bos_coster(simplelist, curve, cost_simple)
        assert result == curve(0)

        glvlist = glv_list_fixedQ(equations, curve, bits, n)
        result = bos_coster(glvlist, curve, cost_glv)
        assert result == curve(0)

        glv3list = glv3_list_fixedQ(equations, curve, bits, n, cost_glv3)
        result = bos_coster(glv3list, curve, cost_glv3)
        assert result == curve(0)

    print(cost_simple.adds, cost_simple.doubles, cost_simple.integer_divisions)
    print(cost_glv.adds, cost_glv.doubles, cost_glv.integer_divisions)
    print(cost_glv3.adds, cost_glv3.doubles, cost_glv3.integer_divisions)


def main():
    experiments(256)
    # experiments_fixedQ(384)


main()

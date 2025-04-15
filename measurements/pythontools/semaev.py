from utils import GramMatrix, scalar_decomposition, smallest_vector, Cost
from math import floor
from lattice import mchange, gauss_reduction


def compute_ys(G, cost=None):

    b1 = G.e(0, 0)
    b2 = G.e(1, 1)
    b12 = G.e(0, 1)
    b13 = G.e(0, 2)
    b23 = G.e(1, 2)
    t1, t2, t12, t13, t23 = [x.bit_length() for x in [b1, b2, b12, b13, b23]]
    left = 8

    t = min([t1 - left, t2 - left, t12 - left, t13 - left, t23 - left])
    t = max([t, 0])
    b1 >>= t
    b2 >>= t
    b12 >>= t
    b13 >>= t
    b23 >>= t
    if cost:
        cost.multiply(b1, b23)
        cost.multiply(b12, b13)
        cost.multiply(b1, b2)
        cost.multiply(b12, b12)
        cost.multiply(b2, b13)
        cost.multiply(b12, b23)
        cost.divide(b1 * b23 - b12 * b13, b1 * b2 - b12 * b12)
        cost.divide(b2 * b13 - b12 * b23, b1 * b2 - b12 * b12)

    num = b1 * b23 - b12 * b13
    den = b1 * b2 - b12 * b12
    y2 = -num / den

    num = b2 * b13 - b12 * b23
    y1 = -num / den
    y1, y2 = floor(y1), floor(y2)
    return y1, y2


def bytedivision(num, den):
    left = 8
    bits = min(num.bit_length(), den.bit_length())
    t = max(bits - left, 0)
    num >>= t
    den >>= t
    return num / den


def bytedoubledivision(num1, num2, den1, den2):
    left = 8
    bits = min(
        num1.bit_length(), den1.bit_length(), num2.bit_length(), den2.bit_length()
    )
    t = max(bits - left, 0)
    num1 >>= t
    den1 >>= t
    num2 >>= t
    den2 >>= t
    return num1 * num2 / (den1 * den2)


def compute_ys2(G, cost=None):

    b1 = G.e(0, 0)
    b2 = G.e(1, 1)
    b12 = G.e(0, 1)
    b13 = G.e(0, 2)
    b23 = G.e(1, 2)

    r1, s1 = b13 // b1, b13 % b1
    r2, s2 = b23 // b2, b23 % b2
    tmp = b12 * r2
    r3, s3 = tmp // b1, tmp % b1
    delta = (
        bytedivision(s1, b1)
        - bytedivision(s3, b1)
        - bytedoubledivision(b12, s2, b1, b2)
    )  #

    print(bytedivision(s1, b1))
    print(bytedivision(s1, b1) - bytedivision(s3, b1))

    print("delta1", delta)
    assert abs(delta) <= 3 / 2, delta
    y1num = r1 - r3 + delta

    tmp = b12 * r1
    r4, s4 = tmp // b2, tmp % b2
    delta = (
        bytedivision(s2, b2)
        - bytedivision(s4, b2)
        - bytedoubledivision(b12, s1, b1, b2)
    )  #
    y2num = r2 - r4 + delta
    print("delta2", delta)
    assert abs(delta) <= 3 / 2, delta

    r5, s5 = b12 // b1, b12 % b1
    tmp = r5 * b12
    r6, s6 = tmp // b2, tmp % b2
    delta = bytedivision(s6, b2) - bytedoubledivision(b12, s5, b1, b2)  #
    assert abs(delta) <= 3 / 2, delta
    print("delta3", delta)
    den = 1 - r6 + delta

    assert abs(y1num) < 2**16
    assert abs(y2num) < 2**16
    assert abs(den) < 2**16

    y2 = -y2num / den
    y1 = -y1num / den
    y1, y2 = floor(y1), floor(y2)
    print("-------", y1, y2, y1num, y2num, den)
    return y1, y2


def x12change(bsc, G, x1, x2, sizes, cost=None):
    mchange(G, -x2, bsc, 1, 2, sizes, cost)
    mchange(G, -x1, bsc, 0, 2, sizes, cost)


def compute_asize(G, x1, x2, cost=None):
    if cost:
        cost.multiply(x2, G.e(1, 2))
        cost.multiply(x1, G.e(0, 2))
        cost.multiply(x2, x2)
        cost.multiply(x2**2, G.e(1, 1))
        cost.multiply(x2, x1)
        cost.multiply(x2 * x1, G.e(0, 1))
        cost.multiply(x1, x1)
        cost.multiply(x1**2, G.e(0, 0))

    a = (
        G.e(2, 2)
        + 2 * x2 * G.e(1, 2)
        + 2 * x1 * G.e(0, 2)
        + x2**2 * G.e(1, 1)
        + 2 * x1 * x2 * G.e(0, 1)
        + x1**2 * G.e(0, 0)
    )
    return a


def semaev_reduction(bsc, G, sizes, cost=None):
    gauss_reduction(G, bsc, 0, 1, None, sizes, cost)

    y1, y2 = compute_ys(G, cost)
    smallest_asize = 0
    if cost:
        cost.its += 1
    for i in range(2):
        for j in range(2):
            t1, t2 = y1 + i, y2 + j
            asize = compute_asize(G, t1, t2, cost)
            if smallest_asize == 0 or smallest_asize > asize:
                x1, x2 = t1, t2
                # print("ij",i,j)
                smallest_asize = asize
    if smallest_asize >= G.e(2, 2):
        return 0

    x12change(bsc, G, x1, x2, sizes, cost)
    return 1


def semaev(pkg, k, N, print_cost=False):
    cost = Cost()
    k0, k1 = scalar_decomposition(k, pkg, N)
    bso = []
    bso.append([k0, k1, -1])
    bso.append([pkg["a1"], pkg["b1"], 0])
    bso.append([pkg["a2"], pkg["b2"], 0])

    gm = GramMatrix()
    gm.compute_gram_matrix3x3_precomputed(bso, N, pkg)
    sizes = gm.compute_gram_sizes_bytes()
    bsc = [[1, 0, 0], [0, 1, 0], [0, 0, 1]]
    counter = 0
    while True:
        counter += 1
        gm.sort_basis()
        if not semaev_reduction(bsc, gm, sizes, cost):
            break

    if print_cost:
        cost.print_statistics()

    bs = []
    for comb in bsc:
        z = [0] * 3
        for c, b in zip(comb, bso):
            for i in range(3):
                z[i] += c * b[i]
        bs.append(z)
    result = smallest_vector(bs)
    if result[0] < 0:
        return [-r for r in result]
    return result

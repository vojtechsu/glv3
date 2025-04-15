WORDBYTES = 4
WORDBITS = 32
DIV_PRECISION_BITS = 32


def dot(u, v):
    return sum(map(lambda x: x[0] * x[1], zip(u, v)))


def fast_rounded_div(a, b, size_a, size_b, cost=None):
    pos_a = 0
    pos_b = 0
    if size_a > WORDBYTES:
        pos_a = size_a - WORDBYTES
        size_a = WORDBYTES
    if size_b > WORDBYTES:
        pos_b = size_b - WORDBYTES
        size_b = WORDBYTES

    sgn = 1 if a >= 0 else -1
    la = abs(a) >> (8 * pos_a)
    lb = abs(b) >> (8 * pos_b)

    if pos_a > pos_b:
        d = pos_a - pos_b
        lb = lb >> (d * 8)
        size_b -= d
    else:
        d = pos_b - pos_a
        la = la >> (d * 8)
        size_a -= d
    minn = min(size_a, size_b)
    minn *= 8
    if minn > DIV_PRECISION_BITS:
        minn -= DIV_PRECISION_BITS
    else:
        minn = 0
    la >>= minn
    lb >>= minn
    if cost:
        cost.divide(la, lb)
    try:
        flq = la / lb
    except:
        print(la, lb, a, b, size_a, a.bit_length() // 8, size_b, b.bit_length() // 8)
        raise Exception
    lq = int(flq)
    if flq - lq > 0.5:
        lq += 1

    return lq * sgn


def simple_rounded_div(a0, b0):

    sgn = (1 if a0 >= 0 else -1) * (1 if b0 >= 0 else -1)
    a = abs(a0)
    b = abs(b0)
    q = a // b
    r = a % b
    r = 2 * r
    if r > b:
        q += 1
    if sgn < 0:
        q = -q
    return q


def scalar_decomposition(m, pkg, N):
    b1k = -pkg["b1"] * m
    b2k = pkg["b2"] * m
    c1 = simple_rounded_div(b2k, N)
    c2 = simple_rounded_div(b1k, N)
    m0 = m
    m0 -= c1 * pkg["a1"]
    m0 -= c2 * pkg["a2"]
    m1 = -c1 * pkg["b1"]
    m1 -= c2 * pkg["b2"]
    return m0, m1


class GramMatrix:
    def __init__(self):
        self.matrix = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
        self.p = [0, 1, 2]
        self.crop = 0

    def compute_gram_matrix3x3_precomputed(self, bso, pkg):
        self.crop = 0
        self.matrix[0][0] = dot(bso[0], bso[0])
        self.matrix[0][1] = dot(bso[0], bso[1])
        self.matrix[1][0] = self.matrix[0][1]
        self.matrix[0][2] = dot(bso[0], bso[2])
        self.matrix[2][0] = self.matrix[0][2]
        self.matrix[1][1] = pkg["a12b12"]
        self.matrix[1][2] = pkg["a1a2b1b2"]
        self.matrix[2][1] = pkg["a1a2b1b2"]
        self.matrix[2][2] = pkg["a22b22"]

    def compute_gram_sizes_bytes(self):
        sizes = []
        for i in range(3):
            sizes.append([])
            for j in range(3):
                sizes[-1].append((self.matrix[i][j].bit_length() + 7) // 8)
        return sizes

    def e(self, i, j):
        return self.matrix[self.p[i]][self.p[j]]

    def set_e(self, i, j, v):
        self.matrix[self.p[i]][self.p[j]] = v

    def switch_columns(self, i, j):
        self.p[i], self.p[j] = self.p[j], self.p[i]

    def compute_m(self, i, j, sizes, cost=None):
        return fast_rounded_div(
            self.e(i, j),
            self.e(i, i),
            sizes[self.p[i]][self.p[j]],
            sizes[self.p[i]][self.p[i]],
            cost,
        )

    def apply_m3x3(self, m, i, j, cost=None):
        for l in range(3):
            self.set_e(j, l, self.e(j, l) - self.e(i, l) * m)
            if cost:
                cost.multiply(self.e(i, l), m)
        for l in range(3):
            self.set_e(l, j, self.e(j, l))
        self.set_e(j, j, self.e(j, j) - m * self.e(j, i))
        if cost:
            cost.multiply(m, self.e(j, i))

    def sort_pair(self, i, j):
        if self.e(i, i) > self.e(j, j):
            self.switch_columns(i, j)
            return 1
        return 0

    def sort_basis(self):
        self.sort_pair(0, 1)
        if self.sort_pair(1, 2):
            self.sort_pair(0, 1)

    def print(self):
        for i in range(3):
            for j in range(3):
                print(self.e(i, j), end=" ")
            print()


class Cost:
    def __init__(self):
        self.multiply_pairs = []
        self.divide_pairs = []
        self.register_size = 32
        self.cost = 0
        self.its = 0
        self.maxmin = 0

        self.adds = 0
        self.doubles = 0
        self.integer_divisions = 0

    def multiply(self, x, y):
        n1, n2 = (
            x.bit_length() // self.register_size + 1,
            y.bit_length() // self.register_size + 1,
        )
        self.cost += n1 * n2
        self.maxmin = max(self.maxmin, min(x, y))
        self.multiply_pairs.append((x, y))

    def divide(self, x, y):
        n1, n2 = (
            x.bit_length() // self.register_size + 1,
            y.bit_length() // self.register_size + 1,
        )
        self.cost += n1 * n2 * 6
        self.divide_pairs.append((x, y))

    def integer_divide(self, x, y):
        self.integer_divisions += 1

    def print_statistics(self):
        print("mul count", len(self.multiply_pairs))
        print("div count", len(self.divide_pairs))
        print("cost", self.cost)
        print("maxmin", self.maxmin)
        print("its", self.its)


def smallest_vector(matrix):
    return min(matrix, key=max).copy()

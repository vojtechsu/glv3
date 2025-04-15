from lattice import small_3, init_package
from utils import scalar_decomposition
from semaev import semaev
from random import randint


def test_scalar_decomp():
    k = 828399494244925932616503812198055559904976794273920841945739236241206941541022348679422890871210954925737444083986
    N = 39402006196394479212279040100143613805079739270465446667939648971411203427402483823859213529384957691103129168225793
    pckg = init_package(384)
    k0, k1 = scalar_decomposition(k, pckg, N)
    print(k0, k1)


def test_lattice():
    k = 828399494244925932616503812198055559904976794273920841945739236241206941541022348679422890871210954925737444083986
    N = 39402006196394479212279040100143613805079739270465446667939648971411203427402483823859213529384957691103129168225793
    expected_result = [
        70918471550450367321219169254940951818,
        -202315241179932127976042878571431716185,
        -57401342650088695421354454620777162270,
    ]
    pckg = init_package(384)
    result = small_3(pckg, k, N, True)
    result2 = semaev(pckg, k, N, True)
    assert result2 == expected_result
    assert result == expected_result


def test_lagrange():
    N = 39402006196394479212279040100143613805079739270465446667939648971411203427402483823859213529384957691103129168225793
    k = 557073415843455186786046191312039577462134098663458688126717814594317292459372200179122660950544547983431586620085
    pckg = init_package(384)
    result2 = small_3(pckg, k, N)
    print(result2)


def test_lattice2():
    N = 39402006196394479212279040100143613805079739270465446667939648971411203427402483823859213529384957691103129168225793
    pckg = init_package(384)
    bits_semaev = []
    bits_greedy = []
    for _ in range(1000):
        k = randint(1, N)
        result = small_3(pckg, k, N)
        result2 = semaev(pckg, k, N)
        bits_greedy.append(max([r.bit_length() for r in result]))
        bits_semaev.append(max([r.bit_length() for r in result2]))
    print("greedy")
    print(max(bits_greedy))
    print(sum(bits_greedy) / len(bits_greedy))

    print("semaev")
    print(max(bits_semaev))
    print(sum(bits_semaev) / len(bits_semaev))


def test_lagrange2():
    N = 39402006196394479212279040100143613805079739270465446667939648971411203427402483823859213529384957691103129168225793
    pckg = init_package(384)
    bits_semaev = []
    bits_greedy = []
    for _ in range(500):
        k = randint(1, N)
        result2 = small_3(pckg, k, N)
        m = max([r.bit_length() for r in result2])
        assert m < 140, m
    print("all good")

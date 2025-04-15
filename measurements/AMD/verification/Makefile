CC=gcc
DIR=$(shell pwd)
CFLAGS= -I../mbedtls/tf-psa-crypto/core \
	-I../mbedtls/tf-psa-crypto/include/psa \
	-I../mbedtls/include \
	-I../mbedtls/tf-psa-crypto/include \
	-I../mbedtls/tf-psa-crypto/drivers/builtin/include \
	-I../mbedtls/tf-psa-crypto/drivers/builtin/include/mbedtls/ \
	$(DIR)/../mbedtls/library/libmbedcrypto.a \
	$(DIR)/../mbedtls/library/libmbedx509.a \
	$(DIR)/../mbedtls/library/libmbedtls.a
DEPS = glvecdsa.h glvecp.h jsf.h lattice.h
UTILS = glvecdsa.c glvecp.c jsf.c lattice.c

all: timing lattice_exp

timing: $(DEPS) $(UTILS) sign.c sign.h timing.c
	$(CC) $(UTILS) timing.c sign.c $(CFLAGS) -o timing

lattice_exp: $(DEPS) $(UTILS) sign.c sign.h lattice_exp.c
	$(CC) $(UTILS) lattice_exp.c sign.c $(CFLAGS) -o lattice_exp

clean:
	rm measure timing 

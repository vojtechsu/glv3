1. Clone the repository https://github.com/Mbed-TLS/mbedtls.git
2. Replace the following files:
	```
	modified:   include/mbedtls/mbedtls_config.h
	modified:   tf-psa-crypto/drivers/builtin/include/mbedtls/bignum.h
	modified:   tf-psa-crypto/drivers/builtin/include/mbedtls/ecdsa.h
	modified:   tf-psa-crypto/drivers/builtin/include/mbedtls/ecp.h
	modified:   tf-psa-crypto/drivers/builtin/src/ecdsa.c
	modified:   tf-psa-crypto/drivers/builtin/src/ecp.c
	modified:   tf-psa-crypto/drivers/builtin/src/ecp_curves.c
	```
3. make; make install;
4. Go to lukasz and compile with:
	```
	gcc *.c -lmbedtls -lmbedx509 -lmbedcrypto -I../tf-psa-crypto/core -o measure
	```
5. ./measure



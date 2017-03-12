#ifndef RA_CLIENT_H
#define RA_CLIENT_H

#include "mbedtls/net_v.h"
#include "mbedtls/net_f.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "s_client.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    mbedtls_ssl_session saved_session;
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;

    mbedtls_x509_crt cacert;
    mbedtls_x509_crt clicert;
    mbedtls_pk_context pkey;
} ssl_state_t;

ssl_state_t *sotiri_connect(client_opt_t *_opt);
int sotiri_send(client_opt_t *opt, ssl_state_t *ssl_state, char *headers[], int n_headers, const char *body);
int sotiri_recv(client_opt_t *opt, ssl_state_t *ssl_state, char *output, size_t output_len);
void sotiri_close_notify(client_opt_t *opt, ssl_state_t *ssl_state);
void sotiri_exit(int err_code, ssl_state_t *ssl_state);


#ifdef __cplusplus
}
#endif

#endif
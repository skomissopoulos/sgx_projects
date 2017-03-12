/*
 *  SSL client with certificate authentication
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include "Enclave_t.h"
#include "Log.h"
#include "pprint.h"
#include "ra_client.h"
#include "RootCerts.h"
#include "s_client.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#define mbedtls_fprintf    fprintf
#define mbedtls_snprintf   snprintf
#endif

#if !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_CTR_DRBG_C)
#else


#include "mbedtls/net_v.h"
#include "mbedtls/net_f.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    const char *p, *basename;
    (void)(ctx);

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str );
}

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
static int my_recv( void *ctx, unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }

    ret = mbedtls_net_recv( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_READ )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

static int my_send( void *ctx, const unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_WRITE );
    }

    ret = mbedtls_net_send( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
/*
 * Enabled if debug_level > 1 in code below
 */
static int my_verify( void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags )
{
    char buf[1024];
    ((void) data);

    mbedtls_printf( "\nVerify requested for (Depth %d):\n", depth );
    mbedtls_x509_crt_info( buf, sizeof( buf ) - 1, "", crt );
    mbedtls_printf( "%s", buf );

    if ( ( *flags ) == 0 )
        mbedtls_printf( "  This certificate has no flags\n" );
    else
    {
        mbedtls_x509_crt_verify_info( buf, sizeof( buf ), "  ! ", *flags );
        mbedtls_printf( "%s\n", buf );
    }

    return( 0 );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */


ssl_state_t *new_ssl_state_t()
{
    ssl_state_t *ssl_state = (ssl_state_t *) malloc(sizeof(ssl_state_t));
    
    /*
     * Make sure memory references are valid.
     */

    mbedtls_ssl_config_init(&ssl_state->conf);
    mbedtls_ctr_drbg_init(&ssl_state->ctr_drbg);
    mbedtls_entropy_init(&ssl_state->entropy);

    memset(&ssl_state->saved_session, 0, sizeof( mbedtls_ssl_session));
    mbedtls_net_init(&ssl_state->server_fd);
    mbedtls_ssl_init(&ssl_state->ssl);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_init(&ssl_state->cacert);
    mbedtls_x509_crt_init(&ssl_state->clicert);
    mbedtls_pk_init(&ssl_state->pkey);
#endif

    return ssl_state;
}


void free_ssl_state_t(ssl_state_t *state)
{
    if (state == NULL)
        return;

    mbedtls_net_free(&state->server_fd);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_free(&state->clicert);
    mbedtls_x509_crt_free(&state->cacert);
    mbedtls_pk_free(&state->pkey);
#endif
    mbedtls_ssl_session_free(&state->saved_session);
    mbedtls_ssl_free(&state->ssl);
    mbedtls_ssl_config_free(&state->conf);
    mbedtls_ctr_drbg_free(&state->ctr_drbg);
    mbedtls_entropy_free(&state->entropy);

    free(state);
}


ssl_state_t *sotiri_connect(client_opt_t *_opt)
{
    client_opt_t opt = *_opt;
    ssl_state_t *ssl_state = new_ssl_state_t();

    int ret = 0, len, tail_len, i, written, frags;
    unsigned char buf[MBEDTLS_SSL_MAX_CONTENT_LEN + 1];

    const char *pers = "sotiri_connect";

#if defined(MBEDTLS_TIMING_C)
    mbedtls_timing_delay_context timer;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    uint32_t flags;
#endif

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( opt.debug_level );
#endif

    // XXX starting here!
    /*
     * 0. Initialize the RNG and the session data
     */
    LL_LOG("Seeding the random number generator..." );

    if( ( ret = mbedtls_ctr_drbg_seed( &ssl_state->ctr_drbg, mbedtls_entropy_func, &ssl_state->entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        LL_CRITICAL(" mbedtls_ctr_drbg_seed returned -%#x", -ret);
        sotiri_exit(ret, ssl_state);
        return NULL;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    /*
     * 1.1. Load the trusted CA
     */
    LL_LOG( "Loading the CA root certificate");

#if defined(MBEDTLS_FS_IO)
    if( strlen( opt.ca_path ) )
        if( strcmp( opt.ca_path, "none" ) == 0 )
            ret = 0;
        else
            ret = mbedtls_x509_crt_parse_path( &ssl_state->cacert, opt.ca_path );
    else if( strlen( opt.ca_file ) )
        if( strcmp( opt.ca_file, "none" ) == 0 )
            ret = 0;
        else
            ret = mbedtls_x509_crt_parse_file( &ssl_state->cacert, opt.ca_file );
    else
#endif
#if defined(MBEDTLS_CERTS_C)
        for( i = 0; mbedtls_test_cas[i] != NULL; i++ )
        {
            ret = mbedtls_x509_crt_parse( &ssl_state->cacert,
                                  (const unsigned char *) mbedtls_test_cas[i],
                                  mbedtls_test_cas_len[i] );
            if( ret != 0 )
                break;
        }
#else
    {
        // load trusted crts
        ret = mbedtls_x509_crt_parse( &ssl_state->cacert,
            (const unsigned char *) root_cas_pem,
            root_cas_pem_len);
    }
#endif
    if( ret < 0 )
    {
        LL_CRITICAL("  mbedtls_x509_crt_parse returned -%#x", -ret);
        sotiri_exit(ret, ssl_state);
        return NULL;
    }

    if( ret != 0 )
    {
        LL_CRITICAL("  mbedtls_pk_parse_key returned -%#x", -ret );
        sotiri_exit(ret, ssl_state);
        return NULL;
    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

    /*
     * 2. Start the connection
     */
    if( opt.server_addr == NULL)
        opt.server_addr = opt.server_name;

    LL_LOG("connecting to %s:%s:%s...",
            opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ? "TCP" : "UDP",
            opt.server_addr, opt.server_port );

    if( ( ret = mbedtls_net_connect( &ssl_state->server_fd, opt.server_addr, opt.server_port,
                             opt.transport == MBEDTLS_SSL_TRANSPORT_STREAM ?
                             MBEDTLS_NET_PROTO_TCP : MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        LL_CRITICAL( " mbedtls_net_connect returned -%#x", -ret );
        sotiri_exit(ret, ssl_state);
        return NULL;
    }

    if( opt.nbio > 0 )
        ret = mbedtls_net_set_nonblock( &ssl_state->server_fd );
    else
        ret = mbedtls_net_set_block( &ssl_state->server_fd );
    if( ret != 0 )
    {
        LL_CRITICAL( " net_set_(non)block() returned -%#x", -ret );
        sotiri_exit(ret, ssl_state);
        return NULL;
    }

    /*
     * 3. Setup stuff
     */
    LL_LOG( "Setting up the SSL/TLS structure..." );

    if( ( ret = mbedtls_ssl_config_defaults( &ssl_state->conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    opt.transport,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        LL_CRITICAL( "mbedtls_ssl_config_defaults returned -%#x", -ret );
        sotiri_exit(ret, ssl_state);
        return NULL;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( opt.debug_level > 0 )
        mbedtls_ssl_conf_verify( &ssl_state->conf, my_verify, NULL );
#endif

    if( opt.auth_mode != DFL_AUTH_MODE )
        mbedtls_ssl_conf_authmode( &ssl_state->conf, opt.auth_mode );

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( opt.hs_to_min != DFL_HS_TO_MIN || opt.hs_to_max != DFL_HS_TO_MAX )
        mbedtls_ssl_conf_handshake_timeout( &ssl_state->conf, opt.hs_to_min, opt.hs_to_max );
#endif /* MBEDTLS_SSL_PROTO_DTLS */

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if( ( ret = mbedtls_ssl_conf_max_frag_len( &ssl_state->conf, opt.mfl_code ) ) != 0 )
    {
        mbedtls_printf( "  mbedtls_ssl_conf_max_frag_len returned %d\n\n", ret );
        sotiri_exit(ret, ssl_state);
        return NULL;
    }
#endif

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    if( opt.trunc_hmac != DFL_TRUNC_HMAC )
        mbedtls_ssl_conf_truncated_hmac( &ssl_state->conf, opt.trunc_hmac );
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    if( opt.extended_ms != DFL_EXTENDED_MS )
        mbedtls_ssl_conf_extended_master_secret( &ssl_state->conf, opt.extended_ms );
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    if( opt.etm != DFL_ETM )
        mbedtls_ssl_conf_encrypt_then_mac( &ssl_state->conf, opt.etm );
#endif

#if defined(MBEDTLS_SSL_CBC_RECORD_SPLITTING)
    if( opt.recsplit != DFL_RECSPLIT )
        mbedtls_ssl_conf_cbc_record_splitting( &ssl_state->conf, opt.recsplit
                                    ? MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED
                                    : MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED );
#endif

#if defined(MBEDTLS_DHM_C)
    if( opt.dhmlen != DFL_DHMLEN )
        mbedtls_ssl_conf_dhm_min_bitlen( &ssl_state->conf, opt.dhmlen );
#endif

    mbedtls_ssl_conf_rng( &ssl_state->conf, mbedtls_ctr_drbg_random, &ssl_state->ctr_drbg );
    mbedtls_ssl_conf_dbg( &ssl_state->conf, my_debug, NULL );

    mbedtls_ssl_conf_read_timeout( &ssl_state->conf, opt.read_timeout );

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_session_tickets( &ssl_state->conf, opt.tickets );
#endif

    if( opt.force_ciphersuite[0] != DFL_FORCE_CIPHER )
        mbedtls_ssl_conf_ciphersuites( &ssl_state->conf, opt.force_ciphersuite );

#if defined(MBEDTLS_ARC4_C)
    if( opt.arc4 != DFL_ARC4 )
        mbedtls_ssl_conf_arc4_support( &ssl_state->conf, opt.arc4 );
#endif

    if( opt.allow_legacy != DFL_ALLOW_LEGACY )
        mbedtls_ssl_conf_legacy_renegotiation( &ssl_state->conf, opt.allow_legacy );
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation( &ssl_state->conf, opt.renegotiation );
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( strcmp( opt.ca_path, "none" ) != 0 &&
        strcmp( opt.ca_file, "none" ) != 0 )
    {
        mbedtls_ssl_conf_ca_chain( &ssl_state->conf, &ssl_state->cacert, NULL );
    }
    if( strcmp( opt.crt_file, "none" ) != 0 &&
        strcmp( opt.key_file, "none" ) != 0 )
    {
        if( ( ret = mbedtls_ssl_conf_own_cert( &ssl_state->conf, &ssl_state->clicert, &ssl_state->pkey ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
            sotiri_exit(ret, ssl_state);
            return NULL;
        }
    }
#endif

    if( opt.min_version != DFL_MIN_VERSION )
        mbedtls_ssl_conf_min_version( &ssl_state->conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.min_version );

    if( opt.max_version != DFL_MAX_VERSION )
        mbedtls_ssl_conf_max_version( &ssl_state->conf, MBEDTLS_SSL_MAJOR_VERSION_3, opt.max_version );

#if defined(MBEDTLS_SSL_FALLBACK_SCSV)
    if( opt.fallback != DFL_FALLBACK )
        mbedtls_ssl_conf_fallback( &ssl_state->conf, opt.fallback );
#endif

    if( ( ret = mbedtls_ssl_setup( &ssl_state->ssl, &ssl_state->conf ) ) != 0 )
    {
        LL_CRITICAL("mbedtls_ssl_setup returned -%#x", -ret );
        sotiri_exit(ret, ssl_state);
        return NULL;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if( ( ret = mbedtls_ssl_set_hostname( &ssl_state->ssl, opt.server_name ) ) != 0 )
    {
        LL_CRITICAL("mbedtls_ssl_set_hostname returned %d\n\n", ret );
        sotiri_exit(ret, ssl_state);
        return NULL;
    }
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    if( opt.ecjpake_pw != DFL_ECJPAKE_PW )
    {
        if( ( ret = mbedtls_ssl_set_hs_ecjpake_password( &ssl_state->ssl,
                        (const unsigned char *) opt.ecjpake_pw,
                                        strlen( opt.ecjpake_pw ) ) ) != 0 )
        {
            mbedtls_printf( "  mbedtls_ssl_set_hs_ecjpake_password returned %d\n\n", ret );
            sotiri_exit(ret, ssl_state);
            return NULL;
        }
    }
#endif

    if( opt.nbio == 2 )
        mbedtls_ssl_set_bio( &ssl_state->ssl, &ssl_state->server_fd, my_send, my_recv, NULL );
    else
        mbedtls_ssl_set_bio( &ssl_state->ssl, &ssl_state->server_fd, mbedtls_net_send, mbedtls_net_recv,
                             opt.nbio == 0 ? mbedtls_net_recv_timeout : NULL );

#if defined(MBEDTLS_TIMING_C)
    mbedtls_ssl_set_timer_cb( &ssl_state->ssl, &timer, mbedtls_timing_set_delay,
                                            mbedtls_timing_get_delay );
#endif

    /*
     * 4. Handshake
     */
    LL_LOG( "Performing the SSL/TLS handshake" );

    while( ( ret = mbedtls_ssl_handshake( &ssl_state->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            LL_CRITICAL( "mbedtls_ssl_handshake returned -%#x", -ret );
            if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED )
                LL_CRITICAL(
                    "Unable to verify the server's certificate. "
                    "Either it is invalid,"
                    "or you didn't set ca_file or ca_path "
                    "to an appropriate value."
                    "Alternatively, you may want to use "
                    "auth_mode=optional for testing purposes." );
            sotiri_exit(ret, ssl_state);
            return NULL;
        }
    }

    LL_LOG( "Hand shake succeeds: [%s, %s]",
            mbedtls_ssl_get_version( &ssl_state->ssl ), mbedtls_ssl_get_ciphersuite( &ssl_state->ssl ) );

    if( ( ret = mbedtls_ssl_get_record_expansion( &ssl_state->ssl ) ) >= 0 )
        LL_DEBUG( "Record expansion is [%d]", ret );
    else
        LL_DEBUG( "Record expansion is [unknown (compression)]" );

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    LL_LOG( "Maximum fragment length is [%u]",
                    (unsigned int) mbedtls_ssl_get_max_frag_len( &ssl_state->ssl ) );
#endif

    if( opt.reconnect != 0 )
    {
        LL_LOG("  . Saving session for reuse..." );

        if( ( ret = mbedtls_ssl_get_session( &ssl_state->ssl, &ssl_state->saved_session ) ) != 0 )
        {
            LL_CRITICAL("mbedtls_ssl_get_session returned -%#x", -ret );
            sotiri_exit(ret, ssl_state);
            return NULL;
        }

        LL_LOG("ok");
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    /*
     * 5. Verify the server certificate
     */
    LL_LOG( "Verifying peer X.509 certificate..." );

    if( ( flags = mbedtls_ssl_get_verify_result( &ssl_state->ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        mbedtls_printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        mbedtls_printf( "%s\n", vrfy_buf );
    }
    else
        LL_LOG("X.509 Verifies");

    if( mbedtls_ssl_get_peer_cert( &ssl_state->ssl ) != NULL )
    {
        if (opt.debug_level > 0)
        {
            LL_DEBUG( "Peer certificate information");
            mbedtls_x509_crt_info( (char *) buf, sizeof( buf ) - 1, "|-", mbedtls_ssl_get_peer_cert( &ssl_state->ssl ) );
            mbedtls_printf("%s\n", buf);   
        }

    }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if( opt.renegotiate )
    {
        /*
         * Perform renegotiation (this must be done when the server is waiting
         * for input from our side).
         */
        mbedtls_printf( "  . Performing renegotiation..." );
        while( ( ret = mbedtls_ssl_renegotiate( &ssl_state->ssl ) ) != 0 )
        {
            if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                mbedtls_printf( "  mbedtls_ssl_renegotiate returned %d\n\n", ret );
                sotiri_exit(ret, ssl_state);
                return NULL;
            }
        }
        mbedtls_printf( " ok\n" );
    }
#endif /* MBEDTLS_SSL_RENEGOTIATION */

    return ssl_state;
}


int sotiri_send(client_opt_t *opt, ssl_state_t *ssl_state, char *headers[], int n_headers, const char *body)
{
    char buf[1024];
    size_t len = 0;
    int ret = -1;
    int i;

    if (headers && n_headers > 0)
        for (i = 0; i < n_headers; i++)
            len += mbedtls_snprintf(buf + len, sizeof(buf) - 1 - len, "%s\r\n", headers[i]);
    len += mbedtls_snprintf(buf + len, sizeof(buf) - 1 - len, "\r\n");
    if (body != NULL)
        len += mbedtls_snprintf(buf + len, sizeof(buf) - 1 - len, "%s", body);

    size_t written;
    int frags;

    if (opt->transport == MBEDTLS_SSL_TRANSPORT_STREAM) {
        for (written = 0, frags = 0; written < len; written += ret, frags++) {
            while ((ret = mbedtls_ssl_write(&ssl_state->ssl, buf + written, len - written)) <= 0) {
                if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    mbedtls_printf("  mbedtls_ssl_write returned -%#x", -ret);
                    return ret;
                }
            }
        }
    }
    else {
        /* Not stream, so datagram */
        do ret = mbedtls_ssl_write(&ssl_state->ssl, buf, len);
        while (ret == MBEDTLS_ERR_SSL_WANT_READ ||
               ret == MBEDTLS_ERR_SSL_WANT_WRITE);
        if (ret < 0) {
            mbedtls_printf("  mbedtls_ssl_write returned %d\n\n", ret);
            return ret;
        }

        frags = 1;
        written = ret;
    }

    buf[written] = '\0';
    LL_LOG("%d bytes written in %d fragments", written, frags);
    LL_LOG("%s", (char*) buf);

    if (opt->debug_level > 0) hexdump("Bytes written:", buf, written);

    return 0;
}


int sotiri_recv(client_opt_t *opt, ssl_state_t *ssl_state, char *output, size_t output_len)
{
    size_t len;
    int ret;

    /*
     * TLS and DTLS need different reading styles (stream vs datagram)
     */
    if (opt->transport == MBEDTLS_SSL_TRANSPORT_STREAM) {
        do {
            len = output_len - 1;
            memset(output, 0, output_len);
            ret = mbedtls_ssl_read( &ssl_state->ssl, output, len );

            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if (ret <= 0)
            {
                switch (ret)
                {
                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                        mbedtls_printf( " connection was closed gracefully\n" );

                    case 0:
                    case MBEDTLS_ERR_NET_CONN_RESET:
                        mbedtls_printf( " connection was reset by peer\n" );

                    default:
                        mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
                }
                return ret;
            }

            len = ret;

            LL_LOG("get %d bytes ending with %x", len, output[len-1]);
            if (opt->debug_level> 0) hexdump("REPONSE:", output, len);
            // TODO: Add full-fledge HTTP parser here
            // possibly from libcurl
            if (ret > 0 && (output[len-1] == '\n' || output[len-1] == '}'))
            {
                ret = 0;
                output[len] = 0;
                break;
            }
            

            output += len;
            output_len -= len;
        }
#pragma warning (disable: 4127)
        while(1);
#pragma warning (default: 4127)
    }
    else {
        /* Not stream, so datagram */
        len = output_len - 1;
        memset(output, 0, output_len);

        do ret = mbedtls_ssl_read(&ssl_state->ssl, output, len);
        while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_TIMEOUT:
                    mbedtls_printf( " timeout\n" );

                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf( " connection was closed gracefully\n" );

                default:
                    mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
            }
            return ret;
        }

        len = ret;
        output[len] = '\0';
        mbedtls_printf( " %d bytes read\n\n%s", len, (char *) buf );
        ret = 0;
    }

    return 0;
}


void sotiri_close_notify(client_opt_t *opt, ssl_state_t *ssl_state)
{
    int ret;
    /* No error checking; may already be closed on other side. */
    do ret = mbedtls_ssl_close_notify(&ssl_state->ssl);
    while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    LL_LOG("closed %s:%s", opt->server_addr, opt->server_port);
}


void sotiri_exit(int err_code, ssl_state_t *ssl_state)
{
#ifdef MBEDTLS_ERROR_C
    if (err_code != 0) {
        char error_buf[100];
        mbedtls_strerror(err_code, error_buf, 100);
        LL_CRITICAL("Last error was: -0x%X - %s\n\n", -err_code, error_buf);
    }
#endif

    free_ssl_state_t(ssl_state);
}


int ra_client(client_opt_t *opt)
{
    int ret;
    ssl_state_t *ssl_state = sotiri_connect(opt);

    /*
     * 6. Write the requests, read the responses.
     */
    char *headers[2] = {"GET /items/12372", "Content-Type: application/json"};
    ret = sotiri_send(opt, ssl_state, headers, 2, NULL);
    if (ret < 0) {
        sotiri_exit(ret, ssl_state);
        return ret;
    }

    /*
     * 7. Read the HTTP response
     */
    char output[1024];
    ret = sotiri_recv(opt, ssl_state, output, sizeof(output));
    if (ret < 0) {
        sotiri_exit(ret, ssl_state);
        return ret;
    }
    mbedtls_printf(" Received: %s\n\n", output);

    /*
     * 8. Done, cleanly close the connection
     */
    /* No error checking, the connection might be closed already */
    sotiri_close_notify(opt, ssl_state);

    /*
     * Cleanup and exit
     */
    ret = 0;
    sotiri_exit(ret, ssl_state);
    return ret;
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_CTR_DRBG_C MBEDTLS_TIMING_C */

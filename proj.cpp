#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

using namespace std;
#define HOST_PORT "443"
#define HOST_RESOURCE "/cgi-bin/randbyte?nbytes=32&format=h"
#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
# include <openssl/conf.h>
#endif

char number[3];
string host = ".minotaur.fi.muni.cz";
string host_port = "443";

void init_openssl_library(void)
{
  (void)SSL_library_init();

  SSL_load_error_strings();

  /* ERR_load_crypto_strings(); */

  OPENSSL_config(NULL);

  /* Include <openssl/opensslconf.h> to get this define */
#if defined (OPENSSL_THREADS)
  fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

/**
 *
 * Věříte standardním certifikačním autoritám předinstalovaným na stroji merlin.fit.vutbr.cz.
 *
 * Věříte lokální certifikační autoritě laboratoře CRoCS FI MU[2]. (Vydavatel: CN = CRoCS CA,
 *   OU = Faculty of Informatics, O = Masaryk University, L = Brno, C = CZ; Platnost od:
 *   8. ‎dubna ‎2017 21:38:25; Platnost do: 8. ‎května ‎2017 21:38:25; Sériové číslo: 00;
 *   Otisk SHA1: ‎6D:01:86:47:24:22:B8:7E:18:F3:C3:C4:5F:22:62:C2:42:70:0D:30)
 *
 */
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    char buf[256];

    cout << "Preverify OK " << preverify_ok << endl;
    X509 *cert = ctx->cert;

    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

    cout << "subj: " << subj << endl;
    cout << "issuer: " << subj << endl;


    /////////////////////////////////////////////////////////
    int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);

    if (pkey_nid == NID_undef) {
        fprintf(stderr, "unable to find specified signature algorithm name.\n");
        return EXIT_FAILURE;
    }
    const char* sslbuf = OBJ_nid2ln(pkey_nid);
//    cout << "pkey_nid: " << sslbuf << endl;

//    ASN1_TIME *not_before = X509_get_notBefore(cert);
//    ASN1_TIME *not_after = X509_get_notAfter(cert);


//    PEM_write_X509(stdout, cert);
    return 1;
}

int main(int argc, char *argv[]) {

    long res = 1;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;
    const char *certDir;

    init_openssl_library();

    certDir = getenv(X509_get_default_cert_dir_env());
    if (!certDir){
        certDir = X509_get_default_cert_dir();
    }
    cout << "Cert path: " << certDir << endl;

    for (int i = 0; i < 100; ++i) {
        cout << endl << "Server " << i << endl;
        const SSL_METHOD* method = SSLv23_method();
        if(!(NULL != method)){
          cerr << "SSLv23_method" << endl;
        }

        ctx = SSL_CTX_new(method);
        if(!(ctx != NULL)) {
            cerr << "SSL_CTX_new" << endl;
        }
        /* Cannot fail ??? */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

        /* Cannot fail ??? */
    //    SSL_CTX_set_verify_depth(ctx, 4);

        /* Cannot fail ??? */
        const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        SSL_CTX_set_options(ctx, flags);

        res = SSL_CTX_load_verify_locations(ctx, NULL, certDir);
        if(!(1 == res)) {
            cerr << "SSL_CTX_load_verify_locations" << endl;
        }

        web = BIO_new_ssl_connect(ctx);
        if(!(web != NULL)) {
            cerr << "BIO_new_ssl_connect" << endl;
        }

        sprintf(number, "%02d", i);
        string url = number + host + ":" + host_port;
        cout << "URL: " << url << endl;
        res = BIO_set_conn_hostname(web, url.c_str());
        if(!(1 == res)) {
            cerr << "BIO_set_conn_hostname" << endl;
        }

        BIO_get_ssl(web, &ssl);
        if(!(ssl != NULL)) {
            cerr << "BIO_get_ssl" << endl;
        }

        const char *const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
        res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
        if(!(1 == res)) {
            cerr << "SSL_set_cipher_list" << endl;
        }

        res = SSL_set_tlsext_host_name(ssl, (number + host).c_str());
        if(!(1 == res)) {
            cerr << "SSL_set_tlsext_host_name" << endl;
        }

        out = BIO_new_fp(stdout, BIO_NOCLOSE);
        if(!(NULL != out)) {
            cerr << "BIO_new_fp" << endl;
        }

        res = BIO_do_connect(web);
        if(!(1 == res)) {
            cerr << "BIO_do_connect" << endl;
        }

        res = BIO_do_handshake(web);
        if(!(1 == res)) {
            cerr << "BIO_do_handshake" << endl;
        }

        /* Step 1: verify a server certificate was presented during the negotiation */
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) { X509_free(cert); } /* Free immediately */
        if(NULL == cert) {
            cerr << "SSL_get_peer_certificate" << endl;
        }

        /* Step 2: verify the result of chain verification */
        /* Verification performed according to RFC 4158    */
        res = SSL_get_verify_result(ssl);
        if(!(X509_V_OK == res)) {
            cerr << "SSL_get_verify_result" << endl;
        }

//        /* Step 3: hostname verification */
//        /* An exercise left to the reader */
//
//            BIO_puts(web, "GET " HOST_RESOURCE " HTTP/1.1\r\n"
//                          "Host: " HOST_NAME "\r\n"
//                          "Connection: close\r\n\r\n");
//            BIO_puts(out, "\n");
//
//            int len = 0;
//            do
//            {
//              char buff[1536] = {};
//              len = BIO_read(web, buff, sizeof(buff));
//
//              if(len > 0)
//                BIO_write(out, buff, len);
//
//            } while (len > 0 || BIO_should_retry(web));
        if(out)
            BIO_free(out);
    }

    if(web != NULL)
      BIO_free_all(web);

    if(NULL != ctx)
      SSL_CTX_free(ctx);
    return 0;
}

/**
 *
 * Velka cas programu prevzata ze stranky: https://wiki.openssl.org/index.php/SSL/TLS_Client
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/conf.h>

#include <openssl/ssl.h>
#include "openssl_hostname_validation.c"

using namespace std;
#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
# include <openssl/conf.h>
#include <fstream>

#endif

#define BIG_ERROR 3
#define MIDDLE_ERROR 2
#define SMALL_ERROR 1

char number[3];
string host = ".minotaur.fi.muni.cz";
string host_port = "443";

//global variables
int errorSum;
string errorMsg;

string public_key_type(X509 *x509);

int public_key_size(X509 *x509);

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

    int depth = X509_STORE_CTX_get_error_depth(ctx);
    int err = X509_STORE_CTX_get_error(ctx);

    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

    string publicKeyType = public_key_type(cert);
    int publicKeyLength = public_key_size(cert);

    if (publicKeyType == "rsa" && publicKeyLength < 1024) {
        errorSum += SMALL_ERROR;
        errorMsg += "RSA is used with key length (" + to_string(publicKeyLength) + "). ";
        cerr << "MY_ERR : RSA with weak key" << endl;
    }

    if (preverify_ok == 0) {
        if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) { //20
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n", depth);
            // this is allways combined with X509_V_ERR_CERT_UNTRUSTED
            errorMsg += "Unable to get Issuer cert locally. ";
            errorSum += SMALL_ERROR;
        } else if (err == X509_V_ERR_CERT_UNTRUSTED) { //27
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_CERT_UNTRUSTED\n", depth);
            // this will append after X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
            errorMsg += "Cert is untrusted. ";
            errorSum += SMALL_ERROR;
        } else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {// 19
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n", depth);
            errorMsg += "Self signed cert in chain. ";
            errorSum += MIDDLE_ERROR;
        } else if (err == X509_V_ERR_CERT_NOT_YET_VALID) {// 9
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_CERT_NOT_YET_VALID\n", depth);
            errorMsg += "Cert is not yet valid. ";
            errorSum += SMALL_ERROR;
        } else if (err == X509_V_ERR_CERT_HAS_EXPIRED) { //10
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_CERT_HAS_EXPIRED\n", depth);
            errorMsg += "Certificate has expired. ";
            errorSum += MIDDLE_ERROR;
        } else if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            // this is allways combined with X509_V_ERR_INVALID_PURPOSE
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT\n", depth);
            errorMsg += "Self signed certificate. ";
            errorSum += SMALL_ERROR;
        } else if (err == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) {
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE\n", depth);
            errorMsg += "Unable to verify leaf signature. ";
            errorSum += MIDDLE_ERROR;
        } else if (err == X509_V_ERR_INVALID_PURPOSE) {
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_INVALID_PURPOSE\n", depth);
            errorMsg += "Certificate cannot be used for the specified purpose. ";
            errorSum += SMALL_ERROR;
        } else if (err == X509_V_ERR_INVALID_CA) {
            fprintf(stderr, "  depth %d : Error = X509_V_ERR_INVALID_CA\n", depth);
            errorMsg += "Certificate is invalid. ";
            errorSum += BIG_ERROR;
        } else if (err == X509_V_OK)
            fprintf(stderr, "  depth %d : Error = X509_V_OK\n", depth);
        else {
            fprintf(stderr, "  depth %d : Error = %d\n", depth, err);
            errorMsg += "Other errors (" + to_string(err) + "). ";
            errorSum += BIG_ERROR;
        }
    }


    #if !defined(NDEBUG)
        return 1;
    #else
        return preverify_ok;
    #endif

}

void print_expiration(X509 *c) {
    int a = X509_cmp_current_time(X509_get_notBefore(c));
    int b = X509_cmp_current_time(X509_get_notAfter(c));
    if(a > 0){
        cout << "TIME COMPARATION: too early" << endl;
    }
    if(b < 0){
        cout << "TIME COMPARATION: too late" << endl;
    }

}

void init_openssl_library(void)
{
  (void)SSL_library_init();
  SSL_load_error_strings();
  /* ERR_load_crypto_strings(); */
  OPENSSL_config(NULL);
}


int main(int argc, char *argv[]) {

    long res = 1;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;
    const char *certDir;

    init_openssl_library();

    //init output file
    ofstream file;
    file.open("xjanou14-domains.csv");

    certDir = getenv(X509_get_default_cert_dir_env());
    if (!certDir){
        certDir = X509_get_default_cert_dir();
    }
    cout << "Cert path: " << certDir << endl;

    for (int i = 0; i < 100; ++i) {

        errorMsg = "";
        errorSum = 0;

        cout << endl << "Server " << i << endl;
        const SSL_METHOD* method = SSLv23_method();
        if(!(NULL != method)){
          cerr << "SERVER " << i << ": "<< "SSLv23_method" << endl;
        }

        ctx = SSL_CTX_new(method);
        if(!(ctx != NULL)) {
            cerr << "SERVER " << i << ": "<< "SSL_CTX_new" << endl;
        }
        /* Cannot fail ??? */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

        /* Cannot fail ??? */
        SSL_CTX_set_verify_depth(ctx, 5);

        /* Cannot fail ??? */
        const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
        SSL_CTX_set_options(ctx, flags);

        res = SSL_CTX_load_verify_locations(ctx,  "crocs-ca.pem", certDir);
        if(!(1 == res)) {
            cerr << "SERVER " << i << ": "<< "SSL_CTX_load_verify_locations: " << res << endl;
        }

        web = BIO_new_ssl_connect(ctx);
        if(!(web != NULL)) {
            cerr << "SERVER " << i << ": "<< "BIO_new_ssl_connect" << endl;
        }

        sprintf(number, "%02d", i);
        string url = number + host + ":" + host_port;
        cout << "URL: " << url << endl;
        res = BIO_set_conn_hostname(web, url.c_str());
        if(!(1 == res)) {
            cerr << "SERVER " << i << ": "<< "BIO_set_conn_hostname" << endl;
        }

        BIO_get_ssl(web, &ssl);
        if(!(ssl != NULL)) {
            cerr << "SERVER " << i << ": "<< "BIO_get_ssl" << endl;
        }

        const char *const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";
        res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
        if(!(1 == res)) {
            cerr << "SERVER " << i << ": "<< "SSL_set_cipher_list" << endl;
        }

        res = SSL_set_tlsext_host_name(ssl, (number + host).c_str());
        if(!(1 == res)) {
            cerr << "SERVER " << i << ": "<< "SSL_set_tlsext_host_name" << endl;
        }

        out = BIO_new_fp(stdout, BIO_NOCLOSE);
        if(!(NULL != out)) {
            cerr << "SERVER " << i << ": "<< "BIO_new_fp" << endl;
        }

        res = BIO_do_connect(web);
        if(!(1 == res)) {
            cerr << "SERVER " << i << ": "<< "BIO_do_connect: " << res << endl;
        }

        res = BIO_do_handshake(web);
        if(!(1 == res)) {
            cerr << "SERVER " << i << ": "<< "BIO_do_handshake: " << res << endl;
        }

        /**************************************************************************************/
        /**************************************************************************************/
        /* You need to perform X509 verification here. There are two documents that provide   */
        /*   guidance on the gyrations. First is RFC 5280, and second is RFC 6125. Two other  */
        /*   documents of interest are:                                                       */
        /*     Baseline Certificate Requirements:                                             */
        /*       https://www.cabforum.org/Baseline_Requirements_V1_1_6.pdf                    */
        /*     Extended Validation Certificate Requirements:                                  */
        /*       https://www.cabforum.org/Guidelines_v1_4_3.pdf                               */
        /*                                                                                    */
        /* Here are the minimum steps you should perform:                                     */
        /*   1. Call SSL_get_peer_certificate and ensure the certificate is non-NULL. It      */
        /*      should never be NULL because Anonymous Diffie-Hellman (ADH) is not allowed.   */
        /*   2. Call SSL_get_verify_result and ensure it returns X509_V_OK. This return value */
        /*      depends upon your verify_callback if you provided one. If not, the library    */
        /*      default validation is fine (and you should not need to change it).            */
        /*   3. Verify either the CN or the SAN matches the host you attempted to connect to. */
        /*      Note Well (N.B.): OpenSSL prior to version 1.1.0 did *NOT* perform hostname   */
        /*      verification. If you are using OpenSSL 0.9.8 or 1.0.1, then you will need     */
        /*      to perform hostname verification yourself. The code to get you started on     */
        /*      hostname verification is provided in print_cn_name and print_san_name. Be     */
        /*      sure you are sensitive to ccTLDs (don't navively transform the hostname       */
        /*      string). http://publicsuffix.org/ might be helpful.                           */
        /*                                                                                    */
        /* If all three checks succeed, then you have a chance at a secure connection. But    */
        /*   its only a chance, and you should either pin your certificates (to remove DNS,   */
        /*   CA, and Web Hosters from the equation) or implement a Trust-On-First-Use (TOFU)  */
        /*   scheme like Perspectives or SSH. But before you TOFU, you still have to make     */
        /*   the customary checks to ensure the certifcate passes the sniff test.             */
        /*                                                                                    */
        /* Happy certificate validation hunting!                                              */
        /**************************************************************************************/
        /**************************************************************************************/


        /* Step 1: verify a server certifcate was presented during negotiation */
        /* https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html          */
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) { X509_free(cert); } /* Free immediately */
        if(NULL == cert) {
            cerr << "SERVER " << i << ": "<< "SSL_get_peer_certificate" << endl;
        }

        /* Step 2: verify the result of chain verifcation             */
        /* http://www.openssl.org/docs/ssl/SSL_get_verify_result.html */
        /* Error codes: http://www.openssl.org/docs/apps/verify.html  */
        res = SSL_get_verify_result(ssl);
        if(!(X509_V_OK == res)) {
            cerr << "SERVER " << i << ": "<< "SSL_get_verify_result" << res << endl;
        }

//        /* Step 3: hostname verifcation.   */
        /* zdroj https://wiki.openssl.org/index.php/Hostname_validation */
        HostnameValidationResult resultHostname = validate_hostname((number + host).c_str(), cert);
        if(resultHostname != MatchFound) {
            errorSum += MIDDLE_ERROR;
            errorMsg += "Cannot match hostname.";
            cerr << "MY_ERROR: SERVER " << i << ": " << "Hostname validation result: " << resultHostname << endl;
        }

        if(out)
            BIO_free(out);


        // print result to file
        int classError = errorSum + 1;
        if(classError > 4){
            classError = 4;
        }

        file << (number + host) << ", " << classError << ", " << errorMsg;
        if(i < 99){
            file << endl;
        }
    }

    file.close();

    if(web != NULL)
      BIO_free_all(web);

    if(NULL != ctx)
      SSL_CTX_free(ctx);
    return 0;
}


/*****************************************************************
 *   public key alg type, key length
 * zdroj: http://www.zedwood.com/article/c-openssl-parse-x509-certificate-pem
******************************************************************/

//----------------------------------------------------------------------
string public_key_type(X509 *x509)
{
    EVP_PKEY *pkey=X509_get_pubkey(x509);
    int key_type = EVP_PKEY_type(pkey->type);
    EVP_PKEY_free(pkey);
    if (key_type==EVP_PKEY_RSA) return "rsa";
    if (key_type==EVP_PKEY_DSA) return "dsa";
    if (key_type==EVP_PKEY_DH)  return "dh";
    if (key_type==EVP_PKEY_EC)  return "ecc";
    return "";
}
//----------------------------------------------------------------------
int public_key_size(X509 *x509)
{
    EVP_PKEY *pkey=X509_get_pubkey(x509);
    int key_type = EVP_PKEY_type(pkey->type);
    int keysize = -1; //or in bytes, RSA_size() DSA_size(), DH_size(), ECDSA_size();
    keysize = key_type==EVP_PKEY_RSA && pkey->pkey.rsa->n ? BN_num_bits(pkey->pkey.rsa->n) : keysize;
    keysize = key_type==EVP_PKEY_DSA && pkey->pkey.dsa->p ? BN_num_bits(pkey->pkey.dsa->p) : keysize;
    keysize = key_type==EVP_PKEY_DH  && pkey->pkey.dh->p  ? BN_num_bits(pkey->pkey.dh->p) : keysize;
    keysize = key_type==EVP_PKEY_EC  ? EC_GROUP_get_degree(EC_KEY_get0_group(pkey->pkey.ec)) : keysize;
    EVP_PKEY_free(pkey);
    return keysize;
}

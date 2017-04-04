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

using namespace std;

static const char *const PIPE_SERVER_2_CLIENT = "xjanou14_pipe_s2c";
static const char *const PIPE_CLIENT_2_SERVER = "xjanou14_pipe_c2s";

int log(string mode, string message);
void startServer();
void startClient();
void sendMsg(int fdSendingPipe, unsigned char *msg);
unsigned char *readMsg(int fdReceivingPipe);
void init_DH(int fdSendingPipe, int fdReceivingPipe, bool isServer, void **pVoid);
DH *getDH2048();
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
void initAES();
void decryptMsg(const void *secret, unsigned char *decryptedtext, unsigned char *str);
int encryptMsg(const void *secret, unsigned char *plaintext, unsigned char **ciphertext);
void cleanUp(void *secret);
void sha256Ecription(unsigned char *text, unsigned char **buf);

void oneClientCycle(const void *secret, int fdSendingPipe, int fdReceivingPipe, unsigned char *plaintext);

void oneServerCycle(const void *secret, int fdSendingPipe, int fdReceivingPipe);

void encryptAndSend(const void *secret, int fdSendingPipe, unsigned char *plaintext);

int main(int argc, char *argv[]) {

    if(argc < 2){
        fprintf(stderr, "Bad number of arguments\n");
        return EXIT_FAILURE;
    }

    string mode(argv[1]);

    //Vytvoreni pojmenovanych rour
    int result1 = mkfifo(PIPE_CLIENT_2_SERVER, S_IRUSR | S_IWUSR);
    if (result1 < 0) {
        perror ("mknod"); // ignorovat, pipy mohli byt vytvoreny drive
    }

    int result2 = mkfifo(PIPE_SERVER_2_CLIENT, S_IRUSR | S_IWUSR);
    if (result2 < 0) {
        perror ("mknod"); // ignorovat, pipy mohli byt vytvoreny drive
    }

    // start modu klient nebo server
    if(mode=="-s"){
        startServer();
    } else {
        startClient();
    }
    return 0;
}

/**
 * Spusti cinnost programu v modu klient
 */
void startClient() {
    // sdilene tajemstvi vytvorene algoritmem DH
    void *secret;

    // pojmenovane roury pro komunikaci se serverem
    int fdSendingPipe, fdReceivingPipe;


    // otevreni routy pro odesilani
    fdSendingPipe = open(PIPE_CLIENT_2_SERVER, O_WRONLY);
    if (fdSendingPipe < 1/* || fdReceivingPipe < 1*/){ perror("Open: "); }
    //otevreni roury pro prijimani
    fdReceivingPipe = open(PIPE_SERVER_2_CLIENT, O_RDONLY);
    if (fdReceivingPipe < 1/* || fdReceivingPipe < 1*/){ perror("Open: "); }

    //inicializace DH a AES
    init_DH(fdSendingPipe, fdReceivingPipe, false, &secret);
    initAES();

    // plain text
    unsigned char *plaintext = (unsigned char *) "Some random string, bla bla bla bla";

    // odesle zpravu, prijme hash a porovna ho s hashem zpravy
    oneClientCycle(secret, fdSendingPipe, fdReceivingPipe, plaintext);

    // uvolneni pameti a zavreni rour
    cleanUp(secret);
    close (fdReceivingPipe);
    close (fdSendingPipe);
}
/**
 * Spusti cinnost programu v modu klient
 */
void startServer() {
    // sdilene tajemstvi vytvorene algoritmem DH
    void *secret;

    // pojmenovane roury pro komunikaci s klientem
    int fdSendingPipe, fdReceivingPipe;
    char const * msg = "Hello too";

    // otevreni roury pro prijimani
    fdReceivingPipe = open(PIPE_CLIENT_2_SERVER, O_RDONLY);
    if (fdReceivingPipe < 1){ perror("Open: "); }
    // otevreni routy pro odesilani
    fdSendingPipe = open(PIPE_SERVER_2_CLIENT, O_WRONLY);
    if (fdSendingPipe < 1){ perror("Open: "); }

    init_DH(fdSendingPipe, fdReceivingPipe, true, &secret);
    initAES();

    // prijme zpravu, vytvori hash a ten odesle clientovi
    oneServerCycle(secret, fdSendingPipe, fdReceivingPipe);

    // uvolneni pameti a zavreni rour
    cleanUp(secret);
    close (fdReceivingPipe);
    close (fdSendingPipe);
}

void oneServerCycle(const void *secret, int fdSendingPipe, int fdReceivingPipe) {

    // prijmuti zpravy od klienta
    unsigned char *str = readMsg(fdReceivingPipe);
    unsigned char *decText = new unsigned char[strlen((char *)str) + 1];

    //desifrovani zpravy od klienta -> ziskani plaintextu
    decryptMsg(secret, decText, str);
    delete [] str;

    unsigned char *buffer = new unsigned char[65];
    // vytvoreni sha256 hashe z plaintextu prijete zpravy
    sha256Ecription(decText, &buffer);
    //cout << "Server hash: " << buffer << endl;

    // odeslani hashe zpet na klienta
    write(fdSendingPipe, buffer, 65);

    delete [] decText;
}

void oneClientCycle(const void *secret, int fdSendingPipe, int fdReceivingPipe, unsigned char *plaintext) {
    encryptAndSend(secret, fdSendingPipe, plaintext);

    // hash
    unsigned char *buffer = new unsigned char[65];
    sha256Ecription(plaintext, &buffer);
    cout << "Original hash: " << buffer << endl;

    // hash from server
    unsigned char *serverHash = readMsg(fdReceivingPipe);
    cout << "Server hash: " << serverHash << endl;
    // comparation
    cout << "Compare: " << memcmp(buffer, serverHash, 64) << endl;

    delete [] buffer;
    delete [] serverHash;
}

void encryptAndSend(const void *secret, int fdSendingPipe, unsigned char *plaintext) {
    unsigned char *ciphertext = new unsigned char[strlen((char *) plaintext) * 2 + 1];
    // encrypt by aes
    int ciphertext_len = encryptMsg(secret, plaintext, &ciphertext);

    // send to server
    write(fdSendingPipe, ciphertext, ciphertext_len);
    delete [] ciphertext;
}

void cleanUp(void *secret) {
    OPENSSL_free(secret);
    EVP_cleanup();
    ERR_free_strings();
}

int encryptMsg(const void *secret, unsigned char *plaintext, unsigned char **ciphertext) {
    int ciphertext_len;

    unsigned char key[32];
    unsigned char iv[16];
    memset(key, 0, 32);
    memset(iv, 0, 16);

    strncpy((char *) key, (char *)secret, 31);
//    cout << "key: " << key << endl;
    strncpy((char *) iv, (char *)secret + 32, 15);
//    cout << "iv: " << iv << endl;
    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, *ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
//    BIO_dump_fp (stdout, (const char *) *ciphertext, ciphertext_len);
    cout << "MSG:" << ciphertext << endl;
    //send
    return ciphertext_len;
}

void initAES() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void decryptMsg(const void *secret, unsigned char *decryptedtext, unsigned char *str) {/* A 256 bit key */
    unsigned char key[32];
    unsigned char iv[16];
    memset(key, 0, 32);
    memset(iv, 0, 16);

    strncpy((char *) key, (char *)secret, 31);
    cout << "key: " << key << endl;
    strncpy((char *) iv, (char *)secret + 32, 15);
    cout << "iv: " << iv << endl;

    int decryptedtext_len;

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(str, strlen((char *) str), key, iv, decryptedtext);
    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
//    printf("%s\n", *decryptedtext);
}


void init_DH(int fdSendingPipe, int fdReceivingPipe, bool isServer, void **secret) {
    /**
     * Duffie hellman
     */
    DH *privkey;
    int codes;
    int secret_size;

    /* Generate the parameters to be used */
//    if(NULL == (privkey = DH_new()));// handleErrors();
//    if(1 != DH_generate_parameters_ex(privkey, 2048, DH_GENERATOR_2, NULL));// handleErrors();

    privkey = getDH2048();

    if(1 != DH_check(privkey, &codes));// handleErrors();
    if(codes != 0)
    {
        /* Problems have been found with the generated parameters */
        /* Handle these here - we'll just abort for this example */
        printf("DH_check failed\n");
        abort();
    }

    /* Generate the public and private key pair */
    if(1 != DH_generate_key(privkey));// handleErrors();

    cout << "G:" << privkey->g << endl;
    /* Send the public key to the peer.
    * How this occurs will be specific to your situation (see main text below) */
    unsigned char *pub_key_2_send;
    BIGNUM *pubkey = NULL;
    if(isServer) {
        pub_key_2_send = (unsigned char *) BN_bn2dec(privkey->pub_key);
        sendMsg(fdSendingPipe, pub_key_2_send);

        /* Receive the public key from the peer. In this example we're just hard coding a value */
        int len;
        unsigned char *received_pub_key = readMsg(fdReceivingPipe);
        if (0 == (BN_dec2bn(&pubkey, (char *) received_pub_key)));// handleErrors();
        delete [] received_pub_key;
    } else {
        /* Receive the public key from the peer. In this example we're just hard coding a value */
        int len;
        unsigned char *received_pub_key = readMsg(fdReceivingPipe);
        if (0 == (BN_dec2bn(&pubkey, (char *) received_pub_key)));// handleErrors();
        delete [] received_pub_key;

        unsigned char *pub_key_2_send = (unsigned char *) BN_bn2dec(privkey->pub_key);
        sendMsg(fdSendingPipe, pub_key_2_send);
    }
    /* Compute the shared secret */
    if(NULL == (*secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(privkey)))));// handleErrors();

    if(0 > (secret_size = DH_compute_key((unsigned char *) *secret, pubkey, privkey)));// handleErrors();

/* Do something with the shared secret */
/* Note secret_size may be less than DH_size(privkey) */
//    printf("The shared secret is:\n");
//    BIO_dump_fp(stdout, (const char *) *secret, secret_size);

    BN_free(pubkey);
    DH_free(privkey);
}

void sendMsg(int fdSendingPipe, unsigned char *msg){
    write(fdSendingPipe, msg, strlen((const char *) msg) + 1);
}

unsigned char *readMsg(int fdReceivingPipe) {
    cout<< "0" << endl;
    unsigned char * buf = new unsigned char[2048];
    cout<< "1" << endl;
    read(fdReceivingPipe, buf, 2048);
    cout<< "2" << endl;
    return buf;
}

//void clientCommunication(int fdSendingPipe, int fdReceivingPipe, const char *msg) {
//    char buf [100];
//
//    for(int i = 0; i < 3; i++) {
//        write(fdSendingPipe, msg, strlen(msg) + 1);
//
//        /**
//         * read
//         */
//        int size = read(fdReceivingPipe, buf, 100);
//        printf("%d:%s\n", size, buf);
//    }
//}
//
//void serverCommunication(int fdSendingPipe, int fdReceivingPipe, const char *msg) {
//    char buf [100];
//
//    for(int i = 0; i < 3; i++) {
//        /**
//         * read
//         */
//        int size = read(fdReceivingPipe, buf, 100);
//        printf("%d:%s\n", size, buf);
//
//        /**
//         * write
//         */
//        write(fdSendingPipe, msg, strlen(msg) + 1);
//    }
//}

int log(string mode, string message){
    cout << mode << ": " << message << endl;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) ;//handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        ; //handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        ; //handleErrors();
    ciphertext_len = len;
    cout << "LEN:" << len << endl;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)); //handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) ; //handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        ; //handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        ; //handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) ; //handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);

    return plaintext_len;
}

/**
 * ***************************** SHA 256 *********************************
 */

void sha256Ecription(unsigned char *text, unsigned char **buf)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_256;
    SHA256_Init(&sha_256);
    SHA256_Update(&sha_256, text, strlen((char *)text));
    SHA256_Final(hash, &sha_256);

    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(((char *) *buf) + (i * 2), "%02x", hash[i]);
    }

    (*buf)[64] = 0;
}

// pre-generated DH params
/*-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA11wKvHPFFtgQCGMhBzenMfyM45Md1P/vctW3CISnmPLzbfBpX5xw
        CddxR7kU7t3VewU1/HMd9smsZhWz83xJpg5S3EYVDougFp2PIY2R+hhJC0HRXl2R
        wNjU/vDsI9mIQK+2TrzM29Zt33bMvxliP1I8GXAgIQSY5dvDtivw0yLR9eY3v+cB
        d/fcrHsSCE3l4lb6Ld3wWm1dUBy8EKhpqUbi1MkW5WsbpkLdr+rcsvj5ywzEJBDq
        eVVkcJKI4TaByElOScXbQbRYaf/lL7+szYw77IfWiCVQCNlHtKcvS43Dm8Idkq7x
        N3r7NsoBIUdUE3j9h/Us8NAizqaB155W0wIBAg==
-----END DH PARAMETERS-----*/
DH *getDH2048()
{
    static unsigned char dh2048_p[]={
            0xD7,0x5C,0x0A,0xBC,0x73,0xC5,0x16,0xD8,0x10,0x08,0x63,0x21,
            0x07,0x37,0xA7,0x31,0xFC,0x8C,0xE3,0x93,0x1D,0xD4,0xFF,0xEF,
            0x72,0xD5,0xB7,0x08,0x84,0xA7,0x98,0xF2,0xF3,0x6D,0xF0,0x69,
            0x5F,0x9C,0x70,0x09,0xD7,0x71,0x47,0xB9,0x14,0xEE,0xDD,0xD5,
            0x7B,0x05,0x35,0xFC,0x73,0x1D,0xF6,0xC9,0xAC,0x66,0x15,0xB3,
            0xF3,0x7C,0x49,0xA6,0x0E,0x52,0xDC,0x46,0x15,0x0E,0x8B,0xA0,
            0x16,0x9D,0x8F,0x21,0x8D,0x91,0xFA,0x18,0x49,0x0B,0x41,0xD1,
            0x5E,0x5D,0x91,0xC0,0xD8,0xD4,0xFE,0xF0,0xEC,0x23,0xD9,0x88,
            0x40,0xAF,0xB6,0x4E,0xBC,0xCC,0xDB,0xD6,0x6D,0xDF,0x76,0xCC,
            0xBF,0x19,0x62,0x3F,0x52,0x3C,0x19,0x70,0x20,0x21,0x04,0x98,
            0xE5,0xDB,0xC3,0xB6,0x2B,0xF0,0xD3,0x22,0xD1,0xF5,0xE6,0x37,
            0xBF,0xE7,0x01,0x77,0xF7,0xDC,0xAC,0x7B,0x12,0x08,0x4D,0xE5,
            0xE2,0x56,0xFA,0x2D,0xDD,0xF0,0x5A,0x6D,0x5D,0x50,0x1C,0xBC,
            0x10,0xA8,0x69,0xA9,0x46,0xE2,0xD4,0xC9,0x16,0xE5,0x6B,0x1B,
            0xA6,0x42,0xDD,0xAF,0xEA,0xDC,0xB2,0xF8,0xF9,0xCB,0x0C,0xC4,
            0x24,0x10,0xEA,0x79,0x55,0x64,0x70,0x92,0x88,0xE1,0x36,0x81,
            0xC8,0x49,0x4E,0x49,0xC5,0xDB,0x41,0xB4,0x58,0x69,0xFF,0xE5,
            0x2F,0xBF,0xAC,0xCD,0x8C,0x3B,0xEC,0x87,0xD6,0x88,0x25,0x50,
            0x08,0xD9,0x47,0xB4,0xA7,0x2F,0x4B,0x8D,0xC3,0x9B,0xC2,0x1D,
            0x92,0xAE,0xF1,0x37,0x7A,0xFB,0x36,0xCA,0x01,0x21,0x47,0x54,
            0x13,0x78,0xFD,0x87,0xF5,0x2C,0xF0,0xD0,0x22,0xCE,0xA6,0x81,
            0xD7,0x9E,0x56,0xD3,
    };
    static unsigned char dh2048_g[]={
            0x02,
    };
    DH *dh;

    if ((dh=DH_new()) == NULL) return(NULL);
    dh->p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
    dh->g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
    if ((dh->p == NULL) || (dh->g == NULL))
    { DH_free(dh); return(NULL); }
    return(dh);
}
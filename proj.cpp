/**
 * 1. projekt do KRY - Sifrovany tunel
 * xjanou14, Martin Janousek
 */

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

static const int ITERATION = 5;


void startServer();
void startClient();
void sendMsg(int fdSendingPipe, unsigned char *msg);
unsigned int readMsg(int fdReceivingPipe, unsigned char ** readMsg);
void init_DH(int fdSendingPipe, int fdReceivingPipe, bool isServer, void **pVoid);
DH *getDH2048();
int decrypt(unsigned char *cipherText, int ctLen, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int encrypt(unsigned char *plaintext, int ptLen, unsigned char *key, unsigned char *iv, unsigned char *cipherText);
void initAES();
void decryptMsg(const void *secret, unsigned char *decryptedtext, unsigned char *str, int i);
int encryptMsg(const void *secret, unsigned char *plaintext, unsigned char **cipherText);
void cleanUp(void *secret);
void sha256Ecription(unsigned char *text, unsigned char **buf);

void oneClientCycle(const void *secret, int fdSendingPipe, int fdReceivingPipe, unsigned char *plaintext);

void oneServerCycle(const void *secret, int fdSendingPipe, int fdReceivingPipe);

void encryptAndSend(const void *secret, int fdSendingPipe, unsigned char *plaintext);

unsigned char* generateString();

int main(int argc, char *argv[]) {

    if(argc < 2){
        fprintf(stderr, "Bad number of arguments\n");
        return EXIT_FAILURE;
    }

    string mode(argv[1]);

    //Vytvoreni pojmenovanych rour
    int r1 = mkfifo(PIPE_CLIENT_2_SERVER, S_IRUSR | S_IWUSR);
    if (r1 < 0) {
//        perror ("mknod"); // ignorovat, pipy mohli byt vytvoreny drive
    }

    int r2 = mkfifo(PIPE_SERVER_2_CLIENT, S_IRUSR | S_IWUSR);
    if (r2 < 0) {
//        perror ("mknod"); // ignorovat, pipy mohli byt vytvoreny drive
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
    if (fdSendingPipe < 1) { perror("Open: "); }
    //otevreni roury pro prijimani
    fdReceivingPipe = open(PIPE_SERVER_2_CLIENT, O_RDONLY);
    if (fdReceivingPipe < 1) { perror("Open: "); }

    //inicializace DH a AES
    init_DH(fdSendingPipe, fdReceivingPipe, false, &secret);
    initAES();

    for (int i = 0; i < ITERATION; i++) {
        // plain text
        unsigned char *plainText = generateString();
        // odesle zpravu, prijme hash a porovna ho s hashem zpravy
        oneClientCycle(secret, fdSendingPipe, fdReceivingPipe, plainText);
        delete[] plainText;
    }

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

    // otevreni roury pro prijimani
    fdReceivingPipe = open(PIPE_CLIENT_2_SERVER, O_RDONLY);
    if (fdReceivingPipe < 1){ perror("Open: "); }
    // otevreni routy pro odesilani
    fdSendingPipe = open(PIPE_SERVER_2_CLIENT, O_WRONLY);
    if (fdSendingPipe < 1){ perror("Open: "); }

    init_DH(fdSendingPipe, fdReceivingPipe, true, &secret);
    initAES();

    for (int i = 0; i < ITERATION; i++) {
        // prijme zpravu, vytvori hash a ten odesle clientovi
        oneServerCycle(secret, fdSendingPipe, fdReceivingPipe);
    }
    // uvolneni pameti a zavreni rour
    cleanUp(secret);
    close(fdReceivingPipe);
    close(fdSendingPipe);
}

/**
 * Jeden cyklus na serveru (prijeti zpravy, vytvoreni hashe a jeho odeslani na klienta)
 */
void oneServerCycle(const void *secret, int fdSendingPipe, int fdReceivingPipe) {

    // prijmuti zpravy od klienta
    unsigned char *str = NULL;
    int len = readMsg(fdReceivingPipe, &str);
    // cout << "Prijmuta zprava: " << str <<endl;
    unsigned char *decText = new unsigned char[len+1];

    //desifrovani zpravy od klienta -> ziskani plaintextu
    decryptMsg(secret, decText, str, len);
    // cout << "Decrypt zprava: " << decText <<endl;
    delete [] str;

    unsigned char *buffer = new unsigned char[65];
    // vytvoreni sha256 hashe z plaintextu prijete zpravy
    sha256Ecription(decText, &buffer);
    // cout << "Server hash: " << buffer << endl;

    // odeslani hashe zpet na klienta
    encryptAndSend(secret, fdSendingPipe, buffer);

    delete [] decText;
}

/**
 * Jeden cyklus klienta (vytvoreni nahodne zpravy, odeslani na server,
 * prijeti hashe ze serveru a porovnani s vypocitanym hashem)
 */
void oneClientCycle(const void *secret, int fdSendingPipe, int fdReceivingPipe, unsigned char *plainText) {
    encryptAndSend(secret, fdSendingPipe, plainText);
//    cout << "Msg was send." << endl;

    // hash
    unsigned char *buffer = new unsigned char[65];
    sha256Ecription(plainText, &buffer);
    // cout << "Original hash: " << buffer << endl;

    // prijeti odpovedi (hashe) ze serveru
    unsigned char *serverHash = NULL;
    int len = readMsg(fdReceivingPipe, &serverHash);
    unsigned char *decHash = new unsigned char[len+1];
    // desifrovani hashe
    decryptMsg(secret, decHash, serverHash, len);
    delete [] serverHash;

    // cout << "Server hash: " << decHash << endl;
    // comparation

    //porovnani, zda odpovida hash zpravy s hashem prijetym ze serveru
    if(int r = memcmp(buffer, decHash, 64) != 0 ){
        cerr << "[Comperation] Error: Hashes are different" << endl;
    } else {
        cout << "[Comperation] OK" << endl;
    }

    delete [] buffer;
    delete [] decHash;
}

/**
 * Zasifrovani zpravy pomoci AES CBC a odeslani
 */
void encryptAndSend(const void *secret, int fdSendingPipe, unsigned char *plainText) {
    int len = (int) (strlen((char *) plainText) * 2 + 1);
    unsigned char *cipherText = new unsigned char[len];
    // zasifrovani pomoci aes
    int ctLen = encryptMsg(secret, plainText, &cipherText);

    // odeslani ciphertextu
    write(fdSendingPipe, cipherText, ctLen);
    delete [] cipherText;
}

void cleanUp(void *secret) {
    OPENSSL_free(secret);
    EVP_cleanup();
    ERR_free_strings();
}

/**
 * zasifrovani zpravy
 */
int encryptMsg(const void *secret, unsigned char *plainText, unsigned char **cipherText) {
    int ctLen;

    /**
     * redukce klice - prvnich 32 bytu (256 bitu) ze secretu se pouzije jako klic
     * dalsich 16 bytu se pouzije jako iv
     */
    unsigned char key[33];
    unsigned char iv[17];
    memset(key, 0, 33);
    memset(iv, 0, 17);

    strncpy((char *) key, (char *)secret, 32);
//    cout << "key: " << key << endl;
    strncpy((char *) iv, (char *)secret + 32, 16);
//    cout << "iv: " << iv << endl;

    // samotne zasifrovani
    int len = strlen((char *)plainText);
    ctLen = encrypt(plainText, len, key, iv, *cipherText);
    // cout << "Ciphertext: " << *cipherText << endl;
    return ctLen;
}

void initAES() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

/**
 * desifrovani zpravy
 */
void decryptMsg(const void *secret, unsigned char *decryptedtext, unsigned char *str, int len) {/* A 256 bit key */

    /**
     * redukce klice - prvnich 32 bytu (256 bitu) ze secretu se pouzije jako klic
     * dalsich 16 bytu se pouzije jako iv
     */
    unsigned char key[33];
    unsigned char iv[17];
    memset(key, 0, 33);
    memset(iv, 0, 17);

    strncpy((char *) key, (char *)secret, 32);
    // cout << "key: " << key << endl;
    strncpy((char *) iv, (char *)secret + 32, 16);
    // cout << "iv: " << iv << endl;

    int decryptedtext_len;

    // samotne zasifrovani
    decryptedtext_len = decrypt(str, len, key, iv, decryptedtext);
    // cout << "Decrypted lng: " << decryptedtext_len << endl;
    // pridani ukoncovaciho symbolu nakonec stringu
    decryptedtext[decryptedtext_len] = '\0';
}


/**
 * inicializace algoritmu DH
 */
void init_DH(int fdSendingPipe, int fdReceivingPipe, bool isServer, void **secret) {

    DH *privateKey;
    int codes;

    // ziskani p a g pro algoritmus DH
    privateKey = getDH2048();
    DH_check(privateKey, &codes);

    // vygenerovani privatniho a verejneho klice
    DH_generate_key(privateKey);

    // odeslani verejneho klice serveru/clientu
    unsigned char *pubKeyToSend;
    BIGNUM *publicKey = NULL;
    if(!isServer) {
        // odeslani verejneho klice
        pubKeyToSend = (unsigned char *) BN_bn2dec(privateKey->pub_key);
        sendMsg(fdSendingPipe, pubKeyToSend);

        // prijmuti verejneho klice od serveru
        unsigned char *receivedPubKey = NULL;
        readMsg(fdReceivingPipe, &receivedPubKey);
        BN_dec2bn(&publicKey, (char *) receivedPubKey);
        delete [] receivedPubKey;
    } else {
        // prijmuti verejneho klice od clienta
        unsigned char *receivedPubKey = NULL;
        readMsg(fdReceivingPipe, &receivedPubKey);
        BN_dec2bn(&publicKey, (char *) receivedPubKey);
        delete [] receivedPubKey;

        // odeslani verejneho klice
        unsigned char *pubKeyToSend = (unsigned char *) BN_bn2dec(privateKey->pub_key);
        sendMsg(fdSendingPipe, pubKeyToSend);
    }
    // vypocitani sdileneho tajemstvi (secret).
    // Toto tajemstvi je shodne na clientu i serveru
    *secret = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(privateKey)));
    DH_compute_key((unsigned char *) *secret, publicKey, privateKey);

    // uvolneni pameti
    BN_free(publicKey);
    DH_free(privateKey);
}

void sendMsg(int fdSendingPipe, unsigned char *msg){
    size_t len = strlen((const char *) msg) + 1;
    write(fdSendingPipe, msg, len);
}

unsigned int readMsg(int fdReceivingPipe, unsigned char **readMsg) {
    unsigned char * buf = new unsigned char[2048];
    ssize_t x = read(fdReceivingPipe, buf, 2048);
    *readMsg = buf;
    return (int) x;
}

int encrypt(unsigned char *plainText, int ptLen, unsigned char *key,
            unsigned char *iv, unsigned char *cipherText)
{

    EVP_CIPHER_CTX *ctx;
    int len, ctLen;

    ctx = EVP_CIPHER_CTX_new();

    // Inicializace sifry AES
    // cout << "Control: key:" << strlen((const char *) key) << " iv:" << strlen((const char *) iv) << endl;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Zasifrovani plaintextu a ulozeni vysledku do ciphertext
    EVP_EncryptUpdate(ctx, cipherText, &len, plainText, ptLen);
    ctLen = len;

    // Dokonceni sifry
    EVP_EncryptFinal_ex(ctx, cipherText + len, &len);
    ctLen += len;

    // Uvolneni pameti
    EVP_CIPHER_CTX_free(ctx);

    return ctLen;
}

int decrypt(unsigned char *cipherText, int ctLen, unsigned char *key,
            unsigned char *iv, unsigned char *plainText)
{

    EVP_CIPHER_CTX *ctx;
    int len, ptLen;

    ctx = EVP_CIPHER_CTX_new();

    // Inicializace sifry AES
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Desifrovani pomoci AES
    EVP_DecryptUpdate(ctx, plainText, &len, cipherText, ctLen);
    ptLen = len;

    // Dokonceni desifrovani
    if(1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len)) ; //handleErrors();
    ptLen += len;

    // Uvolneni pameti
    EVP_CIPHER_CTX_cleanup(ctx);

    return ptLen;
}

/**
 * funkce generujici nahodnou zpravu
 */
unsigned char* generateString(){
    unsigned char * buf = new unsigned char [33];
    for(size_t i = 0; i < 32; i++) {
        buf[i] = (unsigned char) (rand() % 256);
    }
    buf[33] = '\0';
//    cout << "Generated string: " << buf << endl;
    return buf;
}

/**
 * Vytvoreni sha256 hashe z textu
 */
void sha256Ecription(unsigned char *text, unsigned char **buf)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    size_t len = strlen((char *)text);
    SHA256_CTX sha_256;
    SHA256_Init(&sha_256);
    SHA256_Update(&sha_256, text, len);
    SHA256_Final(hash, &sha_256);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(((char *)*buf) + (i*2), "%02x", hash[i]);
    }

    (*buf)[64] = '\0';
}

// vygenerovana funkce systemem
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
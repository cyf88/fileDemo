//
// Created by cyf on 2024/2/29.
//

#include "tri_gmssl.h"
#include <openssl/skf.h>
#include <openssl/gmapi.h>
#include <openssl/pem.h>


ULONG TRI_CONVERT_CRYPTDATA_TO_ECCCIPHERBLOB(unsigned char* encryptData, unsigned long encryptDataLen, unsigned char** eccblob) {
    const unsigned char* p = encryptData;
    ECCCIPHERBLOB*  ret = d2i_ECCCIPHERBLOB(NULL, &p, encryptDataLen);
    if (ret != NULL) {
        *eccblob = (unsigned char *)ret;
    }
    return 0;
}

ULONG TRI_CONVERT_ECCCIPHERBLOB_TO_CRYPTDATA(unsigned char** encryptData, unsigned long* encryptDataLen, unsigned char* eccblob) {
    ECCCIPHERBLOB* origin = (ECCCIPHERBLOB*)eccblob;
    int len = i2d_ECCCIPHERBLOB(origin, encryptData);
    *encryptDataLen = len;
    return 0;
}

ULONG TRI_GET_ECCPUBLICKEYBLOB_FROM_CERTDATA(unsigned char* cert, int certLen, ECCPUBLICKEYBLOB* pbBlob) {
    if (cert == NULL || certLen <= 100) {
        return -1;
    }
    BIO* certBio = NULL;
    const unsigned char* p = cert;
    X509* x509 = d2i_X509(NULL, (const unsigned char**)&p, certLen);
    if (!x509) {
        certBio = BIO_new(BIO_s_mem());
        BIO_write(certBio, cert, certLen);
        x509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
        if (x509 == NULL) {
            return -1;
        }
    }

    EVP_PKEY* pkey = X509_get_pubkey(x509);
    EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    EC_KEY_get_ECCPUBLICKEYBLOB(ec_key, pbBlob);

    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    if (certBio) {
        BIO_free(certBio);
    }

    return 0;

}

ULONG TRI_GET_ECCPUBLICKEYBLOB_FROM_CERTFILE(const char* filepath, ECCPUBLICKEYBLOB* pbBlob) {


    FILE* fp = fopen(filepath, "r");
    X509* cert = d2i_X509_fp(fp, NULL);
    if (cert == NULL) {
        fclose(fp);
        fp = fopen(filepath, "r");
        cert = PEM_read_X509(fp, NULL, NULL, NULL);
    }
    if (cert == NULL) {
        fclose(fp);
        printf("invalid cert:%s\n", filepath);
        return false;
    }

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    //skf 无法导入公钥 先用gmssl转
    EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    EC_KEY_get_ECCPUBLICKEYBLOB(ec_key, pbBlob);

    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    //X509_free(cert);
    return 0;
}



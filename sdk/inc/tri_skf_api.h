#ifndef __triskfapi__
#define __triskfapi__

#include "type_def.h"
#include "openssl/ossl_typ.h"


struct ECDSA_SIG_st {
    BIGNUM* r;
    BIGNUM* s;
};

/*****加解密*****/
//私钥解密vkek   sm2
ULONG TRI_GET_DECRYPT_VKEK(unsigned char* encrypt_vkek, ULONG encrypt_vkek_len, unsigned char* decrypt_vkek, ULONG* decrypt_vkek_len);
// vkek -> vek
ULONG TRI_SM4_ECB(unsigned char* secretkey, unsigned char* in, int inSize, unsigned char* out, int& outSize, bool isEncrypt);
//码流加解密
ULONG TRI_SM4_OFB(unsigned char* key, int keyLen, unsigned char* iv, int ivLen, unsigned char* in, int inSize,
                  unsigned char* out, int& outSize, bool isEncrypt);

ULONG SSL_SM4_ECB(unsigned char* secretkey, unsigned char* in, int inSize, unsigned char* out, int& outSize, bool isEncrypt);
ULONG SSL_SM4_OFB(unsigned char* key, int keyLen, unsigned char* iv, int ivLen, unsigned char* in, int inSize,
                  unsigned char* out, int& outSize, bool isEncrypt);
/*****签名*****/
ULONG TRI_GET_PUBKEY(BOOL signFlag, char** out, int* outlen);
ULONG TRI_GET_PUBLICKEYBLOB(int container, BOOL signFlag, ECCPUBLICKEYBLOB* pbBlob);
ULONG TRI_HEX_TO_PUBLICKEYBLOB(const char* hexPublicKey, ECCPUBLICKEYBLOB* pBlob);
ULONG TRI_SM3(unsigned char* plainText, ULONG plain_len, unsigned char* hash_out);
ULONG SSL_SM3(unsigned char* plainText, ULONG plain_len, unsigned char* hash_out);

//普通签名输出asn1 der
ULONG TRI_SIGNATURE( ECCPUBLICKEYBLOB signPublicKey,  unsigned char* plainText,  ULONG plain_len,
                     unsigned char* signature_out,  ULONG* signature_out_len, unsigned char* id);


//码流签名输出r,s
ULONG TRI_SIGNATURE_RS( ECCPUBLICKEYBLOB signPublicKey,  unsigned char* plainText,  ULONG plain_len,
                        unsigned char* signature_out,  ULONG& signature_out_len, unsigned char* id);

ULONG TRI_VERIFY_SIGNATURE( ECCPUBLICKEYBLOB signPubKeyBlob,  unsigned char* plainText,  ULONG plain_len,
                            unsigned char* signature_in,  ULONG signature_in_len, unsigned char* id);


ULONG SSL_VERIFY_SIGNATURE( ECCPUBLICKEYBLOB signPubKeyBlob,  unsigned char* plainText,  ULONG plain_len,
                            unsigned char* signature_in,  ULONG signature_in_len, unsigned char* id);

ULONG SSL_VERIFY_SIGNATURE_RS( ECCPUBLICKEYBLOB signPubKeyBlob,  unsigned char* plainText,  ULONG plain_len,
                               unsigned char* signature_in,  ULONG signature_in_len, unsigned char* id);


/******Ukey 文件操作***/
ULONG TRI_WRITE_DATA(const char* fileName, unsigned char* data, ULONG len);
ULONG TRI_READ_DATA(const char* fileName, unsigned char* data, ULONG* len);



/*******初始化操作***/
ULONG TRI_INIT_SKF_DEVICE( char* PIN);
ULONG TRI_READ_CLIENT_ID( char* clientId,  UINT* cliendId_len);
ULONG TRI_GET_RANDOM( ULONG randomLen,  unsigned char* random);
ULONG TRI_DESTROY_DEV();
ULONG TRI_DESTROY_CONTAINER();
ULONG TRI_DESTROY_APPLICATION();
ULONG TRI_EXPORT_CERT_TO_FILE(int flag);
ULONG TRI_TEST();


#endif // !__triskfapi__
//
// Created by cyf on 2024/2/29.
//

#ifndef FILEDEMO_TRI_GMSSL_H
#define FILEDEMO_TRI_GMSSL_H

#include <openssl/skf.h>

ULONG TRI_CONVERT_CRYPTDATA_TO_ECCCIPHERBLOB(unsigned char * encryptData,unsigned long encryptDataLen, unsigned char** eccblob);

ULONG TRI_CONVERT_ECCCIPHERBLOB_TO_CRYPTDATA(unsigned char** encryptData, unsigned long* encryptDataLen, unsigned char* eccblob);

ULONG TRI_GET_ECCPUBLICKEYBLOB_FROM_CERTDATA(unsigned char* cert,  int certLen, ECCPUBLICKEYBLOB* pbBlob);

ULONG TRI_GET_ECCPUBLICKEYBLOB_FROM_CERTFILE(const char* filepath, ECCPUBLICKEYBLOB* pbBlob);


#endif //FILEDEMO_TRI_GMSSL_H

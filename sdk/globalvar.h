//
// Created by cyf on 2024/2/27.
//

#ifndef FILEDEMO_GLOBALVAR_H
#define FILEDEMO_GLOBALVAR_H

#include <map>
#include <mutex>
#include <openssl/skf.h>
#include <thread>
#include "type_def.h"

namespace trimps {
    extern std::mutex mutex;
    extern bool isSDKInited;
    extern unsigned char authRandom[16];
    //extern char* ukeyEncPubKey;  //ukey加密公钥，附件六获取通道vkek传入
    extern ECCPUBLICKEYBLOB clientSignKey; //客户端签名公钥，做签名时候使用
    extern ECCPUBLICKEYBLOB clientEncKey; //客户端加密公钥，
    extern ECCPUBLICKEYBLOB serverSignKey; //平台端签名公钥
    extern ULONG currentDecodeId;
    extern std::map<ULONG, DecodeCtx*> decodeHandleMap;
    extern bool ukeyStatus;
    extern std::thread ukeyCheckThread;
    extern unsigned char decryptVkek[16]; //sip 通讯vkek，非视频解密vkek

}

#endif //FILEDEMO_GLOBALVAR_H

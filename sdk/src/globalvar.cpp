//
// Created by cyf on 2024/2/28.
//
#include "globalvar.h"

namespace trimps {

    std::mutex mutex;
    bool isSDKInited = false;
    unsigned char authRandom[16];// 身份鉴别随机数
    //char* ukeyEncPubKey = NULL;
    ECCPUBLICKEYBLOB clientSignKey; //客户端签名公钥，做签名时候使用
    ECCPUBLICKEYBLOB clientEncKey; //客户端加密公钥，
    ECCPUBLICKEYBLOB serverSignKey; //平台端签名公钥，验签使用
    ULONG currentDecodeId = 0;
    std::map<ULONG, DecodeCtx*> decodeHandleMap;
    FUNC_SUT_DEVEVENTMONITOR devEventCallback;   //ukey状态回调
    FUNC_SUT_SIGNVERIFYNOTIFY signNotifyCallback; //签名结果回调
    bool ukeyStatus = false;
    std::thread ukeyCheckThread;

    unsigned char decryptVkek[16];//sip 通讯vkek，非视频解密vkek

}
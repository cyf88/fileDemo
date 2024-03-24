//
// Created by cyf on 2024/2/28.
//
#include <iostream>
#include "core_api.h"
#include "globalvar.h"
#include "tri_nal.h"
#include "easylogging++.h"
#include "tri_util.h"
#include "tri_gmssl.h"
#define ELPP_THREAD_SAFE
INITIALIZE_EASYLOGGINGPP

#define DEFAULT_SECRET "1234567812345678";

void TRI_CONFIGURE_LOGGER() {

    std::string exePath = "/logs/";
    std::string logFileName = "/SanSuoDll/35114sdk.log";
    std::string fileNameWithPath = exePath + logFileName;
    std::cout << "log file path:" << fileNameWithPath << std::endl;

    //LOG(DEBUG) << " TRI_CONFIGURE_LOGGER start";
    el::Configurations defaultConf;
    defaultConf.setToDefault();
    defaultConf.set(el::Level::Debug, el::ConfigurationType::ToFile, "true");
    defaultConf.set(el::Level::Debug, el::ConfigurationType::Enabled, "true");
    //defaultConf.set(el::Level::Debug, el::ConfigurationType::Filename, fileNameWithPath);
    defaultConf.set(el::Level::Debug, el::ConfigurationType::Filename,
                    exePath + "/SanSuoDll/35114sdk_%datetime{%Y-%M-%d}.log");
    //defaultConf.set(el::Level::Debug, el::ConfigurationType::Filename,
    //			callingDllPath + "\\35114sdk_%datetime{%Y-%M-%d}.log");
    defaultConf.set(el::Level::Debug, el::ConfigurationType::MaxLogFileSize, "204857600");//200M
    defaultConf.set(el::Level::Debug, el::ConfigurationType::ToStandardOutput, "true");
    defaultConf.set(el::Level::Debug, el::ConfigurationType::Format, "[%datetime]  [%level] [%fbase:%line] : %msg");
    defaultConf.set(el::Level::Debug, el::ConfigurationType::LogFlushThreshold, "1");
    el::Loggers::reconfigureLogger("default", defaultConf);
#ifdef testEsLog
    _mkdir("E:\\es");
#endif
    LOG(DEBUG) << " TRI_CONFIGURE_LOGGER end";
}

static DecodeCtx* findDecodeCtx(ULONG key) {
    std::map<ULONG, DecodeCtx*>::iterator iter;
    iter = trimps::decodeHandleMap.find(key);
    if (iter != trimps::decodeHandleMap.end()) {
        return iter->second;
    }
    return NULL;
}

ULONG FRI_MUT_RequestChan(unsigned int* puiChan) {
    trimps::mutex.lock();
    *puiChan = ++trimps::currentDecodeId;
    DecodeCtx* decodeCtx = new DecodeCtx;
    decodeCtx->isDecode = true;
    decodeCtx->vkekmaps = new std::map<std::string, vkekInfo>();
    trimps::decodeHandleMap.insert(std::map<ULONG, DecodeCtx*>::value_type(*puiChan, decodeCtx));
    decodeCtx->nalCtx.buf = (unsigned char*)malloc(sizeof(unsigned char) * NAL_BUFFER_SIZE);
    decodeCtx->nalCtx.needHashData = (unsigned char*)malloc(sizeof(unsigned char) * NAL_BUFFER_SIZE * 3);
    decodeCtx->nalCtx.bits = new std::bitset<MAX_BITS_LENGTH>();
    decodeCtx->status = DecodeStatus::NORMAL;
    decodeCtx->streamType = StreamType::REALTIME;
    decodeCtx->security_level = 0;
    trimps::mutex.unlock();
    std::cout << "FRI_MUT_RequestChan End" << std::endl;
    //LOG(DEBUG) << "FRI_MUT_RequestChan end  puiChan:" << *puiChan;
    return 0;
}


ULONG FRI_MUT_VideoDataSecDecodeExt(unsigned int uiChan, IMG_FRAME_UNIT* pstImgData, IMG_FRAME_UNIT** ppstOutData) {

    int totalSize = sizeof(IMG_FRAME_UNIT) + NAL_BUFFER_SIZE;
    *ppstOutData = reinterpret_cast<IMG_FRAME_UNIT*>(malloc(totalSize));
    if (*ppstOutData == NULL) {
        std::cout << "FRI_MUT_VideoDataSecDecodeExt malloc mem error 1";
        return -1;
    }
    (*ppstOutData)->imgsz = 0;

    DecodeCtx* tmp = findDecodeCtx(uiChan);
    if (tmp == NULL) {
        return -1;
    }

    int authResult = -1;
    int ret = decryptNalUnitsStream(tmp, pstImgData->img_buf, pstImgData->imgsz, (*ppstOutData)->img_buf, (ULONG*)&((*ppstOutData)->imgsz), true, &authResult);
    //std::cout << "decryptNalUnitsStream authResult：" << authResult;
    if (trimps::signNotifyCallback != NULL) {
        trimps::signNotifyCallback(uiChan, authResult);
    }

    return ret;
}

VOID FRI_MUT_SafeFree(IMG_FRAME_UNIT** ppstOutData) {
    if (ppstOutData == NULL) {
        return;
    }
    if (*ppstOutData != NULL) {
        free(*ppstOutData);
        *ppstOutData = NULL;
    }
}

ULONG FRI_MUT_VkekImport(unsigned int uiChan, IPC_VKEK_INFO* pstIpcVkekInfo, ULONG ulVkekCnt) {
    DecodeCtx* tmp = findDecodeCtx(uiChan);
    if (tmp == NULL) {
        LOG(ERROR) << "uiChan: " << uiChan << " Hasn't Requested";
        return -1;
    }
    vkekInfo info;
    //ULONG ret = TRI_GET_DECRYPT_VKEK((unsigned char*)pstIpcVkekInfo->cryptkey, strlen(pstIpcVkekInfo->cryptkey),
    //	info.data, &info.dataLen);
    //if (ret != 0) {
    //	LOG(DEBUG) << "TRI_GET_DECRYPT_VKEK fail";
    //	return ret;
    //}

    //test
    memcpy(info.data, "1234567887654321", 16);
    info.dataLen = 16;
    std::map<std::string, vkekInfo>* vkekmaps = tmp->vkekmaps;
    vkekmaps->insert(std::make_pair(pstIpcVkekInfo->cryptkeyversion, info));
    return 0;
}



ULONG FRI_MUT_CertImport(unsigned int uiChan, IPC_CERT_INFO* pstIpcCertInfo) {
    DecodeCtx* tmp = findDecodeCtx(uiChan);
    if (tmp == NULL) {
        LOG(ERROR) << "uiChan: " << uiChan << " Not Found";
        return -1;
    }
    char* decode;
    int decodeLen = 0;
    int len = strlen((char*)pstIpcCertInfo->CertInfo);
    base64Decode((char*)pstIpcCertInfo->CertInfo, strlen((char*)pstIpcCertInfo->CertInfo), true,
                 &decode, &decodeLen);
    ULONG ret = TRI_GET_ECCPUBLICKEYBLOB_FROM_CERTDATA((unsigned char*)decode, decodeLen,
                                                   &tmp->streamSignkey);
    if (ret != 0) {
        LOG(ERROR) << "FRI_MUT_CertImport Fail";

    }
    return ret;
}

ULONG FRI_MUT_CertImport2(unsigned int uiChan, const char* pCertpath) {
    DecodeCtx* tmp = findDecodeCtx(uiChan);
    if (tmp == NULL) {
        LOG(ERROR) << "uiChan: " << uiChan << " Not Found";
        return -1;
    }
    ULONG ret = TRI_GET_ECCPUBLICKEYBLOB_FROM_CERTFILE(pCertpath, &tmp->streamSignkey);
    if (ret != 0) {
        LOG(ERROR) << "FRI_MUT_CertImport Fail";
    }
    return ret;
}


ULONG FRI_MUT_SetCallbackFunction(ENUM_CODE_CBFUN ecbFunCode, void* pcbFunName) {
    switch (ecbFunCode)
    {

        case CODE_CBFUN_DEVEVENTMONITOR:
        {
            trimps::devEventCallback = (FUNC_SUT_DEVEVENTMONITOR)pcbFunName;
        }
        case CODE_CBFUN_SIGNVERIFYNOTIFY:
        {
            trimps::signNotifyCallback = (FUNC_SUT_SIGNVERIFYNOTIFY)pcbFunName;
        }
        default:
            break;
    }

    return 0;
}
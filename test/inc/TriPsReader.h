//
// Created by cyf on 2024/2/29.
//

#ifndef FILEDEMO_TRIPSREADER_H
#define FILEDEMO_TRIPSREADER_H

#include "core_api.h"
#include <iostream>

#define PSBUFLEN (2 * 1024 * 1024)
#define NAL_BUFFER_SIZE 1024 * 1024

#define PS_PES_AUDIO					(0x000001C0)
#define PS_PES_VIDEO					(0x000001E0)
enum
{
    I_frame = 1,
    B_frame = 2,
    P_frame = 3,
    Audio_frame = 4,
};
typedef enum _tagEmStreamType
{
    _Stream_Unknown,
    _Stream_MPEG4 = 0x10,
    _Stream_H264 = 0x1B,
    _Stream_H265 = 0x24,
    _Stream_SVAC_Video = 0x80,
    _Stream_G711 = 0x90,
    _Stream_G7221 = 0x92,
    _Stream_G7231 = 0x93,
    _Stream_G729 = 0x99,
    _Stream_SVAC_Audio = 0x9B,
} EmStreamType;

typedef unsigned int    UINT32;
typedef unsigned char       UINT8;


class TriPsReader {

public:
    TriPsReader(const char* psFilePath, const char* psCertFilePath, FUNC_SUT_SIGNVERIFYNOTIFY signCb);
    ~TriPsReader();
    bool init();
    void doRead();
    static  int signSucNum;


private:
    void* signCb;
    std::string inputFile;
    std::string certFile;
    std::string deviceId;
    FILE* fin;
    int64_t curPts = 0;
    bool isSuccess = false;
    unsigned int uiChan = -1;

    volatile bool m_bStop = false;
    unsigned char m_psAudioType;
    unsigned char m_psStreamType;
    unsigned char* m_psbuf = new unsigned char[2 * 1024 * 1024];
    unsigned char* m_pPSbuf = new unsigned char[PSBUFLEN];
    int frameIndex = 0;

    void decodePSPacket(unsigned char* pBuf, unsigned int size);
    int researchPSTag(unsigned char* buf, unsigned int len);
    bool getCertFromFile(IPC_CERT_INFO* ipcCertInfo);
};


#endif //FILEDEMO_TRIPSREADER_H

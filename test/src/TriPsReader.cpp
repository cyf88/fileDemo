//
// Created by cyf on 2024/2/29.
//

#include "TriPsReader.h"
#include "core_api.h"
#include <string.h>
#include <fstream>


static bool readFile(const std::string& filename, char*& buffer, size_t& length) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open file: " << filename << std::endl;
        return false;
    }

    // Determine the file size
    length = file.tellg();
    file.seekg(0, std::ios::beg);

    // Allocate memory for the buffer
    buffer = new char[length];

    // Read the file data into the buffer
    file.read(buffer, length);
    file.close();
    return true;
}

TriPsReader::TriPsReader(const char* psFilePath, const char* psCertFilePath, FUNC_SUT_SIGNVERIFYNOTIFY signCb) {
    this->inputFile = psFilePath;
    this->certFile = psCertFilePath;
    this->signCb = (void*)signCb;
}
TriPsReader::~TriPsReader() {

}
bool TriPsReader::init() {
    fin = fopen(inputFile.c_str(), "rb");
    if (fin == 0) {
        //LOG(DEBUG) << "Cann't open input file %s!";
        return false;
    }
    FRI_MUT_RequestChan(&uiChan);
    if (uiChan <= 0) {
        return false;
    }
//    auto ipcCertInfo = new IPC_CERT_INFO();
//    getCertFromFile(ipcCertInfo);
//    FRI_MUT_CertImport(uiChan, ipcCertInfo);
//    delete ipcCertInfo;

    FRI_MUT_CertImport2(uiChan, certFile.c_str());

    FRI_MUT_SetCallbackFunction(CODE_CBFUN_SIGNVERIFYNOTIFY,  signCb);

    return true;
}


void TriPsReader::doRead() {
    std::cout << "====start export===== " << std::endl;


    int buflen = 0;
    unsigned char* buf = m_pPSbuf;
    //m_pPSbuf = new unsigned char[PSBUFLEN];

    while (!m_bStop) {
        int readlen = fread(m_pPSbuf + buflen, 1, PSBUFLEN - buflen, fin);
        if (readlen <= 0) {
            decodePSPacket(m_pPSbuf, buflen);
            break;
        }
        readlen += buflen;
        buflen = 0;

        buf = m_pPSbuf;

        while (!m_bStop)
        {
            int iRvCurren = researchPSTag(buf + buflen, readlen - buflen);			//查找第一个PS头的位置
            if (iRvCurren >= 0)
            {
                buflen += iRvCurren;
            }
            else
            {
                buflen = 0;
                break;
            }
            //unsigned long long dFrameTimeTest = timeGetTime();
            int iRvNext = researchPSTag(buf + buflen + 4, readlen - buflen - 4);		//查找第二个PS头的位置
            if (iRvNext == 0)
            {
                iRvNext += 4;
                buflen += iRvNext;
                continue;
            }
            else if (iRvNext > 0)
            {
                iRvNext += 4;
                decodePSPacket(buf + buflen, iRvNext);							//解析出裸码流并解码
                buflen += iRvNext;
                continue;
            }
            else if (iRvNext < 0)
            {
                //						buflen = 0;
                buf += buflen;
                buflen = readlen - buflen;
                memcpy(m_pPSbuf, buf, buflen);
                break;
            }
        }
    }
}



void TriPsReader::decodePSPacket(unsigned char* pBuf, unsigned int size) {
    unsigned char* pCurBuf = pBuf;
    int m_PsBufLen = 0;
    int frametype = P_frame;
    while (!m_bStop)
    {
        if (pCurBuf >= (pBuf + size))
        {
            break;
        }

        unsigned int* pcode = (unsigned int*)pCurBuf;
        if (*pcode == 0xBA010000)												//查找P帧类型
        {
            frametype = P_frame;
            pCurBuf += 13;
            unsigned int pack_stuffing_length = *pCurBuf & 7;
            pCurBuf++;
            pCurBuf += pack_stuffing_length;
            continue;
        }
        else if (*pcode == 0xBB010000)											//查找I帧类型
        {
            int Systemheader_length = *(pCurBuf + 4) * 256 + *(pCurBuf + 5);
            pCurBuf += Systemheader_length + 4 + 2;
            frametype = I_frame;
            continue;
        }
        else if (*pcode == 0xBC010000)											//查找I帧类型
        {
            int psmlength = *(pCurBuf + 4) * 256 + *(pCurBuf + 5);
            frametype = I_frame;

            UINT32 u32PSILength = 0;
            u32PSILength = u32PSILength | pCurBuf[8];
            u32PSILength = (u32PSILength << 8) | pCurBuf[9];

            UINT32 u32ESMLength = 0;
            u32ESMLength = u32ESMLength | pCurBuf[10 + u32PSILength];
            u32ESMLength = (u32ESMLength << 8) | pCurBuf[11 + u32PSILength];

            UINT8* pESM = pCurBuf + 12 + u32PSILength;
            UINT32 u32Tmp = 0;
            while (u32Tmp < u32ESMLength)
            {
                UINT32 u32StreamID = pESM[1 + u32Tmp];
                u32StreamID &= 0x000000FF;
                u32StreamID |= 0x00000100;
                if (u32StreamID == PS_PES_AUDIO)										//查找音频类型
                {
                    m_psAudioType = pESM[0 + u32Tmp];
                }
                else if (u32StreamID == PS_PES_VIDEO)									//视频
                {
                    m_psStreamType = pESM[0 + u32Tmp];

                    m_psStreamType &= 0x000000FF;
                    switch (m_psStreamType)
                    {
                        case _Stream_MPEG4:
                        {
                            //(DEBUG) << "Stream_MPEG4";
                            break;
                        }
                        case _Stream_H265:
                        {
                           // LOG(DEBUG) << "Stream_H265";
                            break;
                        }
                        case _Stream_H264:
                        {
                           // LOG(DEBUG) << "Stream_H264";
                            break;
                        }
                        case _Stream_SVAC_Video:
                        {
                            //LOG(DEBUG) << "Stream_SVAC_Video";
                            break;
                        }
                        default:

                            break;
                    }
                }

                UINT32 u32ESILength = 0;
                u32ESILength = u32ESILength | pESM[2 + u32Tmp];
                u32ESILength = (u32ESILength << 8) | pESM[3 + u32Tmp];
                if (u32ESILength == 0)
                {
                    break;
                }
                u32Tmp += (2 + 2 + u32ESILength);

            }

            pCurBuf += psmlength + 4 + 2;
            continue;
        }
        else if (*pcode == 0xE0010000)													//PS视频数据
        {
            int pes_packet_length = *(pCurBuf + 4) * 256 + *(pCurBuf + 5);
            int pes_header_data_length = *(pCurBuf + 8);
            int payload_length = pes_packet_length - 3 - pes_header_data_length;
            pCurBuf += 9 + pes_header_data_length;

            if (payload_length < PSBUFLEN - m_PsBufLen)									//视频数据拼包
            {
                memcpy(m_psbuf + m_PsBufLen, pCurBuf, payload_length);
                m_PsBufLen += payload_length;
            }

            pCurBuf += payload_length;
            continue;
        }
        else if (*pcode == 0xC0010000)													//PS音频数据解析
        {
            int pes_packet_length = *(pCurBuf + 4) * 256 + *(pCurBuf + 5);
            int pes_header_data_length = *(pCurBuf + 8);
            int payload_length = pes_packet_length - 3 - pes_header_data_length;
            pCurBuf += 9 + pes_header_data_length;

            if (m_psAudioType == 155)													//音频解码,只支持(SVAC audio)类型音频，其他类型音频自行处理
            {
                //decode(pCurBuf, payload_length, Audio_frame);
            }
            pCurBuf += payload_length;

            continue;
        }
        else
        {
            break;
        }
    }
    if (m_PsBufLen != 0 && frametype == I_frame)
    {
        //解密
        int totalSize = sizeof(IMG_FRAME_UNIT) + NAL_BUFFER_SIZE;
        IMG_FRAME_UNIT* in = (IMG_FRAME_UNIT*)(malloc(totalSize));
        memcpy(in->img_buf, m_psbuf, m_PsBufLen);
        in->imgsz = m_PsBufLen;
        IMG_FRAME_UNIT* decryptFrame = NULL;

        int ret = FRI_MUT_VideoDataSecDecodeExt(uiChan, in, &decryptFrame);

        frameIndex++;
        if (frameIndex % 100 == 0) {
            std::cout << "export running frame " << frameIndex << std::endl;
        }

        FRI_MUT_SafeFree(&decryptFrame);
        FRI_MUT_SafeFree(&in);


    }

    m_PsBufLen = 0;

    return;
}

int TriPsReader::researchPSTag(unsigned char* buf, unsigned int len) {
    unsigned int code = 0xFFFFFFFF;
    unsigned char* pos = buf;	// 拿到数据区首指针
    int rest = len;
    int ret = -1;
    while (rest--)
    {
        code = (code << 8) | *pos++;
        if (code == 0x01BA)
        {
            ret = len - rest - 4;
            break;
        }
    }

    return ret;

}


bool TriPsReader::getCertFromFile(IPC_CERT_INFO* ipcCertInfo) {

    char* certbuf;
    size_t certLen;
    readFile(certFile, certbuf, certLen);
    memcpy(ipcCertInfo->CertInfo, certbuf, certLen);
    ipcCertInfo->CertInfo[certLen] = '\0';
    delete certbuf;

}
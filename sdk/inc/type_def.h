//
// Created by cyf on 2024/2/28.
//

#ifndef FILEDEMO_TYPE_DEF_H
#define FILEDEMO_TYPE_DEF_H


#include <bitset>
#include <map>
#include <mutex>
#include "openssl/skf.h"

#define MAX_BITS_LENGTH 8192
#define NAL_BUFFER_SIZE 1024 * 1024
//#define P_frame 1
//#define I_frame 2


struct bits_buffer_s {
    unsigned char* p_data;
    unsigned char  i_mask;
    int i_size;
    int i_data;
};

/***
*@remark:  讲传入的数据按地位一个一个的压入数据
*@param :  buffer   [in]  压入数据的buffer
*          count    [in]  需要压入数据占的位数
*          bits     [in]  压入的数值
*/
#define bits_write(buffer, count, bits)\
{\
	bits_buffer_s *p_buffer = (buffer); \
	int i_count = (count); \
	uint64_t i_bits = (bits); \
	p_buffer->i_size += count;\
while (i_count > 0)\
{\
	i_count--; \
if ((i_bits >> i_count) & 0x01)\
{\
	p_buffer->p_data[p_buffer->i_data] |= p_buffer->i_mask; \
}\
	else\
{\
	p_buffer->p_data[p_buffer->i_data] &= ~p_buffer->i_mask; \
}\
	p_buffer->i_mask >>= 1;         /*操作完一个字节第一位后，操作第二位*/\
if (p_buffer->i_mask == 0)     /*循环完一个字节的8位后，重新开始下一位*/\
{\
	p_buffer->i_data++; \
	p_buffer->i_mask = 0x80; \
}\
}\
}


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

enum
{
    I_frame = 1,
    B_frame = 2,
    P_frame = 3,
    Audio_frame = 4,
};


typedef enum
{
    SEC_CAPTY_A = 0x00,	//安全能力A级：支持双向身份认证
    SEC_CAPTY_B = 0x01,	//安全能力B级：支持双向身份认证、支持视频								//数据签名
    SEC_CAPTY_C1 = 0x02,	//安全能力C级：支持双向身份认证、支持视频								//数据签名和视频数据加密
    SEC_CAPTY_C2 = 0x03,
    SEC_CAPTY_MAX = 0x04
} SEC_CAPTYLEVEL_TYPE;



typedef enum class DecodeStatus {

    NORMAL = 0,
    HTTP_VKEK_NOT_EQUAL_STREAM_VKEK = 10001,
    ENCRYPTED_FLAG_NOT_SET_ONE = 10002,
    HTTP_GET_REAL_VKEK_ERROR = 10003,
    VKEK_VERSION_LENGTH_NULL = 10004,
    ENCRYPT_VKEK_DATALEN_IS_NULL = 10005,
    NOT_FOUND_VKEK_IN_SES = 10006,
    NON_IDR_FRAME = 10007,
    VKEK_LENGTH_NOT_16 = 10008,
    SIP_GET_REAL_VKEK_ERROR = 10009,
    GET_UKEY_PUBKEY_ERROR = 10010,
};

typedef enum class StreamType {
    REALTIME = 0,
    PLAYBACK = 1,
    PSFILE = 2,

};




typedef enum {
    NALU_TYPE_NONE_IDR_SLICE = 1,
    NALU_TYPE_IDR_SLICE = 2,
    NALU_TYPE_NONE_IDR_SVC_SLICE = 3,
    NALU_TYPE_IDR_SVC_SLICE = 4,
    NALU_TYPE_SURVEILLANCE_EXTENSION_UNIT = 5,
    NALU_TYPE_SEI = 6,
    NALU_TYPE_SPS = 7,
    NALU_TYPE_PPS = 8,
    NALU_TYPE_SES = 9,
    NALU_TYPE_AUTH = 10,
    NALU_TYPE_E0STREAM = 11,
    NALU_TYPE_RESERVED1 = 12,
    NALU_TYPE_CHAPTER6 = 13,
    NALU_TYPE_RESERVED2 = 14,
    NALU_TYPE_SVC_PPS = 15,
}NaluType;

typedef enum {
    EXTENSION_TIME = 0x04,
    EXTENSION_GIS = 0x10,
    EXTENSION_ANALYSIS = 0x11,
    EXTENSION_OSD = 0x12,
    EXTENSION_RESERVED

}ExtensionType;

typedef struct {
    int startcodeprefix_len;
    unsigned int len;
    unsigned long max_size;
    int forbidden_bit;
    int nal_reference_idc;
    int nal_uint_type;
    int encryption_idc;
    int authentication_idc;
    unsigned char* buf;
}NALU_t;

typedef struct sesparam {
    int encryption_flag;                 // u(1)
    int authentication_flag;             // u(1)
    int encryption_type;                 // u(4)
    int vek_flag;                        // u(1)
    int iv_flag;                        // u(1)
    int vek_encryption_type;            // u(4)
    int evek_length_minus1;              // u(8)
    unsigned char evek[32];
    unsigned char vek[32];
    int vek_length;              // u(8)

    int vkek_version_length_minus1;       // u(8)
    unsigned char vkek_version[32];        //f(n)

    int iv_length_minus1;                  // u(8)
    unsigned char iv[32];                 //f(n)

    int hash_type;                          //u(2)
    int hash_discard_p_pictures;            // u(1)
    int signature_type;                      //u(2)
    int successive_hash_pictures_minus1;       // u(8)
    unsigned char camera_idc[19];                          //f(152)
    unsigned char camera_id[20];                          //f(160)

}ses_parameters;

typedef struct authparam {
    int frame_num;
    int spatial_el_flag;//默认为0 ，目前无法取到
    int auth_data_lenth_minus_1;
    unsigned char authData[512];
}auth_parameters;

typedef struct timeparam {
    unsigned int extension_id;
    unsigned int extension_length;
    unsigned int hour_bits;
    unsigned int minute_bits;
    unsigned int second_bits;
    unsigned int second_fraction_bits;
    unsigned int ref_data_flag;
    unsigned int year_minus2000_bits;
    unsigned int month_bits;
    unsigned int day_bits;

}time_parameters;

typedef struct nal_ctx {
    ses_parameters sesparamPtr;
    auth_parameters authparamPtr;
    time_parameters timeparamPtr;
    std::bitset<MAX_BITS_LENGTH>* bits;
    unsigned char* buf;
    ULONG currentEncryptNalLen;
    ULONG currentDecryptNalLen;
    unsigned char* needHashData;
    ULONG needHashDataLen;
    unsigned char hash[512];
    bool hashEmpty;
} NalCtx;

typedef struct {
    bool encrypt;
    unsigned char data[128];
    ULONG dataLen;
    bool shouldRecover;
} vkekInfo;

typedef struct {
    ULONG decodeHandle;//加解密标识
    NalCtx nalCtx;//nal单元处理上下文
    ECCPUBLICKEYBLOB streamSignkey; //码流验签公钥
    std::map<std::string, vkekInfo>* vkekmaps;//key version value 加密的vkeks
    ULONG vekeks_len;//vkek数量
    std::string currentVkekVersion;//当前vkek版本
    unsigned char currentVkek[256];//当前加密的vkek值
    ULONG currentVkekLen;
    bool isDecode;//1 为解密 2.加密
    //加密相关参数，需要在加密时候写入头
    unsigned char encrypt_vkek[128];//密文vkek，为解密文vek使用
    ULONG encrypt_vkek_len;
    unsigned char evek[128];//密文vek,流里需要设置
    ULONG evek_len;
    unsigned char vek[128];//明文vek ，加密流需要使用
    ULONG vek_len;
    unsigned char iv[128];//iv向量
    ULONG iv_len;
    std::mutex * decodeMutex;
    std::string deviceId;
    DecodeStatus status;
    unsigned char stream_id[20]; //码流中的id
    FILE* stream; //es流保存
    unsigned int security_level; // 安全等级  0-未知  1-A   2-B   3-C
    std::string localVersion;  //流导出时添加的vetk信息
    StreamType streamType; //0:实时流  1：回放流，有时间传入， 2：本地ps文件
    bool isAuth;  //是否签名  加密接口中使用
    bool isEncrypt; //是否加密，加密接口中使用
    ExtensionType extionType;

} DecodeCtx, EncodeCtx;
#endif //FILEDEMO_TYPE_DEF_H

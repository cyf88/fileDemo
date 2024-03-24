#include "tri_nal.h"
#include "tri_util.h"
#include "tri_skf_api.h"
#include "type_def.h"
#include "openssl/sm3.h"
#include <openssl/sm2.h>
#include <queue>
#include <bitset>
#include <map>
#include <string>
#include <vector>
#include "easylogging++.h"
#include "globalvar.h"


ULONG auth_parameters_set(DecodeCtx* ctx, unsigned char* rbspBuffer, ULONG rbspBufferLen, auth_parameters* auth_ptr) {
    int ret = 0;
    if (auth_ptr == NULL) {
        return -1;
    }
    memset(auth_ptr, 0x00, sizeof(auth_ptr));
    ctx->nalCtx.bits->reset();
    ULONG bitsLen = 0;
    ULONG startIndex = 0;
    array_2_bitset(rbspBuffer, rbspBufferLen, ctx->nalCtx.bits, &bitsLen);
    unsigned char data = { 0 };
    bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//4bit
    auth_ptr->frame_num = data;
    startIndex = startIndex + 8;
    //目前不知道如何获取spatial_svac_flag，默认
    auth_ptr->spatial_el_flag = 0;
    memset(&data, 0x00, sizeof(char));
    bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//4bit
    auth_ptr->auth_data_lenth_minus_1 = data;
    startIndex = startIndex + 8;
    for (int index = 0; index <= auth_ptr->auth_data_lenth_minus_1; index++) {
        memset(&data, 0x00, sizeof(char));
        bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
        startIndex = startIndex + 8;
        auth_ptr->authData[index] = data;
    }
    return 0;
}

ULONG time_parameters_set(DecodeCtx* ctx, unsigned char* rbspBuffer, ULONG rbspBufferLen, time_parameters* time_ptr) {
    int ret = 0;
    if (time_ptr == NULL) {
        return 1;
    }
    memset(time_ptr, 0x00, sizeof(time_parameters));
    ctx->nalCtx.bits->reset();
    ULONG bitsLen = 0;
    ULONG startIndex = 0;
    array_2_bitset(rbspBuffer, rbspBufferLen, ctx->nalCtx.bits, &bitsLen);
    unsigned char data = { 0 };
    bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);
    time_ptr->extension_id = data;
    startIndex = startIndex + 8;
    bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);
    time_ptr->extension_length = data;
    startIndex = startIndex + 8;
    bitset_2_char(ctx->nalCtx.bits, startIndex, 5, &data);
    time_ptr->hour_bits = data;
    startIndex = startIndex + 5;
    bitset_2_char(ctx->nalCtx.bits, startIndex, 6, &data);
    time_ptr->minute_bits = data;
    startIndex = startIndex + 6;
    bitset_2_char(ctx->nalCtx.bits, startIndex, 6, &data);
    time_ptr->second_bits = data;
    startIndex = startIndex + 6;
    bitset_2_char(ctx->nalCtx.bits, startIndex, 14, &data);
    time_ptr->second_fraction_bits = data;
    startIndex = startIndex + 14;
    bitset_2_char(ctx->nalCtx.bits, startIndex, 1, &data);
    time_ptr->ref_data_flag = data;
    startIndex = startIndex + 1;
    if (time_ptr->ref_data_flag == 1) {
        bitset_2_char(ctx->nalCtx.bits, startIndex, 7, &data);
        time_ptr->year_minus2000_bits = data;
        startIndex = startIndex + 7;
        bitset_2_char(ctx->nalCtx.bits, startIndex, 4, &data);
        time_ptr->month_bits = data;
        startIndex = startIndex + 4;
        bitset_2_char(ctx->nalCtx.bits, startIndex, 5, &data);
        time_ptr->day_bits = data;
    }
    return 0;

}


ULONG ses_parameters_set(DecodeCtx* ctx, unsigned char* rbspBuffer, ULONG rbspBufferLen, ses_parameters* ses_ptr) {
    //LOG(DEBUG) << "ses_parameters_set call start";

    int ret = 0;
    if (ses_ptr == NULL) {
        return -1;
    }
    memset(ses_ptr, 0x00, sizeof(ses_parameters));
    ctx->nalCtx.bits->reset();
    ULONG bitsLen = 0;
    ULONG startIndex = 0;
    array_2_bitset(rbspBuffer, rbspBufferLen, ctx->nalCtx.bits, &bitsLen);
    unsigned char data = { 0 };
    bitset_2_char(ctx->nalCtx.bits, startIndex++, 1, &data);//1bit
    ses_ptr->encryption_flag = data;
    memset(&data, 0x00, sizeof(char));
    bitset_2_char(ctx->nalCtx.bits, startIndex++, 1, &data);//1bit
    ses_ptr->authentication_flag = data;
    if (ses_ptr->encryption_flag) {
        memset(&data, 0x00, sizeof(char));
        bitset_2_char(ctx->nalCtx.bits, startIndex, 4, &data);//4bit
        startIndex = startIndex + 4;
        ses_ptr->encryption_type = data;
        memset(&data, 0x00, sizeof(char));
        bitset_2_char(ctx->nalCtx.bits, startIndex++, 1, &data);//1bit
        ses_ptr->vek_flag = data;
        memset(&data, 0x00, sizeof(char));
        bitset_2_char(ctx->nalCtx.bits, startIndex++, 1, &data);//1bit
        ses_ptr->iv_flag = data;
        if (ses_ptr->vek_flag) {
            memset(&data, 0x00, sizeof(char));
            bitset_2_char(ctx->nalCtx.bits, startIndex, 4, &data);//4bit
            startIndex = startIndex + 4;
            ses_ptr->vek_encryption_type = data;
            memset(&data, 0x00, sizeof(char));
            bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
            startIndex = startIndex + 8;
            ses_ptr->evek_length_minus1 = data;
            memset(ses_ptr->evek, 0x00, sizeof(char) * 32);
            for (int index = 0; index <= ses_ptr->evek_length_minus1; index++) {
                memset(&data, 0x00, sizeof(char));
                bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
                startIndex = startIndex + 8;
                ses_ptr->evek[index] = data;
            }
            memset(&data, 0x00, sizeof(char));
            bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
            startIndex = startIndex + 8;
            ses_ptr->vkek_version_length_minus1 = data;
            memset(ses_ptr->vkek_version, 0x00, sizeof(char) * 32);
            for (int index = 0; index <= ses_ptr->vkek_version_length_minus1; index++) {
                memset(&data, 0x00, sizeof(char));
                bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
                startIndex = startIndex + 8;
                ses_ptr->vkek_version[index] = data;
            }
        }
        if (ses_ptr->iv_flag) {
            memset(&data, 0x00, sizeof(char));
            bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
            startIndex = startIndex + 8;
            ses_ptr->iv_length_minus1 = data;
            memset(ses_ptr->iv, 0x00, sizeof(char) * 32);
            for (int index = 0; index <= ses_ptr->iv_length_minus1; index++) {
                memset(&data, 0x00, sizeof(char));
                bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
                startIndex = startIndex + 8;
                ses_ptr->iv[index] = data;
            }

        }

    }
    if (ses_ptr->authentication_flag) {
        memset(&data, 0x00, sizeof(char));
        bitset_2_char(ctx->nalCtx.bits, startIndex, 2, &data);//2bit
        startIndex += 2;
        ses_ptr->hash_type = data;

        memset(&data, 0x00, sizeof(char));
        bitset_2_char(ctx->nalCtx.bits, startIndex++, 1, &data);//1bit
        ses_ptr->hash_discard_p_pictures = data;

        memset(&data, 0x00, sizeof(char));
        bitset_2_char(ctx->nalCtx.bits, startIndex, 2, &data);//2bit
        startIndex += 2;
        ses_ptr->signature_type = data;

        memset(&data, 0x00, sizeof(char));
        bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//2bit
        startIndex += 8;
        ses_ptr->successive_hash_pictures_minus1 = data;
        if (ses_ptr->successive_hash_pictures_minus1 < 0) {
            //return 1;
        }

        memset(ses_ptr->camera_idc, 0x00, sizeof(char) * 19);
        for (unsigned int index = 0; index < 19; index++) {
            memset(&data, 0x00, sizeof(char));
            bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
            startIndex += 8;
            ses_ptr->camera_idc[index] = data;
        }
    }
    if (ses_ptr->vek_flag || ses_ptr->authentication_flag) {
        memset(ses_ptr->camera_id, 0x00, sizeof(char) * 20);
        for (unsigned int index = 0; index < 20; index++) {
            memset(&data, 0x00, sizeof(char));
            bitset_2_char(ctx->nalCtx.bits, startIndex, 8, &data);//8bit
            startIndex += 8;
            ses_ptr->camera_id[index] = data;
        }
        memcpy(ctx->stream_id, ses_ptr->camera_id, sizeof(char) * 20);
    }


    if (ctx->nalCtx.sesparamPtr.encryption_flag == 1) {// idr frame
		unsigned char vek[32] = { 0 };
		ULONG vek_len = 0;

		if (ses_ptr->evek_length_minus1 > 0 && ses_ptr->vkek_version_length_minus1 > 0) {
			//got evek
			vkekInfo vkekinfo;
			memset(&vkekinfo, 0x00, sizeof(vkekInfo));
			std::string vkek_version = (char*)ses_ptr->vkek_version;
			std::map<std::string, vkekInfo>* vkekmap = ctx->vkekmaps;
			std::map<std::string, vkekInfo>::iterator iter;
			iter = vkekmap->find(vkek_version);
			if (iter != vkekmap->end()) {
				vkekinfo = iter->second;
			}
			else {
				//码流vkek version 和 导入的vkek version 不一致
				LOG(ERROR) << "UKEY_VKEK_NOT_EQUAL_STREAM_VKEK ";
				vkekinfo.dataLen = 16;
			}
			unsigned char* vkek = (unsigned char*)malloc(sizeof(unsigned char) * (vkekinfo.dataLen + 1));
			memset(vkek, 0x00, sizeof(unsigned char)* (vkekinfo.dataLen + 1));
			memcpy(vkek, vkekinfo.data, vkekinfo.dataLen);
			int outSize = 0;
			memset(ctx->nalCtx.sesparamPtr.vek, 0x00, sizeof(unsigned char) * 32);

#ifdef	SKF_CRYPTO
			TRI_SM4_ECB(vkek, ctx->nalCtx.sesparamPtr.evek, ctx->nalCtx.sesparamPtr.evek_length_minus1 + 1,
				ctx->nalCtx.sesparamPtr.vek, outSize, false);
#else
			SSL_SM4_ECB(vkek, ctx->nalCtx.sesparamPtr.evek, ctx->nalCtx.sesparamPtr.evek_length_minus1 + 1,
				ctx->nalCtx.sesparamPtr.vek, outSize, false);
#endif
			ctx->nalCtx.sesparamPtr.vek_length = strlen((const char*)ctx->nalCtx.sesparamPtr.vek);
			free(vkek);
		}
		else {
			//memset(ctx->nalCtx.sesparamPtr.vek, 0x00, 32);
			//ctx->nalCtx.sesparamPtr.vek_length = 0;
			ctx->status = DecodeStatus::NOT_FOUND_VKEK_IN_SES;
			LOG(DEBUG) << "not found evek in ses nalu, ----deviceId:" << ctx->deviceId;
		}
	}

    //码流等级
    if (ses_ptr->encryption_flag == 0 && ses_ptr->authentication_flag == 0) {
    ctx->security_level = 1;
    }
    if (ses_ptr->encryption_flag == 0 && ses_ptr->authentication_flag == 1) {
    ctx->security_level = 2;
    }
    if (ses_ptr->encryption_flag == 1 && ses_ptr->authentication_flag == 1) {
    ctx->security_level = 3;
    }
    //using namespace std;
    //LOG(DEBUG) << "ses parameters";
    //LOG(DEBUG) << "encryption_flag:" << ses_ptr->encryption_flag;
    //LOG(DEBUG) << "authentication_flag:" << ses_ptr->authentication_flag;
    //LOG(DEBUG) << "encryption_type:" << ses_ptr->encryption_type;
    //LOG(DEBUG) << "vek_flag:" << ses_ptr->vek_flag;
    //LOG(DEBUG) << "iv_flag:" << ses_ptr->iv_flag;
    //LOG(DEBUG) << "vek_encryption_type:" << ses_ptr->vek_encryption_type;
    //LOG(DEBUG) << "evek_length_minus1:" << ses_ptr->evek_length_minus1;
    //LOG(DEBUG) << "evek:" << ses_ptr->evek;
    //LOG(DEBUG) << "vek_length:" << ses_ptr->vek_length;
    //LOG(DEBUG) << "vek:" << ses_ptr->vek;
    //LOG(DEBUG) << "vkek_version_length_minus1:" << ses_ptr->vkek_version_length_minus1;
    //LOG(DEBUG) << "vkek_version:" << ses_ptr->vkek_version;
    //LOG(DEBUG) << "iv_length_minus1:" << ses_ptr->iv_length_minus1;
    //LOG(DEBUG) << "iv:" << ses_ptr->iv;
    //LOG(DEBUG) << "hash_type:" << ses_ptr->hash_type;
    //LOG(DEBUG) << "hash_discard_p_pictures:" << ses_ptr->hash_discard_p_pictures;
    //LOG(DEBUG) << "signature_type:" << ses_ptr->signature_type;
    //LOG(DEBUG) << "successive_hash_pictures_minus1:" << ses_ptr->successive_hash_pictures_minus1;
    //LOG(DEBUG) << "camera_idc:" << ses_ptr->camera_idc;
    //LOG(DEBUG) << "camera_id:" << ses_ptr->camera_id;
    return ret;
}



ULONG decryptNalUnit(DecodeCtx* ctx,  unsigned char* encryptNalUnit,  ULONG encryptNalUnitLen,  unsigned char* decryptNalUnit,  ULONG* decryptNalUnitLen) {
        clock_t start, finish;
        double Total_time;
        ULONG ret = 0;
        NALU_t nalu;
        memset(&nalu, 0x00, sizeof(NALU_t));
        nalu.forbidden_bit = (encryptNalUnit[0] & 0x80) >> 7;//1bit
        nalu.nal_reference_idc = (encryptNalUnit[0] & 0x40) >> 6;//1bit
        nalu.nal_uint_type = (encryptNalUnit[0] & 0x3c) >> 2;//4bit
        nalu.encryption_idc = (encryptNalUnit[0] & 0x02) >> 1;//1bit
        nalu.authentication_idc = encryptNalUnit[0] & 0x01;//1bit

        unsigned long u24 = 0;//3 * 8 位数据
        unsigned int readIndex = 1;//从payload开始，码流脱壳操作是 0x00 0x00 0x03 0x00 去除0x03
        unsigned int writeIndex = 1;

        memcpy(ctx->nalCtx.buf, &encryptNalUnit[0], sizeof(unsigned char));
        while (readIndex < encryptNalUnitLen) {
            if (readIndex + 3 < encryptNalUnitLen) {
                u24 = encryptNalUnit[readIndex] << 24 | encryptNalUnit[readIndex + 1] << 16 | encryptNalUnit[readIndex + 2] << 8 | encryptNalUnit[readIndex + 3];//之后的32位
                if (u24 == 0x0300) {
                    ctx->nalCtx.buf[writeIndex++] = 0x00;
                    ctx->nalCtx.buf[writeIndex++] = 0x00;
                    readIndex += 3;
                    continue;
                }
                else if (u24 == 0x0301) {
                    ctx->nalCtx.buf[writeIndex++] = 0x00;
                    ctx->nalCtx.buf[writeIndex++] = 0x00;
                    readIndex += 3;
                    continue;
                }
                else if (u24 == 0x0302) {
                    ctx->nalCtx.buf[writeIndex++] = 0x00;
                    ctx->nalCtx.buf[writeIndex++] = 0x00;
                    readIndex += 3;
                    continue;
                }
                else if (u24 == 0x0303) {
                    ctx->nalCtx.buf[writeIndex++] = 0x00;
                    ctx->nalCtx.buf[writeIndex++] = 0x00;
                    readIndex += 3;
                    continue;
                }
            }
            ctx->nalCtx.buf[writeIndex++] = encryptNalUnit[readIndex];
            readIndex++;
        }


        if (nalu.authentication_idc == 1) {
            memcpy(ctx->nalCtx.needHashData + ctx->nalCtx.needHashDataLen, encryptNalUnit, encryptNalUnitLen);
            ctx->nalCtx.needHashDataLen += (encryptNalUnitLen);
        }
        //不进行任何操作，并直接返回
        if (nalu.nal_uint_type == NALU_TYPE_SES) {
            memset(&(ctx->nalCtx.sesparamPtr), 0x00, sizeof(ses_parameters));
            ses_parameters_set(ctx, ctx->nalCtx.buf + 1, writeIndex - 1, &(ctx->nalCtx.sesparamPtr));
            //memcpy(decryptNalUnit, ctx->nalCtx.buf, writeIndex);
            *decryptNalUnitLen = 0;
        }
        else if (nalu.nal_uint_type == NALU_TYPE_RESERVED1 || nalu.nal_uint_type == NALU_TYPE_RESERVED2) {
            memcpy(decryptNalUnit, encryptNalUnit, encryptNalUnitLen);
            *decryptNalUnitLen = encryptNalUnitLen;
        }
        else if (nalu.nal_uint_type == NALU_TYPE_AUTH) {

            int ret = auth_parameters_set(ctx, ctx->nalCtx.buf + 1, writeIndex - 1, &(ctx->nalCtx.authparamPtr));
            //memcpy(decryptNalUnit, ctx->nalCtx.buf, writeIndex);
            *decryptNalUnitLen = 0;

        }
        else if (nalu.nal_uint_type == NALU_TYPE_SURVEILLANCE_EXTENSION_UNIT) {
            switch (*(ctx->nalCtx.buf + 1)) {
                case EXTENSION_TIME:
                    time_parameters_set(ctx, ctx->nalCtx.buf + 1, writeIndex - 1, &(ctx->nalCtx.timeparamPtr));
                    break;
                case EXTENSION_GIS:
                    break;
                case EXTENSION_ANALYSIS:
                    break;
                case EXTENSION_OSD:
                    break;
                default:
                    break;
            }
        }
        else {
            if (nalu.encryption_idc == 1) {
                //LOG(DEBUG) << "find encryption_idc:  nalu type: " << nalu.nal_uint_type
                //	 << " vek_length: " << ctx->nalCtx.sesparamPtr.vek_length
                //	 << " encryption_type: " << ctx->nalCtx.sesparamPtr.encryption_type
                //	 << " deviceId: " << ctx->deviceId;

                if (ctx->nalCtx.sesparamPtr.vek_length != 0) {
                    if (ctx->nalCtx.sesparamPtr.encryption_type == 0) {
                        //sm1_ofb

                    }
                    else {
                        if (ctx->nalCtx.sesparamPtr.vek_length != 0) {

                            //encryptNalUnitLen = writeIndex
                            //不解密最后一个字节
                            int ivLenth = 0;
                            if (ctx->nalCtx.sesparamPtr.iv_length_minus1 > 0) {
                                ivLenth = ctx->nalCtx.sesparamPtr.iv_length_minus1 + 1;
                            }
                            if (ivLenth > 256) {
                                //0016无法解析iv超过32位
                                LOG(DEBUG) << "iv len > 256 TRI_DECRYPT_STREAM fail";
                                memcpy(decryptNalUnit, encryptNalUnit, encryptNalUnitLen);
                                *decryptNalUnitLen = encryptNalUnitLen;
                                return 0;
                            }

//验签服务注释解密
//#ifdef	SKF_CRYPTO
//                            int rs = TRI_SM4_OFB(ctx->nalCtx.sesparamPtr.vek, ctx->nalCtx.sesparamPtr.vek_length
//                        , ctx->nalCtx.sesparamPtr.iv, ivLenth
//                        , ctx->nalCtx.buf + 1, writeIndex - 2,
//                        decryptNalUnit + 1, (int&)(*decryptNalUnitLen), false);
//#else
//                            int rs = SSL_SM4_OFB(ctx->nalCtx.sesparamPtr.vek, ctx->nalCtx.sesparamPtr.vek_length
//                                    , ctx->nalCtx.sesparamPtr.iv, ivLenth
//                                    , ctx->nalCtx.buf + 1, writeIndex - 2,
//                                                 decryptNalUnit + 1, (int&)(*decryptNalUnitLen), true);
//#endif
                            int rs = 0;
                            *decryptNalUnitLen = encryptNalUnitLen;


                            if (rs != 0) {
                                LOG(DEBUG) << "decrypt video data using vek failed!";
                                memcpy(decryptNalUnit, encryptNalUnit, encryptNalUnitLen);
                                *decryptNalUnitLen = encryptNalUnitLen;
                            }
                            else {
                                //把第一个字节复制到解密流里，并设置加密设为0
                                memcpy(decryptNalUnit, ctx->nalCtx.buf, sizeof(unsigned char));
                                decryptNalUnit[0] = decryptNalUnit[0] & 0xfd;
                                *decryptNalUnitLen = *decryptNalUnitLen + 2;
                                memcpy(&decryptNalUnit[*decryptNalUnitLen - 1], ctx->nalCtx.buf + writeIndex - 1, sizeof(unsigned char));
                                //先将解密数据复制到nal结构体的buf里
                                memcpy(ctx->nalCtx.buf, decryptNalUnit, *decryptNalUnitLen);
                                //对0x00 0x00 0x00 变更 0x00 0x00 0x03 0x00
                                *decryptNalUnitLen = prevention(ctx->nalCtx.buf, *decryptNalUnitLen, decryptNalUnit);
                                u24 = 0;//3 * 8 位数据
                                readIndex = 1;//从payload开始，头信息不参加0x00 0x00 0x00 变更 0x00 0x00 0x03 0x00逻辑
                                writeIndex = 1;

                            }

                        }
                        else {
                            memcpy(decryptNalUnit, encryptNalUnit, encryptNalUnitLen);
                            *decryptNalUnitLen = encryptNalUnitLen;
                        }
                    }
                }

            }
            else {
                //不加密
                memcpy(decryptNalUnit, encryptNalUnit, encryptNalUnitLen);
                *decryptNalUnitLen = encryptNalUnitLen;
            }
        }


        //异常状态处理

        return 0;

}



ULONG buildNalSes(EncodeCtx* ctx, unsigned char* pSes, int& len) {

    bits_buffer_s bitsBuffer;
    bitsBuffer.i_data = 0;
    bitsBuffer.i_size = 0;
    bitsBuffer.i_mask = 0x80;
    bitsBuffer.p_data = (unsigned char*)(pSes);

    bits_write(&bitsBuffer, 8, 0xE4); /*start code*/
    //C7  1100 0111
    bits_write(&bitsBuffer, 1, ctx->isEncrypt ? 1 : 0);  //encryption_flag
    //bool authentication_flag = ctx->isAuth&&isKeyFrame;
    //欣博码流不签名的P帧 authentication_flag=1,
    bits_write(&bitsBuffer, 1, ctx->isAuth ? 1 : 0);  //authentication_flag;
    if (ctx->isEncrypt) {
        bits_write(&bitsBuffer, 4, 1);  //encryption_type 0:SM1  1:SM4
        bits_write(&bitsBuffer, 1, 1);  //vek_flag
        bits_write(&bitsBuffer, 1, 1);  //iv_flag
        bits_write(&bitsBuffer, 4, 1);  //vek_encryption_type
        unsigned char evek_len_minus1 = ctx->evek_len - 1;
        unsigned char* evek = ctx->evek;
        bits_write(&bitsBuffer, 8, evek_len_minus1); // evek_length_minus1
        //evek
        for (int i = 0; i <= evek_len_minus1; i++) {
            bits_write(&bitsBuffer, 8, evek[i]);
        }

        //vkek_version_length_minus1
        unsigned char  vkek_version_length_minus1 = (ctx->localVersion).length() - 1;
        bits_write(&bitsBuffer, 8, vkek_version_length_minus1);
        //vkek_version
        for (int i = 0; i <= vkek_version_length_minus1; i++) {
            bits_write(&bitsBuffer, 8, ctx->localVersion[i]);
        }

        // iv_length_minus1
        unsigned char iv_lenth_minus1 = ctx->iv_len - 1;
        bits_write(&bitsBuffer, 8, iv_lenth_minus1);
        //iv
        for (int i = 0; i <= iv_lenth_minus1; i++) {
            bits_write(&bitsBuffer, 8, ctx->iv[i]);
        }
    }
    if (ctx->isAuth) {
        bits_write(&bitsBuffer, 2, 0); // hash_type  0:SM3
        bits_write(&bitsBuffer, 1, 1); // hash_discard  1:只对I帧
        bits_write(&bitsBuffer, 2, 0); //signature_type 0:SM2
        bits_write(&bitsBuffer, 8, 1); // 1:只对I帧
        //camera_idc
        for (int i = 0; i < 19; i++) {
            bits_write(&bitsBuffer, 8, ctx->stream_id[i]);
        }
    }
    //camera_id
    if (ctx->isEncrypt || ctx->isAuth) {
        for (int i = 0; i < 20; i++) {
            bits_write(&bitsBuffer, 8, ctx->stream_id[i]);
        }
    }

    //补全位数，字节对齐
    unsigned int left = bitsBuffer.i_size % 8;
    left = 8 - left;
    for (int i = 0; i < left; i++) {
        bits_write(&bitsBuffer, 1, 0);
    }
    len = (bitsBuffer.i_size + left) / 8;
    return 0;
}
ULONG buildNalAuth(EncodeCtx* ctx, unsigned char* data, ULONG dataLen, unsigned char* auth, ULONG& authlen) {
    unsigned char startCode[6] = { 0x00, 0x00, 0x00, 0x01, 0xA8, 0x00 };
    //0xA8 签名数据帧  0x00  frame_num   + min
    unsigned char digist[32] = { 0 };
    ULONG digist_len;
    TRI_SM3(data, dataLen, digist);
    //sm3((unsigned char*)data, dataLen, digist);
    unsigned char sign[1024] = { 0 };
    ULONG signSize = 0;
    ULONG ret = TRI_SIGNATURE_RS(trimps::clientSignKey, digist, sizeof(digist), sign, signSize, (unsigned char*)"1234567812345678");
    if (ret != 0) {
        std::cout << "SKF_SIGNATURE error ret=" << ret;
        return ret;
    }
    char* signBase64 = NULL;
    int signBase64len;
    base64Encode((const char*)sign, signSize, 0, &signBase64, &signBase64len);
    authlen = 0;
    memcpy(auth, startCode, 6);
    authlen += 6;
    char ascii_char = (char)((signBase64len - 1) & 0x7F);
    memcpy(auth + authlen, &ascii_char, 1);   //authentication_data_length_minus1
    authlen++;
    memcpy(auth + authlen, signBase64, signBase64len);
    authlen += signBase64len;
    free(signBase64);
    return 0;

}

ULONG encryptNalUnit2(EncodeCtx* ctx, unsigned char* decryptNalUnit, ULONG decryptNalUnitLen, unsigned char* encryptNalUnit, ULONG& encryptNalUnitLen) {
    ULONG ret = 0;
    encryptNalUnitLen = 0;
    NALU_t nalu;
    memset(&nalu, 0x00, sizeof(NALU_t));
    //nalu.buf = (unsigned char*)malloc(sizeof(unsigned char) * decryptNalUnitLen * 2);
    nalu.forbidden_bit = (decryptNalUnit[0] & 0x80) >> 7;//1bit
    nalu.nal_reference_idc = (decryptNalUnit[0] & 0x40) >> 6;//1bit
    nalu.nal_uint_type = (decryptNalUnit[0] & 0x3c) >> 2;//4bit
    ///nalu.encryption_idc = (decryptNalUnit[0] & 0x02) >> 1;//1bit
    //nalu.authentication_idc = decryptNalUnit[0] & 0x01;//1bitf
    //清零后两位(encryption_idc  authentication_idc)
    decryptNalUnit[0] = decryptNalUnit[0] & 0xfc;

    //加密I帧和P帧,并在之前添加加密信息SES
    if (nalu.nal_uint_type == NALU_TYPE_NONE_IDR_SLICE
        || nalu.nal_uint_type == NALU_TYPE_IDR_SLICE) {
        //std::cout << "encryptNalUnit find type: " << nalu.nal_uint_type << std::endl;
        //std::cout << "decryptNalUnitLen: " <<decryptNalUnitLen << std::endl;
        if (ctx->security_level == SEC_CAPTY_A) {
            memcpy(encryptNalUnit, decryptNalUnit, decryptNalUnitLen);
            encryptNalUnitLen = decryptNalUnitLen;
            return 0;
        }

        unsigned char* tmpBuf = (unsigned char*)malloc(sizeof(unsigned char) * NAL_BUFFER_SIZE);
        ULONG tmpBufLen = decryptNalUnitLen;
        memcpy(tmpBuf, decryptNalUnit, decryptNalUnitLen);
        decryptNalUnitLen = exuviation(tmpBuf, decryptNalUnitLen, decryptNalUnit);

        //添加安全参数头
        unsigned char ses[200] = { 0 };
        int len;
        buildNalSes(ctx, ses, len);
        memcpy(encryptNalUnit, ses, len);
        encryptNalUnitLen += len;
        //添加码流头
        unsigned char startCode[4] = { 0x00, 0x00, 0x00, 0x01 };
        memcpy(&encryptNalUnit[encryptNalUnitLen], startCode, 4);
        encryptNalUnitLen += 4;
        if (ctx->isEncrypt) {
            //加密操作，不加密最后一个字节

            int64_t i_time, i_start, i_elapsed;

            unsigned char* tmpEncBuf = (unsigned char*)malloc(NAL_BUFFER_SIZE);
            int encSize = 0;

#ifdef	SKF_CRYPTO
            int ret = TRI_SM4_OFB(ctx->vek, 16, ctx->iv, 16, decryptNalUnit + 1, decryptNalUnitLen - 2,
        tmpEncBuf, encSize, true);
#else
            int ret = SSL_SM4_OFB(ctx->vek, 16, ctx->iv, 16, decryptNalUnit + 1, decryptNalUnitLen - 2,
                                  tmpEncBuf, encSize, false);
#endif

            if (ret == 0) {
                //把第一个字节复制到解密流里，并设置加密设为1
                memcpy(&encryptNalUnit[encryptNalUnitLen], decryptNalUnit, 1);
                encryptNalUnit[encryptNalUnitLen] = encryptNalUnit[encryptNalUnitLen] | 0x02;
                encryptNalUnitLen = encryptNalUnitLen + 1;
                //防伪字节添加
                int preLen = prevention(tmpEncBuf, encSize, &encryptNalUnit[encryptNalUnitLen]);
                encryptNalUnitLen += preLen;
                //结尾字节添加
                memcpy(&encryptNalUnit[encryptNalUnitLen], decryptNalUnit + decryptNalUnitLen - 1, sizeof(unsigned char));
                encryptNalUnitLen++;

            }
            else {
                std::cout << "cryptSM4Ofb fail" << std::endl;
                memcpy(encryptNalUnit, decryptNalUnit, decryptNalUnitLen);
                encryptNalUnitLen = decryptNalUnitLen;
            }
            if (tmpEncBuf != nullptr) {
                free(tmpEncBuf);
                tmpEncBuf = nullptr;
            }
        }
        else {
            //不加密，复制原始不脱壳的数据
            memcpy(&encryptNalUnit[encryptNalUnitLen], tmpBuf, tmpBufLen);
            encryptNalUnitLen = encryptNalUnitLen + tmpBufLen;
        }
        //签名数据只对关键帧I
        if (ctx->isAuth && (nalu.nal_uint_type == NALU_TYPE_IDR_SLICE)) {
            //找到数据帧第一字节，设置签名为 1
            encryptNalUnit[len + 4] = encryptNalUnit[len + 4] | 0x01;
            unsigned char auth[200];
            ULONG authLen;
            buildNalAuth(ctx, (unsigned char*)encryptNalUnit + len + 4, encryptNalUnitLen - len - 4, auth, authLen);
            //签名数据是base64编码,不会出现000000，不做防伪码插入
            memcpy(&encryptNalUnit[encryptNalUnitLen], auth, authLen);
            encryptNalUnitLen += authLen;
        }

        free(tmpBuf);
        tmpBuf = nullptr;
    }
    else {
        memcpy(encryptNalUnit, decryptNalUnit, decryptNalUnitLen);
        encryptNalUnitLen = decryptNalUnitLen;
    }

    return 0;
}

ULONG decryptNalUnitsStream(DecodeCtx* ctx,  unsigned char* encryptNalusStream,  ULONG  encryptNalusStreamLen,  unsigned char* decryptNalusStream,  ULONG* decryptNalusStreamLen, bool needAuth, int* authResult) {
    //解密nalu流长度
    *decryptNalusStreamLen = 0;

    //以下是写入相关参数
    ULONG writeIndex = 0;

    //以下是读取相关参数
    ULONG readIndex = 0;
    unsigned long u32 = 0;//4 * 8 位数据
    unsigned long u24 = 0;//3 * 8 位数据
    ULONG nalStartIndexInStream = 0;//起始开区间
    ULONG nalEndInStream = 0;//末尾闭区间
    ctx->nalCtx.needHashDataLen = 0;
    memset(&(ctx->nalCtx.authparamPtr), 0x00, sizeof(auth_parameters));
    while (readIndex < encryptNalusStreamLen) {//字节流未到末尾
        unsigned char tmpchar = encryptNalusStream[readIndex];
        u32 = (u32 << 8 | tmpchar) & 0xffffffff; //读取32位操作指令
        u24 = u32 & 0xffffff;// 读取24位操作指令
        if (readIndex >= 3) {
            //已经读取了4个字节
            if (nalStartIndexInStream > 0) {
                //如果已经读取到nal的实际数据,则找结尾指令 0x000000 或者 0x000001
                if (u24 == 0x000000 || u24 == 0x000001) {
                    // if (u24 == 0x000001) {
                    //找到当前nal结尾
                    nalEndInStream = readIndex - 3;//往前3个字节即为nal结尾
                    //todo 1.从nalStartIndexInStream 到 nalStarEndInStream 即为整个nal单元
                    if (nalStartIndexInStream + 1 < nalEndInStream) {
                        //合法有效nal区间
                        ctx->nalCtx.currentEncryptNalLen = nalEndInStream - nalStartIndexInStream;
                        //memcpy(ctx->nalCtx.currentEncryptNalUnit, encryptNalusStream + nalStartIndexInStream + 1, ctx->nalCtx.currentEncryptNalLen);
                        //测试截取的数据
                        //todo 2.解析该段nal，如果为加密段，解密，否则返回原始数据
                        ctx->nalCtx.currentDecryptNalLen = 0;
                        bool tmp = false;
                        decryptNalUnit(ctx, encryptNalusStream + nalStartIndexInStream + 1, ctx->nalCtx.currentEncryptNalLen, decryptNalusStream + writeIndex, &(ctx->nalCtx.currentDecryptNalLen));
                        //todo 3.保存字节流
                        if (ctx->nalCtx.currentDecryptNalLen > 0) {
                            size_t memWriteLen = sizeof(unsigned char) * ctx->nalCtx.currentDecryptNalLen;
                            //memcpy(decryptNalusStream + writeIndex, ctx->nalCtx.currentDecryptNalUnit, memWriteLen);
                            writeIndex += memWriteLen;
                        }
                        else {
                            //去除前缀数据
                            writeIndex -= sizeof(ULONG);
                        }

                    }
                    nalStartIndexInStream = 0;
                    nalEndInStream = 0;
                }
            }
            else {
                //未读到nal实际数据,则寻找开始指令0x00000001
                if (u32 == 0x00000001) {
                    nalStartIndexInStream = readIndex;//nalStartIndexInStream 开区间
                    //写入分隔符号
                    memset(decryptNalusStream + writeIndex, 0x00, sizeof(ULONG) - 1);
                    memset(decryptNalusStream + writeIndex + 3, 0x01, sizeof(char));
                    writeIndex += sizeof(ULONG);
                    /*std::cout << std::endl << "decrypt nal unit start:" << std::endl;
                    printHex(decryptNalusStream, writeIndex);
                    std::cout << std::endl << "decrypt nal unit end:" << std::endl;*/
                }

            }
            readIndex++;
        }
        else {
            //说明正在读流中开始数据
            readIndex++;
            continue;

        }

    }

    //流结束，但是已经解析到nal开始，则需要把流最后作为结束
    if (nalStartIndexInStream != 0 && nalEndInStream == 0) {
        nalEndInStream = encryptNalusStreamLen - 1;
        if (nalStartIndexInStream + 1 < nalEndInStream) {
            //合法有效nal区间
            ctx->nalCtx.currentEncryptNalLen = nalEndInStream - nalStartIndexInStream;
            //memcpy(ctx->nalCtx.currentEncryptNalUnit, encryptNalusStream + nalStartIndexInStream + 1, ctx->nalCtx.currentEncryptNalLen);
            /*std::cout << std::endl << "new nal:" << std::endl;
            printHex(currentDecryptNalUnit, currentDecryptNalLen);
            std::cout << std::endl;*/
            //todo 2.解析该段nal，如果为加密段，解密，否则返回原始数据
            ctx->nalCtx.currentDecryptNalLen = 0;
            bool tmp = false;
            decryptNalUnit(ctx, encryptNalusStream + nalStartIndexInStream + 1, ctx->nalCtx.currentEncryptNalLen
                    , decryptNalusStream + writeIndex, &(ctx->nalCtx.currentDecryptNalLen));

            nalStartIndexInStream = 0;
            nalEndInStream = 0;
            //todo 3.保存字节流
            size_t memWriteLen = sizeof(char) * ctx->nalCtx.currentDecryptNalLen;
            writeIndex += memWriteLen;
            //如果最后一段输出为0，比如签名数据，那么去掉之前添加的分割符 00 00 00 01
            if ((ctx->nalCtx.currentDecryptNalLen) == 0) {
                writeIndex -= 4;
            }
        }
        nalStartIndexInStream = 0;
        nalEndInStream = 0;
    }

    ////对流做验签
    if (!needAuth) {
        *authResult = 2;
    }
    else {
        if (ctx->nalCtx.needHashDataLen > 0) {
            unsigned char digist[32] = { 0 };
            SSL_SM3(ctx->nalCtx.needHashData, ctx->nalCtx.needHashDataLen, digist);
            if (ctx->nalCtx.sesparamPtr.successive_hash_pictures_minus1 > 0) {
                if (ctx->nalCtx.hashEmpty) {
                    ctx->nalCtx.hashEmpty = false;
                    memcpy(ctx->nalCtx.hash, digist, 32);
                }
                else {
                    memcpy(ctx->nalCtx.hash + 32, digist, 32);
                    SSL_SM3(ctx->nalCtx.hash, 64, digist);
                    memcpy(ctx->nalCtx.hash, digist, 32);
                }
            }
            else {
                ctx->nalCtx.hashEmpty = false;
                memcpy(ctx->nalCtx.hash, digist, 32);
            }
            if (ctx->nalCtx.authparamPtr.auth_data_lenth_minus_1 > 0) {
                //出现验证unit，直接验证
                char* decodeSign2 = NULL;
                int decodeSign2Len = 0;
                base64Decode((char*)ctx->nalCtx.authparamPtr.authData, ctx->nalCtx.authparamPtr.auth_data_lenth_minus_1 + 1, 0, &decodeSign2, &decodeSign2Len);
                //gmssl 的签名格式是asn1 ，而返回的是gm标准 64位 前32位为r 后32位为s
                bool isSuccess = false;
                //验签
                if (ctx->streamSignkey.BitLen == 32 * 8) {

#ifdef	SKF_CRYPTO
                    ULONG ret = TRI_VERIFY_SIGNATURE(ctx->streamSignkey, digist, 32,
                                                     (unsigned char*)decodeSign2, decodeSign2Len, (unsigned char*)"1234567812345678");
#else
                    ULONG ret = SSL_VERIFY_SIGNATURE_RS(ctx->streamSignkey, digist, 32,
                                                     (unsigned char*)decodeSign2, decodeSign2Len, (unsigned char*)"1234567812345678");
#endif
                    if (ret == 0) {
                        *authResult = 0;
                    }
                    else {
                        *authResult = 1;
                    }
                }
                else {
                    *authResult = 3;
                }

                if (decodeSign2 != NULL) {
                    free(decodeSign2);
                }
            }
            else {
                *authResult = 2;
            }

        }
    }

    if (writeIndex != 0) {
        *decryptNalusStreamLen = writeIndex;
    }
    else {
        *decryptNalusStreamLen = 0;
    }

    return 0;
}

ULONG encryptNalUnitsStream(EncodeCtx* ctx,  unsigned char* decryptNalusStream,  ULONG decryptNalusStreamLen,  unsigned char* encryptNalusStream,  ULONG* encryptNalusStreamLen) {
    ////解密nalu流长度
    *encryptNalusStreamLen = 0;

    //以下是写入相关参数
    ULONG writeIndex = 0;

    //以下是读取相关参数
    ULONG readIndex = 0;
    unsigned long u32 = 0;//4 * 8 位数据
    unsigned long u24 = 0;//3 * 8 位数据
    ULONG nalStartIndexInStream = 0;//起始开区间
    ULONG nalEndInStream = 0;//末尾闭区间

    while (readIndex < decryptNalusStreamLen) {//字节流未到末尾
        unsigned char tmpchar = decryptNalusStream[readIndex];
        u32 = u32 << 8 | tmpchar; //读取32位操作指令
        u24 = u32 & 0xffffff;// 读取24位操作指令
        if (readIndex >= 3) {
            //已经读取了4个字节
            if (nalStartIndexInStream > 0) {
                //如果已经读取到nal的实际数据,则找结尾指令 0x000000 或者 0x000001
                if (u24 == 0x000000 || u24 == 0x000001) {
                    //找到当前nal结尾
                    nalEndInStream = readIndex - 3;//往前3个字节即为nal结尾
                    //todo 1.从nalStartIndexInStream 到 nalStarEndInStream 即为整个nal单元
                    if (nalStartIndexInStream + 1 < nalEndInStream) {
                        //合法有效nal区间
                        ctx->nalCtx.currentDecryptNalLen = nalEndInStream - nalStartIndexInStream;
                        //memcpy(ctx->nalCtx.currentDecryptNalUnit, decryptNalusStream + nalStartIndexInStream + 1, ctx->nalCtx.currentDecryptNalLen);
                        //测试截取的数据
                        //todo 2.解析该段nal，如果为加密段，解密，否则返回原始数据
                        ctx->nalCtx.currentEncryptNalLen = 0;
                        encryptNalUnit2(ctx, decryptNalusStream + nalStartIndexInStream + 1, ctx->nalCtx.currentDecryptNalLen,
                                        encryptNalusStream + writeIndex, (ctx->nalCtx.currentEncryptNalLen));
                        //todo 3.保存字节流
                        if (ctx->nalCtx.currentEncryptNalLen > 0) {
                            size_t memWriteLen = sizeof(char) * ctx->nalCtx.currentEncryptNalLen;
                            //memcpy(encryptNalusStream + writeIndex, ctx->nalCtx.currentEncryptNalUnit, memWriteLen);
                            writeIndex += memWriteLen;
                        }
                        else {
                            //去除前缀数据
                            writeIndex -= sizeof(ULONG);
                        }

                    }
                    nalStartIndexInStream = 0;
                    nalEndInStream = 0;
                }
            }
            else {
                //未读到nal实际数据,则寻找开始指令0x00000001
                if (u32 == 0x00000001) {
                    nalStartIndexInStream = readIndex;//nalStartIndexInStream 开区间
                    //写入分隔符号
                    memset(encryptNalusStream + writeIndex, 0x00, sizeof(ULONG) - 1);
                    memset(encryptNalusStream + writeIndex + 3, 0x01, sizeof(char));
                    writeIndex += sizeof(ULONG);
                    /*std::cout << std::endl << "decrypt nal unit start:" << std::endl;
                    printHex(decryptNalusStream, writeIndex);
                    std::cout << std::endl << "decrypt nal unit end:" << std::endl;*/
                }

            }
            readIndex++;
        }
        else {
            //说明正在读流中开始数据
            readIndex++;
            continue;

        }

    }

    //流结束，但是已经解析到nal开始，则需要把流最后作为结束
    if (nalStartIndexInStream != 0 && nalEndInStream == 0) {
        nalEndInStream = decryptNalusStreamLen - 1;
        if (nalStartIndexInStream + 1 < nalEndInStream) {
            //合法有效nal区间
            ctx->nalCtx.currentDecryptNalLen = nalEndInStream - nalStartIndexInStream;
            //memcpy(ctx->nalCtx.currentDecryptNalUnit, decryptNalusStream + nalStartIndexInStream + 1, ctx->nalCtx.currentDecryptNalLen);
            /*std::cout << std::endl << "new nal:" << std::endl;
            printHex(currentDecryptNalUnit, currentDecryptNalLen);
            std::cout << std::endl;*/
            //todo 2.解析该段nal，如果为加密段，解密，否则返回原始数据
            ctx->nalCtx.currentEncryptNalLen = 0;

            encryptNalUnit2(ctx, decryptNalusStream + nalStartIndexInStream + 1, ctx->nalCtx.currentDecryptNalLen,
                            encryptNalusStream + writeIndex, (ctx->nalCtx.currentEncryptNalLen));

            nalStartIndexInStream = 0;
            nalEndInStream = 0;
            //todo 3.保存字节流
            size_t memWriteLen = sizeof(char) * ctx->nalCtx.currentEncryptNalLen;
            //memcpy(encryptNalusStream + writeIndex, ctx->nalCtx.currentEncryptNalUnit, memWriteLen);
            writeIndex += memWriteLen;
            if ((ctx->nalCtx.currentEncryptNalLen) == 0) {
                writeIndex -= 4;
            }
        }
        nalStartIndexInStream = 0;
        nalEndInStream = 0;
    }
    if (writeIndex != 0) {
        *encryptNalusStreamLen = writeIndex;
    }
    else {
        *encryptNalusStreamLen = 0;
    }
    return 0;
}

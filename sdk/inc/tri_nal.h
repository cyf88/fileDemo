//
// Created by cyf on 2024/2/28.
//

#ifndef FILEDEMO_TRI_NAL_H
#define FILEDEMO_TRI_NAL_H

#include "type_def.h"



/*
    解析标准NAL单元(需要去除开始和结束特殊指令)
*/
ULONG decryptNalUnit(DecodeCtx* ctx,  unsigned char* encryptNalUnit,  ULONG encryptNalUnitLen,  unsigned char* decryptNalUnit,  ULONG* decryptNalUnitLen);

ULONG encryptNalUnit2(EncodeCtx* ctx,  unsigned char* decryptNalUnit,  ULONG decryptNalUnitLen,  unsigned char* encryptNalUnit,  ULONG* encryptNalUnitLen);

ULONG rebuildNalSes(DecodeCtx* ctx, ses_parameters* ses, unsigned char** outSes, ULONG* outLen);

/*
    解析标准NAL数据流(可以解析包含带开始和结束指令的nal单元串)
*/
ULONG decryptNalUnitsStream(DecodeCtx* ctx,  unsigned char* encryptNalusStream,  ULONG  encryptNalusStreamLen,  unsigned char* decryptNalusStream,  ULONG* decryptNalusStreamLen, bool needAuth, int* authResult);

/*
    加密标准NAL数据流(可以解析包含带开始和结束指令的nal单元串)
*/
ULONG encryptNalUnitsStream(EncodeCtx* ctx,  unsigned char* decryptNalusStream,  ULONG decryptNalusStreamLen, unsigned char* encryptNalusStream,  ULONG* encryptNalusStreamLen);

/*
  解析ses实际参数
*/
ULONG ses_parameters_set(DecodeCtx* ctx, unsigned char* rbspBuffer, ULONG rbspBufferLen, ses_parameters* ses_ptr);

ULONG auth_parameters_set(DecodeCtx* ctx, unsigned char* rbspBuffer, ULONG rbspBufferLen, auth_parameters* auth_ptr);

ULONG time_parameters_set(DecodeCtx* ctx, unsigned char* rbspBuffer, ULONG rbspBufferLen, time_parameters* time_ptr);

#endif //FILEDEMO_TRI_NAL_H

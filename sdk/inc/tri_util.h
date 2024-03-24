#ifndef __triutil__
#define __triutil__

#include "type_def.h"
#include <iostream>
#include<cstdio>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <bitset>
#include "easylogging++.h"
#include <vector>


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


ULONG str_splites( char* inOrigin,  const char* inPattern,  char** out,  int* outLen);

ULONG readX509UserCredentialCNFromMem( unsigned char* data,  int dataLen,  char* clientId,  UINT* clientIdlen);

ULONG readX509UserCredentialCN( X509* cert, char* clientId,  UINT* clientIdlen);

ULONG get_buffer(EVP_PKEY* pkey, unsigned char** pub_key, int* pkeyLen);

ULONG base64Encode(const char* buffer, int length, bool newLine, char** out, int* outlen);

ULONG base64Decode(char* input, int length, bool newLine, char** out, int* outlen);

ULONG TRI_REMOVE_PS_HEAD( unsigned char* inBuf,  ULONG inSize,  unsigned char* oBuf, ULONG* outSize, ULONG* frametype);

void printHex(unsigned char* buffer, int size);

void writeData(const char* path, unsigned char* data, ULONG dataLen);

ULONG bitset_2_char(const std::bitset<MAX_BITS_LENGTH>* bits, ULONG startBitIndex, ULONG len, unsigned char* buf);

ULONG array_2_bitset( unsigned char* data,  ULONG dataLen,  std::bitset<MAX_BITS_LENGTH>* out,   ULONG* outLen);

ULONG TRI_ENCODE_PUBKEY( const unsigned char* buffer,  char** out,  int* outlen);

std::string GetExePath();

std::string getValueFromConfig(const std::string& configFile, const std::string& section, const std::string& key);
int prevention(uint8_t* src, size_t srcLen, uint8_t* dst);
int exuviation(uint8_t* src, size_t srcLen, uint8_t* dst);
std::string getCurrentFormattedTime(const std::string& format, bool msFlag);
std::vector<std::string> splitSkfFiles(const char* str, int strLen);
std::string charArrayToHex(const unsigned char* charArray, int length);
void hexStringToCharArray(const std::string& hexString, char* charArray);
std::string addOrSubtractHours(const std::string& timeStr, int hours);
std::string calculateMD5(const char* buffer, size_t length);
bool isBeforeDeadline(const std::string formattedDeadLine);
int calculateDaysDifference(const std::string formattedDeadLine);



#endif // !__tritypeapi__



#include "tri_util.h"
#include <iostream>
#include <bitset>
#include <ctime>
#include <iomanip>
#include <openssl/md5.h>
#include <openssl/skf.h>
#include "type_def.h"


using namespace std;


ULONG bitset_2_char(const std::bitset<MAX_BITS_LENGTH>* bits, ULONG startBitIndex, ULONG len, unsigned char* buf) {
	char ch = { 0 };
	for (ULONG i = 0; i < len; i++) {

		if (bits->test(MAX_BITS_LENGTH - 1 - startBitIndex - i)) {	// 第i + j位为1
			ch = (ch << 1) | 0x1;
		}
		else {
			ch = ch << 1;
		}
	}
	*buf = ch;
	return 0;
}


ULONG array_2_bitset( unsigned char* data,  ULONG dataLen,  std::bitset<MAX_BITS_LENGTH>* out,   ULONG* outLen) {
	*outLen = 0;
	ULONG n_bits = dataLen * 8;
	for (ULONG i = 0; i < dataLen; ++i)
	{
		unsigned char ch = data[i];
		ULONG n_offset = i * 8;
		for (int j = 7; j >= 0; j--)
		{
			out->set(MAX_BITS_LENGTH - 1 - n_offset - (7 - j), ch & (1 << j));	// 第j位为是否为1
			*outLen = *outLen + 1;
		}
	} 
	return 0;
}

void writeData(const char* path, unsigned char* data, ULONG dataLen) {
	FILE* stream;
	int numwrite = 0;
	if ((stream = fopen(path, "wb")) != NULL)  // 文件写入
	{
		numwrite = fwrite(data, sizeof(unsigned char), dataLen, stream);
		printf("Number of items write = %d\n", numwrite);
		fclose(stream);
	}
	
}

ULONG str_splites( char* inOrigin,  const char* inPattern,  char** out,  int* outLen) {
	std::cout << "inOrgin:" << inOrigin << std::endl;
	int len = 0;
	char* tmp = strtok(inOrigin, inPattern);
	while (tmp) {
		*(out + len) = tmp;
		std::cout << "index:" << len << " " << *(out + len) << std::endl;
		++len;
		// 再次调用分割时指针要变为NULL, 也就是这里的第一个参数，分割的字符串还是str
		// 第二个参数要和第一次调用时的分割符保持一致
		tmp = strtok(NULL, inPattern);
	}
	*outLen = len;
	std::cout << *outLen << std::endl;
	return 0;
}

ULONG get_buffer(EVP_PKEY* pkey, unsigned char** pub_key, int* pkeyLen) {
	EC_KEY* tempEcKey = NULL;

	tempEcKey = EVP_PKEY_get0_EC_KEY(pkey);
	if (tempEcKey == NULL) {
		printf("Getting EC_KEY from EVP_PKEY error");
		return 1;
	}

	const EC_GROUP* group = EC_KEY_get0_group(tempEcKey);
	point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);

	*pkeyLen = EC_KEY_key2buf(tempEcKey, form, pub_key, NULL);
	if (*pkeyLen == 0) {
		printf("Creating buffer from key error");
		return 2;
	}
	return 0;
}

ULONG readX509UserCredentialCN( X509* cert,  char* clientId,  UINT* clientIdlen) {
	X509_NAME* subj = X509_get_subject_name(cert);
	int len = 1024;
	char buf[1024];
	int ret = X509_NAME_get_text_by_NID(subj, NID_commonName, buf, len);
	printf("commonName : %s\n\n", buf);
	char* splitesTmp[10];
	int length = 0;
	str_splites(buf, "_", splitesTmp, &length);
	if (length > 0) {
		strcpy(clientId, splitesTmp[0]);
		*clientIdlen = strlen((const char*)clientId);
		return 0;
	}
	else {
		return 1;
	}
}



ULONG readX509UserCredentialCNFromMem( unsigned char* data,  int dataLen,  char* clientId,  UINT* clientIdlen) {
	LOG(DEBUG) << "usrCert pause started";
	BIO* certBio = NULL;
	X509* usrCert = d2i_X509(NULL, (const unsigned char**)&data, dataLen);
	LOG(DEBUG) << "usrCert pause end";
	if (usrCert == NULL) {
		LOG(DEBUG) << "usrCert pause error 1";
		certBio = BIO_new(BIO_s_mem());
		BIO_write(certBio, data, dataLen);
		usrCert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
		if (usrCert == NULL) {
			LOG(DEBUG) << "usrCert pause error 2";
			return EXIT_FAILURE;
		}
	}
	LOG(DEBUG) << "usrCert geted";
	long Version = X509_get_version(usrCert);
	std::cout << Version << std::endl;
	int ret = readX509UserCredentialCN(usrCert, clientId, clientIdlen);
	if (certBio != NULL) {
		BIO_free(certBio);
	}
	if (usrCert != NULL)
		X509_free(usrCert);
	return ret;
}


ULONG base64Encode(const char* buffer, int length, bool newLine,char ** out,int * outlen)
{
	BIO* bmem = NULL;
	BIO* b64 = NULL;
	BUF_MEM* bptr;

	b64 = BIO_new(BIO_f_base64());
	if (!newLine) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, buffer, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);
	BIO_set_close(b64, BIO_NOCLOSE);

	char* buff = (char*)malloc(bptr->length + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;
	*out = buff;
	*outlen = bptr->length;
	BIO_free_all(b64);

	return 0;
}

// base64 解码
ULONG base64Decode(char* input, int length, bool newLine, char** out, int* outlen)
{
	BIO* b64 = NULL;
	BIO* bmem = NULL;
	char* buffer = (char*)malloc(length);
	memset(buffer, 0, length);
	b64 = BIO_new(BIO_f_base64());
	if (!newLine) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	int size = BIO_read(bmem, buffer, length);
	*out = buffer;
	*outlen = size;
	BIO_free_all(bmem);
	return 0;
}

void printHex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

ULONG TRI_REMOVE_PS_HEAD( unsigned char* inBuf,  ULONG inSize,  unsigned char* oBuf,  ULONG* outSize, ULONG* frametype) {

	ULONG PESBodyLength = 0;
	unsigned char* pCurBuf = inBuf;
	while (true) {
		if (pCurBuf >= (inBuf + inSize)) {
			break;
		}
		unsigned int* pcode = (unsigned int*)pCurBuf;
		if (*pcode == 0xBA010000) {
			*frametype = P_frame;
			pCurBuf += 13;
			unsigned int pack_stuffing_length = *pCurBuf & 7;
			pCurBuf++;
			pCurBuf += pack_stuffing_length;
			continue;
		}
		else if (*pcode == 0xBB010000) {
			int Systemheader_length = *(pCurBuf + 4) * 256 + *(pCurBuf + 5);
			pCurBuf += Systemheader_length + 4 + 2;
			*frametype = I_frame;
			continue;
		}
		else if (*pcode == 0xBC010000) {
			int psmlength = *(pCurBuf + 4) * 256 + *(pCurBuf + 5);

			uint32_t u32PSILength = 0;
			u32PSILength = u32PSILength | pCurBuf[8];
			u32PSILength = (u32PSILength << 8) | pCurBuf[9];

			uint32_t u32ESMLength = 0;
			u32ESMLength = u32ESMLength | pCurBuf[10 + u32PSILength];
			u32ESMLength = (u32ESMLength << 8) | pCurBuf[11 + u32PSILength];

			uint8_t* pESM = pCurBuf + 12 + u32PSILength;
			uint32_t u32Tmp = 0;
			while (u32Tmp < u32ESMLength) {
				uint32_t u32StreamID = pESM[1 + u32Tmp];
				u32StreamID &= 0x000000FF;
				u32StreamID |= 0x00000100;
				if (u32StreamID == 0x01C0) {
				}
				uint32_t u32ESILength = 0;
				u32ESILength = u32ESILength | pESM[2 + u32Tmp];
				u32ESILength = (u32ESILength << 8) | pESM[3 + u32Tmp];
				if (u32ESILength == 0) {
					break;
				}
				u32Tmp += (2 + 2 + u32ESILength);
			}

			pCurBuf += psmlength + 4 + 2;
			*frametype = I_frame;
			continue;
		}
		else if (*pcode == 0xE0010000) {  // video

			int pes_packet_length = *(pCurBuf + 4) * 256 + *(pCurBuf + 5);
			int pes_header_data_length = *(pCurBuf + 8);
			int payload_length = pes_packet_length - 3 - pes_header_data_length;
			pCurBuf += 9 + pes_header_data_length;

			memcpy(oBuf + PESBodyLength, pCurBuf, payload_length);
			PESBodyLength += payload_length;
			pCurBuf += payload_length;
			continue;
		}
		else if (*pcode == 0xC0010000) {  // audio
			int pes_packet_length = *(pCurBuf + 4) * 256 + *(pCurBuf + 5);
			int pes_header_data_length = *(pCurBuf + 8);
			int payload_length = pes_packet_length - 3 - pes_header_data_length;
			pCurBuf += 9 + pes_header_data_length;
			pCurBuf += payload_length;
			continue;
		}
		else {
			break;
		}
	}
	*outSize = PESBodyLength;
	return 0;
}

/*
用于公钥打印和base64编码
*/
ULONG TRI_ENCODE_PUBKEY( const unsigned char* buffer,  char** out,  int* outlen) {
	unsigned char publicKey[65] = { 0 };
	//公钥中补04
	publicKey[0] = { 0x04 };
	int indexKey = 1;
	for (int i = 36; i < 68; i++) {
		publicKey[indexKey] = buffer[i];
		indexKey++;
		//std::cout << std::hex << " 0x" << (int)buffer[i];
	}
	//std::cout << std::endl;
	for (int i = 100; i < 132; i++) {
		publicKey[indexKey] = buffer[i];
		indexKey++;
		//std::cout << std::hex << " 0x" << (int)buffer[i];
	}
	//std::cout << std::endl;
	base64Encode((const char*)publicKey, 65, 0, out, outlen);
	//std::cout << "GET BASE64 PublicKey: " << *out << std::endl;
	return 0;
}



// 去除字符串两端的空格
static std::string trim(const std::string& str) {
	size_t first = str.find_first_not_of(' ');
	if (std::string::npos == first) {
		return str;
	}
	size_t last = str.find_last_not_of(' ');
	return str.substr(first, (last - first + 1));
}

std::string getValueFromConfig(const std::string& configFile, const std::string& section, const std::string& key) {
	std::ifstream configStream(configFile);
	if (!configStream) {
		return "";
	}

	std::string line;
	std::string currentSection;
	bool foundSection = false;

	while (std::getline(configStream, line)) {
		line = trim(line);
		if (line.empty()) {
			continue;
		}

		if (line[0] == '[' && line.back() == ']') {
			currentSection = line.substr(1, line.size() - 2);
			foundSection = (currentSection == section);
		}
		else if (foundSection && std::count(line.begin(), line.end(), '=') == 1) {
			std::istringstream iss(line);
			std::string sectionKey, value;
			if (iss >> sectionKey) {
				size_t eqPos = line.find('=');
				value = line.substr(eqPos + 1);
				sectionKey = trim(sectionKey);
				value = trim(value);
				if (sectionKey == key) {
					return value;
				}
			}
		}
	}

	return "";
}


//检测到 00 00 [00,01,02,03]添加03
int prevention(uint8_t* src, size_t srcLen, uint8_t* dst) {
	if (src == NULL || srcLen < 3) {
		return -1;
	}
	int dstPtr = 0;
	for (int i = 0; i < srcLen; i++) {
		uint32_t windows_data = src[i] << 16 | src[i + 1] << 8 | src[i + 2];
		windows_data = windows_data & 0xffffff;
		if (windows_data <= uint32_t(0x03)) {
			dst[dstPtr++] = 0x00;
			dst[dstPtr++] = 0x00;
			dst[dstPtr++] = 0x03;
			i++;
			continue;
		}
		dst[dstPtr++] = src[i];
	}
	return dstPtr;
}

//码流脱壳操作， 检测到 00 00 03时去掉03
int exuviation(uint8_t* src, size_t srcLen, uint8_t* dst) {
	if (src == NULL || srcLen < 4) {
		return -1;
	}
	int dstPtr = 0;
	for (int i = 0; i < srcLen; i++) {
		if (i + 2 < srcLen) {
			uint32_t windows_data = src[i] << 16 | src[i + 1] << 8 | src[i + 2];
			if (windows_data <= (uint32_t)0x03) {
				dst[dstPtr++] = 0x00;
				dst[dstPtr++] = 0x00;
				i += 2;
				continue;
			}
		}
		dst[dstPtr++] = src[i];
	}
	return dstPtr;
}


/*
* msFlag 毫秒输出
*/
std::string getCurrentFormattedTime(const std::string& format, bool msFlag) {
	auto now = std::chrono::system_clock::now();

	std::time_t now_c = std::chrono::system_clock::to_time_t(now);
	struct tm* parts = std::localtime(&now_c);

	char buffer[256];
	std::strftime(buffer, sizeof(buffer), format.c_str(), parts);

	if (msFlag) {
		auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
		std::stringstream ss;
		ss << std::setw(3) << std::setfill('0') << ms.count();
		return std::string(buffer) + "." + ss.str();
	}
	else {
		return std::string(buffer);
	}
}

//分割文件名字符串，是用\0分割的
std::vector<std::string> splitSkfFiles(const char* str, int strLen) {
	std::vector<std::string> result;
	std::string token;
	int i = 0;
	for (int i = 0; i < strLen; i++) {
		if (str[i] != '\0') {
			token += str[i];
		}
		else {
			if (!token.empty()) {
				result.push_back(token);
				token.clear();
			}
		}
	}
	if (!token.empty()) {
		result.push_back(token);
	}
	return result;
}

std::string charArrayToHex(const unsigned char* charArray, int length) {
	std::stringstream ss;

	for (int i = 0; i < length; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(charArray[i]);
	}

	return ss.str();
}

void hexStringToCharArray(const std::string& hexString, char* charArray) {
	int charArrayLength = hexString.length() / 2;
	for (size_t i = 0; i < hexString.length(); i += 2) {
		std::string byteString = hexString.substr(i, 2);
		char byte = static_cast<char>(std::stoi(byteString, nullptr, 16));
		charArray[i / 2] = byte;
	}

}


// 函数：增加或减少小时数
std::string addOrSubtractHours(const std::string& timeStr, int hours) {
	// 将时间字符串转换为时间点
	std::tm tm = {};
	std::istringstream ss(timeStr);
	ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

	if (ss.fail()) {
		return "Invalid time format";
	}

	// 将时间点转换为时间戳
	std::time_t timeValue = std::mktime(&tm);

	// 计算增加或减少后的时间
	timeValue += hours * 3600;

	// 将时间戳转换回时间点
	tm = *std::localtime(&timeValue);

	// 格式化为输出字符串
	std::ostringstream result;
	result << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S");
	return result.str();
}

std::string calculateMD5(const char* buffer, size_t length) {
	MD5_CTX md5Context;
	MD5_Init(&md5Context);
	MD5_Update(&md5Context, buffer, length);

	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5_Final(hash, &md5Context);

	std::stringstream md5StringStream;
	md5StringStream << std::hex << std::setfill('0');
	for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
		md5StringStream << std::setw(2) << static_cast<unsigned>(hash[i]);
	}

	return md5StringStream.str();
}

bool isBeforeDeadline(const std::string formattedDeadLine) {
	// 获取当前时间
	auto now = std::chrono::system_clock::now();

	// 将格式化的时间字符串转换为 std::chrono::time_point
	std::tm tmInput = {};
	std::istringstream ss(formattedDeadLine);
	ss >> std::get_time(&tmInput, "%Y-%m-%d");

	auto timePointInput = std::chrono::system_clock::from_time_t(std::mktime(&tmInput));

	// 比较时间点
	return now < timePointInput;
}

int calculateDaysDifference(const std::string formattedDeadLine) {
	if (!isBeforeDeadline(formattedDeadLine)) {
		return 0;
	}
	// 获取当前日期
	auto now = std::chrono::system_clock::now();
	auto nowTime = std::chrono::system_clock::to_time_t(now);
	std::tm tmNow = *std::localtime(&nowTime);

	// 将输入的日期字符串转换为 std::tm
	std::tm tmInput = {};
	std::istringstream ss(formattedDeadLine);
	ss >> std::get_time(&tmInput, "%Y-%m-%d");

	// 计算日期差
	auto timeInput = std::chrono::system_clock::from_time_t(std::mktime(&tmInput));
	auto timeDifference = std::chrono::duration_cast<std::chrono::hours>(timeInput - now);
	int daysDifference = timeDifference.count() / 24;

	return daysDifference;
}





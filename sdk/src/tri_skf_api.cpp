#define FMCFG_OS_WINDOWS
//#define FILE_STORAGE

#include "tri_skf_api.h"
#include "openssl/gmapi.h"
#include "tri_util.h"
#include "tri_gmssl.h"
#include "easylogging++.h"
#include <iostream>
#include <vector>
#include <openssl/sm2.h>
#include "openssl/sms4.h"
#include "openssl/modes.h"
#include <openssl/asn1.h>
#include <openssl/gmskf.h>

#define PKCS5_PADDING 1
#define MAX_EXPORT_SIZE 3
#define EXPORT_FILE_SIZE 2048
#define EXPORT_FILE_NAME "exportFile"
#define PLAYRIGHT_FILE_NAME "playRightFile"

#define APPLICATION_NAME  "fisec" //需要修改正式的应用名称
#define CLINET_CONTAINER_NAME  "fcontainer1" //需要修改正式的容器名称
#define SERVER_CONTAINER_NAME  "fcontainer0" //需要修改正式的容器名称

#define APPLICATION_NAME_OTHER "FisecApp"    //部里的UKey名称
#define CLINET_CONTAINER_NAME_OTHER "FisecCon"


/* key relative vars */
DEVHANDLE           dev;
HAPPLICATION        application;
HCONTAINER          client_container;
HCONTAINER          server_container;

static BIO* bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);


ULONG TRI_EXPORT_CERT_TO_FILE(int flag) {
	unsigned char* cert = (unsigned char*)malloc(sizeof(unsigned char) * 1024);
	ULONG size = 0;
	SKF_ExportCertificate(client_container, flag, cert, &size);
	int numwrite = 0;
	FILE* stream;
	std::string fileName = "cert";
	if (flag == 0) {
		fileName = fileName + "0.cer";
	}
	else {
		fileName = fileName + "1.cer";
	}
	if ((stream = fopen(fileName.c_str(), "wb")) != NULL)  // 文件写入
	{
		numwrite = fwrite(cert, sizeof(unsigned char), size, stream);
		printf("Number of items write = %d\n", numwrite);
		fclose(stream);
	}
	if (cert != NULL) {
		free(cert);
	}
	return 0;
}

ULONG TRI_GET_DECRYPT_VKEK(unsigned char* encrypt_vkek, ULONG encrypt_vkek_len, unsigned char* decrypt_vkek, ULONG* decrypt_vkek_len) {
	unsigned char* ecccryptblob = NULL;
	TRI_CONVERT_CRYPTDATA_TO_ECCCIPHERBLOB(encrypt_vkek, encrypt_vkek_len, &ecccryptblob);
//	int ret = SKF_PrvKeyDecrypt(client_container, 1, (ECCCIPHERBLOB*)ecccryptblob, decrypt_vkek, decrypt_vkek_len);
//	if (ret != 0) {
//		printf("SKF_PrvKeyDecrypt error rv=%08x\n", ret);
//		if (ecccryptblob != NULL) {
//			OPENSSL_free(ecccryptblob);
//		}
//		return ret;
//	}
	if (ecccryptblob != NULL) {
		OPENSSL_free(ecccryptblob);
	}
	return 0;
}

ULONG TRI_INIT_SKF_DEVICE( char* PIN) {
	int	nRet = 0;
	ULONG uiListLen = 0;
	ULONG retrycount = 0;
	LPSTR pDevList = NULL;

	unsigned char random[16] = { 0 };
	BLOCKCIPHERPARAM EncryptParam;
	unsigned char cipher[32] = { 0 };
	ULONG ulcipherLen = 16;
	HANDLE hSessionKey;

	unsigned char au8IntExtKey[16] =
	{
		0x31, 0x32, 0x33, 0x34,
		0x35, 0x36, 0x37, 0x38,
		0x31, 0x32, 0x33, 0x34,
		0x35, 0x36, 0x37, 0x38,
	};


	nRet = SKF_EnumDev(1, NULL, &uiListLen);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "1 SKF_EnumDev Error,rv=" << nRet;
		return nRet;
	}
	LOG(DEBUG) << "1.SKF_EnumDev Ok ";
	if (uiListLen == 0) {
		LOG(DEBUG) << "SKF_ConnectDev not found dev";
		return -1;
	}
	pDevList = (LPSTR)malloc(uiListLen * sizeof(unsigned char));
	memset(pDevList, 0x00, uiListLen);
	nRet = SKF_EnumDev(1, pDevList, &uiListLen);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "2 SKF_EnumDev Error,rv=" << nRet;
		return nRet;
	}
	LOG(DEBUG) << "2.SKF_EnumDev Ok num:" << uiListLen;

	nRet = SKF_ConnectDev(pDevList, &dev);
	//nRet = SKF_ConnectDev(deviceTestName, &dev);
	if (nRet != SAR_OK) {
		LOG(DEBUG) << "SKF_ConnectDev Error,rv" << nRet;
		return nRet;
	}
	LOG(DEBUG) << "SKF_ConnectDev Ok";

	nRet = SKF_GenRandom(dev, random, 8);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "SKF_GenRandom Error,rv=" << nRet;
		return nRet;
	}
	LOG(DEBUG) << "SKF_GenRandom Ok";

	memset(&EncryptParam, 0x00, sizeof(BLOCKCIPHERPARAM));
	EncryptParam.PaddingType = PKCS5_PADDING;

	nRet = SKF_SetSymmKey(dev, au8IntExtKey, SGD_SM1_ECB, &hSessionKey);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "SKF_SetSymmKey Error,rv=" << nRet;
		return nRet;
	}
	LOG(DEBUG) << "SKF_SetSymmKey Ok";

	nRet = SKF_EncryptInit(hSessionKey, EncryptParam);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "SKF_EncryptInit Error,rv=" << nRet;
		return nRet;
	}
	LOG(DEBUG) << "SKF_EncryptInit Ok";

	nRet = SKF_Encrypt(hSessionKey, random, 16, cipher, &ulcipherLen);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "SKF_Encrypt Error,rv=" << nRet;
		return nRet;
	}
	LOG(DEBUG) << "SKF_Encrypt Ok";

	nRet = SKF_DevAuth(dev, cipher, 16);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "SKF_DevAuth Error,rv=" << nRet;
		return nRet;
	}
	LOG(DEBUG) << "SKF_DevAuth Ok";

	if (hSessionKey != NULL) {
		SKF_CloseHandle(hSessionKey);
	}

	nRet = SKF_OpenApplication(dev, (LPSTR)APPLICATION_NAME, &application);
	if (nRet != SAR_OK)
	{
		nRet = SKF_OpenApplication(dev, (LPSTR)APPLICATION_NAME_OTHER, &application);
		if (nRet != SAR_OK) {
			LOG(DEBUG) << "SKF_OpenApplication Error,rv=" << nRet;
			return nRet;
		}
	}
	LOG(DEBUG) << "SKF_OpenApplication Ok";

	nRet = SKF_VerifyPIN(application, USER_TYPE, (LPSTR)PIN, &retrycount);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "SKF_VerifyPIN Error,rv=" << nRet;
		TRI_DESTROY_APPLICATION();
		TRI_DESTROY_DEV();
		return nRet;
	}
	LOG(DEBUG) << "SKF_VerifyPIN Ok";
	nRet = SKF_OpenContainer(application, (LPSTR)CLINET_CONTAINER_NAME, &client_container);
	if (nRet != SAR_OK)
	{
		nRet = SKF_OpenContainer(application, (LPSTR)CLINET_CONTAINER_NAME_OTHER, &client_container);
		if (nRet != SAR_OK) {
			LOG(DEBUG) << "SKF_OpenContainer Error client,rv=" << nRet;
			TRI_DESTROY_APPLICATION();
			TRI_DESTROY_DEV();
			return nRet;
		}
	}
	LOG(DEBUG) << "SKF_Open client Container Ok";
	nRet = SKF_OpenContainer(application, (LPSTR)SERVER_CONTAINER_NAME, &server_container);
	if (nRet != SAR_OK)
	{
		LOG(DEBUG) << "SKF_OpenContainer Error server,rv=" << nRet;
		TRI_DESTROY_CONTAINER();
		TRI_DESTROY_APPLICATION();
		TRI_DESTROY_DEV();
		return nRet;
	}
	LOG(DEBUG) << "SKF_Open server Container Ok";

	return 0;
}

ULONG TRI_GET_RANDOM( ULONG randomLen,  unsigned char* random) {
	int ret = SKF_GenRandom(dev, random, randomLen);
	return ret;
}



ULONG TRI_VERIFY_SIGNATURE( ECCPUBLICKEYBLOB signPubKeyBlob,  unsigned char* plainText,  ULONG plain_len,
	 unsigned char* signature_in,  ULONG signature_in_len, unsigned char* id) {
	
	ULONG ret = 0;
	HANDLE hHash;
	ULONG signPubKeyBlobLen;
	ECCSIGNATUREBLOB	eccsign;

	ret = SKF_DigestInit(dev, SGD_SM3, &signPubKeyBlob, id, strlen((const char*)id), &hHash);
	if (ret != SAR_OK) {
		LOG(DEBUG) << "SKF_DigestInit Error,rv=" << ret;
		return ret;
	}
	unsigned char outData[64];
	ULONG outDataLen = 64;
	ret = SKF_Digest(hHash, plainText, plain_len, outData, &outDataLen);
	if (ret != SAR_OK) {
		LOG(DEBUG) << "SKF_Digest Error,rv=" << ret;
		return ret;
	}

	//封装der格式签名数据
	ECDSA_SIG* esig = d2i_ECDSA_SIG(NULL, (const unsigned char**)&signature_in, signature_in_len);
	ECDSA_SIG_get_ECCSIGNATUREBLOB(esig, &eccsign);

	ret = SKF_ExtECCVerify(dev, &signPubKeyBlob, outData, outDataLen, &eccsign);
	if (ret != SAR_OK)
	{
		LOG(DEBUG) << "SKF_ExtECCVerify Fail,rv=" << ret;
		return ret;
	}
	return ret;

}



ULONG TRI_SIGNATURE( ECCPUBLICKEYBLOB signPublicKey,  unsigned char* plainText,  ULONG plain_len,
	 unsigned char* signature_out,  ULONG* signature_out_len, unsigned char* id) {

	int ret = 0;
	HANDLE hHash;
	ret = SKF_DigestInit(dev, SGD_SM3, &signPublicKey, id, strlen((const char*)id), &hHash);
	if (ret != SAR_OK)
	{
		printf("SKF_DigestInit Error,rv=%08x\n", ret);
		return ret;
	}
	printf("SKF_DigestInit Ok\n");
	unsigned char hashData[1024];
	ULONG hashDataLen = 0;
	ret = SKF_Digest(hHash, plainText, plain_len, hashData, &hashDataLen);
	if (ret != SAR_OK)
	{
		printf("SKF_Digest Error,rv=%08x\n", ret);
		return ret;
	}
	printf("SKF_Digest Ok\n");

	ECCSIGNATUREBLOB signData;
	memset(&signData, 0x00, sizeof(ECCSIGNATUREBLOB));
	ret = SKF_ECCSignData(client_container, hashData, hashDataLen, &signData);
	if (ret != SAR_OK) {
		printf("SKF_ECCSignData Error,rv=%08x\n", ret);
		return ret;
	}
	ECDSA_SIG* esig = ECDSA_SIG_new_from_ECCSIGNATUREBLOB(&signData);
	unsigned char sign[256] = { 0 };
	*signature_out_len = i2d_ECDSA_SIG(esig, &signature_out);
	return 0;
}

ULONG TRI_SIGNATURE_RS( ECCPUBLICKEYBLOB signPublicKey,  unsigned char* plainText,  ULONG plain_len,
	 unsigned char* signature_out,  ULONG& signature_out_len, unsigned char* id) {

	int ret = 0;
	HANDLE hHash;
	ret = SKF_DigestInit(dev, SGD_SM3, &signPublicKey, id, strlen((const char*)id), &hHash);
	if (ret != SAR_OK)
	{
		printf("SKF_DigestInit Error,rv=%08x\n", ret);
		return ret;
	}
	printf("SKF_DigestInit Ok\n");
	unsigned char hashData[1024];
	ULONG hashDataLen = 0;
	ret = SKF_Digest(hHash, plainText, plain_len, hashData, &hashDataLen);
	if (ret != SAR_OK)
	{
		printf("SKF_Digest Error,rv=%08x\n", ret);
		return ret;
	}
	printf("SKF_Digest Ok\n");

	ECCSIGNATUREBLOB signData;
	memset(&signData, 0x00, sizeof(ECCSIGNATUREBLOB));
	ret = SKF_ECCSignData(client_container, hashData, hashDataLen, &signData);
	if (ret != SAR_OK) {
		printf("SKF_ECCSignData Error,rv=%08x\n", ret);
		return ret;
	}
	//128字节缩减到64个字节，将0去除
	//去除前32字节的0x00
	memcpy(signature_out, signData.r + 32, 32);
	memcpy(signature_out + 32, signData.s + 32, 32);
	signature_out_len = 64;

	return 0;
}


ULONG TRI_DESTROY_DEV() {
	SKF_CancelWaitForDevEvent();
	LOG(DEBUG) << "SKF_CancelWaitForDevEvent Ok";

	if (dev != NULL) {
		return SKF_DisConnectDev(dev);
	}
	return 1;
}

ULONG TRI_DESTROY_CONTAINER() {
	if (client_container != NULL) {
		return SKF_CloseContainer(client_container);
	}
	if (server_container != NULL) {
		return SKF_CloseContainer(server_container);
	}
	return 1;
}

ULONG TRI_DESTROY_APPLICATION() {
	if (application != NULL) {
		return SKF_CloseApplication(application);
	}
	return 1;
}

ULONG TRI_READ_CLIENT_ID( char* clientId,  UINT* cliendId_len) {
	int ret = 0;
	ULONG certLen = 0;
	BYTE* certificate = (BYTE*)malloc(sizeof(BYTE) * 1024);
	if (client_container == NULL) {
		LOG(DEBUG) << "1.SKF not init success";
		return -1;
	}

	ret = SKF_ExportCertificate(client_container, 0, certificate, &certLen);
	if (ret != SAR_OK) {
		LOG(DEBUG) << "1.SKF_ExportCertificate Error,rv=" << ret;
		return ret;
	}

	printf("SKF_ExportCertificate length:%d\n", certLen);
	ret = readX509UserCredentialCNFromMem(certificate, certLen, clientId, cliendId_len);
	if (ret != 0) {
		LOG(DEBUG) << "readX509UserCredentialCNFromMem Error,rv=" << ret;
		if (certificate != NULL)
			free(certificate);
		return ret;
	}

	LOG(DEBUG) << "readX509UserCredentialCNFromMem clientdID=" << clientId;
	if (certificate != NULL)
		free(certificate);
	return 0;
}


ULONG TRI_SM4_ECB(unsigned char* secretkey, unsigned char* in, int inSize, unsigned char* out, int& outSize, bool isEncrypt) {
	ULONG ret = 0;
	HANDLE hSessionKey;
	BLOCKCIPHERPARAM bparam;
	ret = SKF_SetSymmKey(dev, secretkey, SGD_SM4_ECB, &hSessionKey);
	if (ret != SAR_OK) {
		printf("SKF_SetSymmKey Error,rv=%08x\n", ret);
		LOG(DEBUG) << "SKF_SetSymmKey Error";
		return ret;
	}
	memset(&bparam, 0x00, sizeof(BLOCKCIPHERPARAM));
	bparam.PaddingType = PKCS5_PADDING;
	bparam.FeedBitLen = 128;
	ret = SKF_LockDev(dev, 6000);//6s
	if (ret != SAR_OK) {
		LOG(DEBUG) << "SKF_LockDev fail";
		return ret;
	}
	if (isEncrypt) {
		ret = SKF_EncryptInit(hSessionKey, bparam);
		if (ret != SAR_OK) {
			printf("SKF_DecryptInit Error,rv=%08x\n", ret);
			return ret;
		}
		ret = SKF_Encrypt(hSessionKey, in, inSize, out, (ULONG*)&outSize);
		if (ret != SAR_OK) {
			printf("SKF_Encrypt Error,rv=%08x\n", ret);
			return ret;
		}
	}
	else {
		ret = SKF_DecryptInit(hSessionKey, bparam);
		if (ret != SAR_OK) {
			printf("SKF_DecryptInit Error,rv=%08x\n", ret);
			return ret;
		}
		ret = SKF_Decrypt(hSessionKey, in, inSize, out, (ULONG*)&outSize);
		if (ret != SAR_OK) {
			printf("SKF_Decrypt Error,rv=%08x\n", ret);
			return ret;
		}
	}
	ret = SKF_UnlockDev(dev);
	if (ret != SAR_OK) {
		std::cout << " SKF_LockDev Error" << std::endl;
		SKF_CloseHandle(hSessionKey);
		return ret;
	}

	SKF_CloseHandle(hSessionKey);
	return ret;

}


static ULONG TRI_SM4_OFB_DEC(unsigned char* key, unsigned char* iv, int ivLen, unsigned char* in, int inSize,
	unsigned char* out, int& outSize) {
	clock_t start, finish;
	double Total_time;

	//渔翁加解密接口最大支持65536字节
	int fragment = 65536;
	ULONG ret = 0;
	HANDLE hsession = NULL;
	//start = clock();
	ret = SKF_SetSymmKey(dev, key, SGD_SM4_OFB, &hsession);
	if (ret != SAR_OK) {
		printf("SKF_SetSymmKey fail ret=%d\n", ret);
		LOG(DEBUG) << "SKF_SetSymmKey fail";
		return ret;
	}
	BLOCKCIPHERPARAM param;
	memset(&param, 0x00, sizeof(BLOCKCIPHERPARAM));
	memcpy(param.IV, iv, ivLen);
	param.IVLen = ivLen;
	param.PaddingType = PKCS5_PADDING;
	param.FeedBitLen = 128;
	
	ret = SKF_LockDev(dev, 6000);//6s
	if (ret != SAR_OK) {
		LOG(DEBUG) << "SKF_LockDev fail";
		return ret;
	}
	ret = SKF_DecryptInit(hsession, param);
	if (ret != SAR_OK) {
		printf("SKF_DecryptInit fail ret=%d\n", ret);
		LOG(DEBUG) << "SKF_DecryptInit fail";
		SKF_CloseHandle(hsession);
		return ret;
	}
	unsigned int paddingLen = 16 - inSize % 16;
	unsigned int newlen = inSize + paddingLen;
	unsigned int count = newlen / fragment;

	ULONG uiDecryptDataInOffset = 0;
	ULONG uiDecryptDataOutOffset = 0;
	ULONG uiTempDataLen = 16;
	for (unsigned int index = 0; index < count; index++) {
		ret = SKF_DecryptUpdate(hsession, &in[uiDecryptDataInOffset], fragment, &out[uiDecryptDataOutOffset], &uiTempDataLen);
		if (ret != SAR_OK)
		{
			printf("SKF_DecryptUpdate Error,rv=%08x\n", ret);
			SKF_CloseHandle(hsession);
			return ret;
		}
		uiDecryptDataInOffset += fragment;
		uiDecryptDataOutOffset += uiTempDataLen;
	}

	//剩余未解密字节
	ULONG lastData = newlen - uiDecryptDataInOffset;
	SKF_DecryptUpdate(hsession, in + uiDecryptDataInOffset, lastData, out + uiDecryptDataOutOffset, &uiTempDataLen);
	uiDecryptDataOutOffset += uiTempDataLen;

	uiTempDataLen = 0;
	ret = SKF_DecryptFinal(hsession, out + uiDecryptDataOutOffset, &uiTempDataLen);
	if (ret != SAR_OK)
	{
		printf("SKF_DecryptFinal Error,rv=%08x\n", ret);		
		SKF_UnlockDev(dev);
		SKF_CloseHandle(hsession);
		return ret;
	}
	ret = SKF_UnlockDev(dev);
	if (ret != SAR_OK) {
		std::cout << " SKF_LockDev Error" << std::endl;
		SKF_CloseHandle(hsession);
		return ret;
	}

	uiDecryptDataOutOffset += uiTempDataLen;

	//finish = clock();
	//Total_time = (double)(finish - start) / CLOCKS_PER_SEC;
	//printf("Muti Blocks Decrypt Done, Data Decrypted: %d Bytes secons:%f\n", uiDecryptDataOutOffset, Total_time);
	outSize = inSize;//不用关心最后SKF_DecryptFinal长度，直接返回密文长度即为明文长度

	if (hsession != NULL) {
		SKF_CloseHandle(hsession);
	}
	return ret;
}
static ULONG TRI_SM4_OFB_ENC(unsigned char* key, unsigned char* iv, int ivLen, unsigned char* in, int inSize,
	unsigned char* out, int& outSize) {
	clock_t start, finish;
	double Total_time;

	//渔翁加解密接口最大支持65536字节
	int fragment = 65536;
	ULONG ret = 0;
	HANDLE hsession = NULL;
	//start = clock();
	ret = SKF_SetSymmKey(dev, key, SGD_SM4_OFB, &hsession);
	if (ret != SAR_OK) {
		printf("SKF_SetSymmKey fail ret=%d\n", ret);
		LOG(DEBUG) << "SKF_SetSymmKey fail";
		return ret;
	}
	BLOCKCIPHERPARAM param;
	memset(&param, 0x00, sizeof(BLOCKCIPHERPARAM));
	memcpy(param.IV, iv, ivLen);
	param.IVLen = ivLen;
	param.PaddingType = PKCS5_PADDING;
	param.FeedBitLen = 128;

	ret = SKF_EncryptInit(hsession, param);
	if (ret != SAR_OK) {
		printf("SKF_EncryptInit fail ret=%d\n", ret);
		SKF_CloseHandle(hsession);
		return ret;
	}
	unsigned int paddingLen = 16 - inSize % 16;
	unsigned int newlen = inSize + paddingLen;
	unsigned int count = newlen / fragment;

	ULONG uiDecryptDataInOffset = 0;
	ULONG uiDecryptDataOutOffset = 0;
	ULONG uiTempDataLen = 16;
	for (unsigned int index = 0; index < count; index++) {
		ret = SKF_EncryptUpdate(hsession, &in[uiDecryptDataInOffset], fragment, &out[uiDecryptDataOutOffset], &uiTempDataLen);
		if (ret != SAR_OK)
		{
			printf("SKF_EncryptUpdate Error,rv=%08x\n", ret);
			SKF_CloseHandle(hsession);
			return ret;
		}
		uiDecryptDataInOffset += fragment;
		uiDecryptDataOutOffset += uiTempDataLen;
	}

	//剩余未解密字节
	ULONG lastData = newlen - uiDecryptDataInOffset;
	SKF_EncryptUpdate(hsession, in + uiDecryptDataInOffset, lastData, out + uiDecryptDataOutOffset, &uiTempDataLen);
	uiDecryptDataOutOffset += uiTempDataLen;

	uiTempDataLen = 0;
	ret = SKF_EncryptFinal(hsession, out + uiDecryptDataOutOffset, &uiTempDataLen);
	if (ret != SAR_OK)
	{
		printf("SKF_EncryptFinal Error,rv=%08x\n", ret);
		SKF_CloseHandle(hsession);
		return ret;
	}
	uiDecryptDataOutOffset += uiTempDataLen;

	//finish = clock();
	//Total_time = (double)(finish - start) / CLOCKS_PER_SEC;
	//printf("Muti Blocks Decrypt Done, Data Decrypted: %d Bytes secons:%f\n", uiDecryptDataOutOffset, Total_time);
	outSize = inSize;//不用关心最后SKF_DecryptFinal长度，直接返回密文长度即为明文长度

	if (hsession != NULL) {
		SKF_CloseHandle(hsession);
	}
	return ret;
}

ULONG TRI_SM4_OFB(unsigned char* key, int keyLen,  unsigned char* iv, int ivLen, unsigned char* in, int inSize,
	unsigned char* out, int& outSize, bool isEncrypt) {
	if (isEncrypt) {
		return TRI_SM4_OFB_DEC(key, iv, ivLen, in, inSize, out, outSize);
	} else {
		return TRI_SM4_OFB_DEC(key, iv, ivLen, in, inSize, out, outSize);
	}
}




ULONG TRI_WRITE_DATA(const char* fileName, unsigned char* data, ULONG len) {
	printf("writedata: %s \n", data);
	unsigned char files[1024];
	ULONG  filesLen = 0;
	int ret = SKF_EnumFiles(application, (LPSTR)files, &filesLen);
	if (filesLen > 0) {
		//判断file是否已经存在
		std::vector<std::string> tokens = splitSkfFiles((const char*)files, filesLen);
		auto it = std::find(tokens.begin(), tokens.end(), fileName);
		if (it == tokens.end()) {
			//不存在文件
			int ret = SKF_CreateFile(application, (LPSTR)fileName, EXPORT_FILE_SIZE, SECURE_USER_ACCOUNT, SECURE_USER_ACCOUNT);
			if (ret != 0) {
				printf("SKF_CreateFile Error,rv=%08x\n", ret);
				return ret;
			}
		}
	}
	else {
		//不存在文件
		int ret = SKF_CreateFile(application, (LPSTR)fileName, EXPORT_FILE_SIZE, SECURE_USER_ACCOUNT, SECURE_USER_ACCOUNT);
		if (ret != 0) {
			printf("SKF_CreateFile Error,rv=%08x\n", ret);
			return ret;
		}
	}
	ret = SKF_WriteFile(application, (LPSTR)fileName, 0, data, EXPORT_FILE_SIZE);
	if (ret != 0) {
		printf("SKF_WriteFile Error,rv=%08x\n", ret);
		return ret;
	}
	return 0;
}
ULONG TRI_READ_DATA(const char* fileName, unsigned char* data, ULONG* len) {

	ULONG length;
	for (int i = 0; i < EXPORT_FILE_SIZE/128; i++) {
		ULONG offset = i * 128;
		int ret = SKF_ReadFile(application, (LPSTR)fileName, offset, 128, (BYTE*)(data + offset), &length);
		if (ret != 0) {
			printf("SKF_ReadFile Error,rv=%08x\n", ret);
			return ret;
		}
	}
	return 0;
}


//从容器读出证书，再导出公钥
ULONG TRI_GET_PUBLICKEYBLOB(int container, BOOL signFlag, ECCPUBLICKEYBLOB* pbBlob) {

	HCONTAINER hContainer;
	if (container == 0) {
		hContainer = server_container;
	}
	else {
		hContainer = client_container;
		// 渔翁接口SKF_ExportPublicKey 的 client_container 获取准确
		ULONG signPubKeyBlobLen;
		int ret = SKF_ExportPublicKey(hContainer, signFlag, (unsigned char*)pbBlob, &signPubKeyBlobLen);
		if (ret != SAR_OK)
		{
			printf("SKF_ExportPublicKey Error,rv=%08x\n", ret);
			return ret;
		}
		return ret;
	}


	// 渔翁接口SKF_ExportPublicKey 的 server_container 可能获取不准确, 从证书提取SKF_ExportCertificate
	//ULONG signPubKeyBlobLen;
	//int ret = SKF_ExportPublicKey(hContainer, signFlag, (unsigned char*)&pbBlob, &signPubKeyBlobLen);
	//if (ret != SAR_OK)
	//{
	//	printf("SKF_ExportPublicKey Error,rv=%08x\n", ret);
	//	return ret;
	//}
	const unsigned char* p;
	int ret = 1;
	BYTE* certificate = NULL;
	ULONG certLen = SKF_MAX_CERTIFICATE_SIZE;
	if (!(certificate = (BYTE*)OPENSSL_zalloc(certLen))) {
		return ret;
	}
	ret = SKF_ExportCertificate(hContainer, signFlag, certificate, &certLen);
	if (ret != SAR_OK) {
        OPENSSL_free(certificate);
		return ret;
	}
	p = certificate;
	BIO* certBio = NULL;
	X509* usrCert = d2i_X509(NULL, &p, certLen);
	if (!usrCert) {
		std::cout << "unable to parse certificate in memory" << std::endl;
		certBio = BIO_new(BIO_s_mem());
		BIO_write(certBio, certificate, certLen);
		usrCert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
		if (usrCert == NULL) {
			std::cout << "usrCert pause error 2" << std::endl;
			ret = EXIT_FAILURE;
            OPENSSL_free(certificate);
            if (certBio != NULL) {
                BIO_free(certBio);
            }
            if (usrCert != NULL) {
                X509_free(usrCert);
            }
            return ret;
		}

	}
	EVP_PKEY* pkey = X509_get_pubkey(usrCert);
	//skf 无法导入公钥 先用gmssl转
	EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	EC_KEY_get_ECCPUBLICKEYBLOB(ec_key, pbBlob);

	ret = SAR_OK;

	OPENSSL_free(certificate);
	if (certBio != NULL) {
		BIO_free(certBio);
	}
	if (usrCert != NULL) {
		X509_free(usrCert);
	}
	return ret;
}


/*
获取公钥信息，该信息带04，

signFlag为选择加密还是签名公钥 1位签名，0为加密
out为公钥的返回结果
outlen为公钥的长度
*/
ULONG TRI_GET_PUBKEY(BOOL signFlag, char** out, int* outlen) {

	int	nRet = 0;
	char cert[2048] = { 0 };
	ULONG uiListLen = 2048;
	nRet = SKF_ExportPublicKey(client_container, signFlag, NULL, &uiListLen);
	unsigned char pubkey[132] = { 0 };
	if (nRet != SAR_OK) {
		std::cout << "SKF_ExportPublicKey ENC Error,rv=" << nRet << std::endl;
	}
	else {
		std::cout << "SKF_ExportPublicKey ENC OK, len=" << uiListLen << std::endl;
		SKF_ExportPublicKey(client_container, signFlag, (unsigned char*)pubkey, &uiListLen);
		TRI_ENCODE_PUBKEY(pubkey, out, outlen);
	}
	return nRet;
}

ULONG TRI_HEX_TO_PUBLICKEYBLOB(const char* hexPublicKey, ECCPUBLICKEYBLOB* pBlob) {
	// 将16进制字符串解码为字节数组
	//公钥字符串32+32字节, 
	if (strlen(hexPublicKey) != 128) {
		printf("hexPublicKey len != 128\n");
		return 1;
	}
	pBlob->BitLen = 256;
	int publicKeyBytesLen = strlen(hexPublicKey) / 4;
	for (int i = 0; i < publicKeyBytesLen; i++) {
		sscanf(hexPublicKey + 2 * i, "%2hhx", pBlob->XCoordinate+32+i);
		sscanf(hexPublicKey + 64 +  2 * i, "%2hhx", pBlob->YCoordinate + 32 + i);
	}

	return 0;
}














ULONG TRI_SM3(unsigned char* plainText, ULONG plain_len, unsigned char* hash_out) {
	ULONG ret = 0;
	HANDLE	hHash;
	ULONG hash_len = 0;
	ret = SKF_DigestInit(dev, SGD_SM3, NULL, NULL, 0, &hHash);
	if (ret != SAR_OK) {
		std::cout << "SKF_DigestInit Error,rv=" << ret;
		return ret;
	}

	int fregment = 40960;  //超过一定长度 hash值会不准确
	unsigned int count = plain_len / fregment;
	unsigned int lastSize = plain_len % fregment;

	for (int index = 0; index < count; index++) {
		ret = SKF_DigestUpdate(hHash, plainText + index * fregment, fregment);
		if (ret != SAR_OK) {
			printf("SKF_DigestUpdate Error,rv=%08x\n", ret);
			return ret;
		}

	}
	if (lastSize != 0) {
		ret = SKF_DigestUpdate(hHash, plainText + count * fregment, lastSize);
		if (ret != SAR_OK) {
			printf("SKF_DigestUpdate Error,rv=%08x\n", ret);
			return ret;
		}
	}
	ret = SKF_DigestFinal(hHash, hash_out, &hash_len);
	if (ret != SAR_OK) {
		printf("SKF_DigestFinal Error,rv=%08x\n", ret);
		return ret;
	}

	SKF_CloseHandle(hHash);
	return ret;
}

ULONG TRI_TEST() {


	unsigned char digist[32] = { 0 };
	unsigned char digist2[32] = { 0 };
	ULONG digist_len;

	unsigned char* plainData = (unsigned char*)malloc(100000);
	memset(plainData, 0x01, 100000);
	sm3(plainData, 100000, digist);

	TRI_SM3(plainData, 100000, digist2);

	return 0;

}


ULONG SSL_SM4_ECB(unsigned char* secretkey, unsigned char* in, int inSize, unsigned char* out, int& outSize, bool isEncrypt) {
	sms4_key_t key;
	if (isEncrypt) {
		sms4_set_encrypt_key(&key, secretkey);
	}
	else {
		sms4_set_decrypt_key(&key, secretkey);
	}

	sms4_ecb_encrypt(in, out, &key, isEncrypt);
	return 0;
}

ULONG SSL_SM4_OFB(unsigned char* key, int keyLen, unsigned char* iv, int ivLen, unsigned char* in, int inSize,
	unsigned char* out, int& outSize, bool isEncrypt) {
	int tmpLen;
	// int inlen, outlen;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	/* Now we can set key and IV */
	EVP_CipherInit_ex(ctx, EVP_sm4_ofb(), NULL, key, iv, isEncrypt);

	if (!EVP_CipherUpdate(ctx, out, &outSize, in, inSize)) {
		/* Error */
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}

	if (!EVP_CipherFinal_ex(ctx, out + outSize, &tmpLen)) {

		/* Error */
		EVP_CIPHER_CTX_free(ctx);
		return 1;
	}

	outSize += tmpLen;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

ULONG SSL_SM3(unsigned char* plainText, ULONG plain_len, unsigned char* hash_out) {
	sm3(plainText, plain_len, hash_out);
	return 0;
}



static bool sm2utl_verify(const EVP_MD* md, BIO* in, unsigned char* sign,
	int signSize, const char* id, ENGINE* e,
	EC_KEY* ec_key) {
	bool retval = false;
	EVP_MD_CTX* md_ctx = NULL;
	unsigned char buf[1024];
	size_t siz = sizeof(buf);
	unsigned int ulen = sizeof(buf);
	int len = 0;

	if (!(md_ctx = EVP_MD_CTX_new()) || !EVP_DigestInit_ex(md_ctx, md, e) ||
		!SM2_compute_id_digest(md, id, strlen(id), buf, &siz, ec_key) ||
		!EVP_DigestUpdate(md_ctx, buf, siz)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	while ((len = BIO_read(in, buf, sizeof(buf))) > 0) {
		if (!EVP_DigestUpdate(md_ctx, buf, len)) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	siz = sizeof(buf);
	if (!EVP_DigestFinal_ex(md_ctx, buf, &ulen)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	/* SM2_verify() can check no suffix on signature */
	if (1 == SM2_verify(NID_undef, buf, ulen, sign, signSize, ec_key)) {
		printf("Signature Verification Successful\n");
		retval = true;
	}
	else {
		printf("Signature Verification Failure\n");
	}

end:
	EVP_MD_CTX_free(md_ctx);
	return retval;
}

static bool sm2utl_verify_rssignData(const EVP_MD* md, BIO* in, unsigned char* sign,
                                     int signSize, const char* id, ENGINE* e,
                                     EC_KEY* ec_key) {
    bool retval = false;
    EVP_MD_CTX* md_ctx = NULL;
    unsigned char buf[1024];
    size_t siz = sizeof(buf);
    unsigned int ulen = sizeof(buf);
    int len = 0;
    if (!(md_ctx = EVP_MD_CTX_new()) || !EVP_DigestInit_ex(md_ctx, md, e) ||
        !SM2_compute_id_digest(md, id, strlen(id), buf, &siz, ec_key) ||
        !EVP_DigestUpdate(md_ctx, buf, siz)) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    while ((len = BIO_read(in, buf, sizeof(buf))) > 0) {
        if (!EVP_DigestUpdate(md_ctx, buf, len)) {
            EVP_MD_CTX_free(md_ctx);
            return false;
        }
    }
    siz = sizeof(buf);
    if (!EVP_DigestFinal_ex(md_ctx, buf, &ulen)) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    ECDSA_SIG* ecdsa_sign = ECDSA_SIG_new();
    unsigned char* r = sign;
    unsigned char* s = sign + 32;
    ecdsa_sign->r = BN_new();
    ecdsa_sign->s = BN_new();
    if (NULL == BN_bin2bn(r, sizeof(unsigned char) * 32, ecdsa_sign->r)) {
        printf("error BN_bin2bn r \n");
        return 1;
    }
    if (NULL == BN_bin2bn(s, sizeof(unsigned char) * 32, ecdsa_sign->s)) {
        printf("error BN_bin2bn s \n");
        return 1;
    }
    //转成asn1
    int sig_size = i2d_ECDSA_SIG(ecdsa_sign, NULL);
    unsigned char* sig_bytes;
    if (sig_size > ulen) {
        sig_bytes = (unsigned char*)malloc(sig_size);
    }
    else {
        sig_bytes = (unsigned char*)malloc(ulen);
    }
    memcpy(sig_bytes, buf, ulen);
    unsigned char* p = sig_bytes;
    signSize = i2d_ECDSA_SIG(ecdsa_sign, &p);
    memcpy(sign, sig_bytes, signSize);

    /* SM2_verify() can check no suffix on signature */
    if (1 == SM2_verify(NID_undef, buf, ulen, sign, signSize, ec_key)) {
        printf("Signature Verification Successful\n");
        retval = true;
    }
    else {
        printf("Signature Verification Failure\n");
    }
    EVP_MD_CTX_free(md_ctx);
    if (sig_bytes != NULL) {
        free(sig_bytes);
    }
    //回收临时数据
    if (ecdsa_sign != NULL) {
        ECDSA_SIG_free(ecdsa_sign);
    }

    return retval;
}

ULONG SSL_VERIFY_SIGNATURE_RS( ECCPUBLICKEYBLOB signPubKeyBlob,  unsigned char* plainText,  ULONG plain_len,
                            unsigned char* signature_in,  ULONG signature_in_len, unsigned char* id) {
    ULONG ret = 1;
    const EVP_MD* md = EVP_sm3();
    BIO* in = NULL;
    in = BIO_new(BIO_s_mem());
    BIO_write(in, (const unsigned char*)plainText, plain_len);

    EC_KEY* ec_key = EC_KEY_new_from_ECCPUBLICKEYBLOB(&signPubKeyBlob);

    if (true == sm2utl_verify_rssignData(md, in, signature_in, signature_in_len, (const char*)id, 0, ec_key)) {
        ret = 0;
        LOG(DEBUG) << "verify success";
    }
    else {
        LOG(DEBUG) << "verify fail";
        ret = 1;
    }

    if (ec_key != NULL) {
        EC_KEY_free(ec_key);
    }
    if (in != NULL) {
        BIO_free(in);
    }
    return ret;
}

ULONG SSL_VERIFY_SIGNATURE( ECCPUBLICKEYBLOB signPubKeyBlob,  unsigned char* plainText,  ULONG plain_len,
	 unsigned char* signature_in,  ULONG signature_in_len, unsigned char* id) {

	int ret = 1;
	const EVP_MD* md = EVP_sm3();
	BIO* in = NULL;
	in = BIO_new(BIO_s_mem());
	BIO_write(in, (const unsigned char*)plainText, plain_len);

	EC_KEY* ec_key = EC_KEY_new_from_ECCPUBLICKEYBLOB(&signPubKeyBlob);
	if (true == sm2utl_verify(md, in, signature_in, signature_in_len, (const char*)id, 0, ec_key)) {
		printf("verify success\n");
		ret = 0;
	}
	else {
		printf("verify fail\n");
	}

	if (ec_key != NULL) {
		EC_KEY_free(ec_key);
	}
	if (in != NULL) {
		BIO_free(in);
	}
	return ret;

}


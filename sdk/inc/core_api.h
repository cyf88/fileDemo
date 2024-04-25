//
// Created by cyf on 2024/2/28.
//

#ifndef FILEDEMO_CORE_API_H
#define FILEDEMO_CORE_API_H

#ifndef VOID
#define VOID void
typedef unsigned int ULONG;
#endif

#define FRI_ERROR_NOT_SET_GB_CODE 20000
#define FRI_ERROR_NOT_SET_SERVER_IP 20001
#define FRI_ERROR_NOT_SET_SERVER_PORT 20002
#define FRI_ERROR_NOT_SET_CLIENT_ID 20003
#define FRI_ERROR_NOT_SET_CLIENT_PORT 20004
#define FRI_SDK_HAS_INITED 20005
#define FRI_SDK_SIP_DESTORY_FAIL 20006
#define FRI_SDK_LOGIN_HAS_NOT_INITED 20007
#define FRI_SDK_HAS_NOT_INITED 20008

#define FRI_NO_RESPONSE_FROM_SERVER 30004
#define FRI_NO_R1_FROM_SERVER 30005
#define FRI_UNKNOWN_ERROR_FROM_SERVER 30006
#define FRI_LOGIN_ERROR_FROM_SERVER 30007
#define FRI_NO_DECODEHANDLE 30008
#define FRI_SIGN_R_ERROR 30009
#define FRI_SIGN_S_ERROR 30010
#define FRI_VERIFY_SIGN_FAIL 30011
#define FRI_SES_ERROR 30012
#define FRI_MEMERY_MOLLOC_ERROR 30013
#define FRI_INPUT_DATA_ERROR 30014
#define FRI_DECODE_SAME_TIME 30015
#define FRI_GENERATE_EVEK_ERROR 30016


#define CAMERA_ID_SIZE		21
#define CAMERA_IDC_SIZE		19
#define CERT_SIZE 100
#define CERT_IDC_SIZE		(CAMERA_IDC_SIZE*2+1)
#define CERT_INFO_SIZE		2048


typedef struct stru_RegisterRequest_InParam
{
    char ServerID[CAMERA_ID_SIZE];	//平台ID
    unsigned char random1[32];     //平台生成的随机数
    char algorithm[128];   		   //安全算法
} REG_REQ_INPARAM, * PREG_REQ_INPARAM;

typedef struct stru_RegisterRequest_OutParam
{
    unsigned char random2[32];  //设备生成随机数R2
    char Sbase[128];        	//签名数据
    int Sbase_len;          	//签名数据长度
    char algorithm[128];     	//安全算法
} REG_REQ_OUTPARAM, * PREG_REQ_OUTPARAM;

typedef struct stru_RegisterConfirm_InParam
{
    unsigned char random1[32];      //平台通过sip信令传递给设备的随机数
    unsigned char random2[32];      //设备生成随机数
    char DeviceID[CAMERA_ID_SIZE];     //设备ID
    char cryptkey[256];        	//密钥
    char keyversion[128];  			//密钥版本号
    char signData[129];    			//验签数据
    int SignData_len;      			//验签数据长度
} REG_CON_INPARAM, * PREG_CON_INPARAM;

typedef struct stru_Sipmsg_Check_InParam
{
    char Date[40];          	// SIP信令Date字段
    char METHOD[32];     	// SIP信令METHOD
    char From[128];        	// SIP信令From字段
    char To[128];          	// SIP信令To字段
    char CallID[128];       	// SIP信令CallID字段
    char MessageBody[8192]; 	// SIP信令的消息体
    char algorithm[40];      	//杂凑算法SM3
    char nonce[128];        	//校验数据
} SIPMSG_CHECK_INPARAM;

typedef struct stru_Sipmsg_Check_OutParam
{
    char Nonce[128];  //校验数据
    int Nonce_length;  //校验数据长度
    char algorithm[40]; //杂凑算法SM3
} SIPMSG_CHECK_OUTPARAM;

/*
* 2.6媒体流整帧数据结构
*/

typedef struct stru_ImgFrame_Unit
{
    unsigned int type;			// 'I' = I帧及其他关键帧编码数据;
    // 'P' = 非I帧编码数据（包括P帧或B帧的编码数据）
    unsigned int fsn;				// 帧序号
    unsigned int imgsz;			// 以字节为单位的编码后媒体数据长度
    unsigned char img_buf[1];	// 编码后媒体数据缓冲区，此类首地址表示法
    // 可以支持可变长的媒体数据缓存，便于后续
    // 数据的使用
}IMG_FRAME_UNIT;

/*2.7安全参数数据结构*/

typedef struct stru_Sec_Param_Info
{
    char CameraID[CAMERA_ID_SIZE];      	//摄像机ID
    char ServerID[CAMERA_ID_SIZE];  		//服务器ID
    int VEKChangeTime; 			    		//VEK变化周期（秒）
} SEC_PARAM_INFO;

/*
* 2.8密码模块信息数据结构
*/

typedef struct stru_Crypt_Mod_Info
{
    char szVender[128]; 		//密码模块厂商信息
    char szCode[64];  	 	//密码模块ID
} CRYPT_MOD_INFO;

/*
* 2.9IPC设备证书数据结构
*/

typedef struct Struct_IpcCert_Info
{
    char DeviceID[CAMERA_ID_SIZE];		//IPC设备标号
    char CertIDC[CERT_IDC_SIZE];			//证书IDC
    char CertInfo[CERT_INFO_SIZE];		//证书内容
} IPC_CERT_INFO, * PIPC_CERT_INFO;

/*
* 2.10IPC视频流验签结果数据结构
*/

typedef struct Struct_SignVerify_result
{
    bool	m_ulVerifyFlag;		//验签使能标记，缺省配置为未使能
    ULONG	m_ulSuccSum[2];	//验签成功次数
    ULONG	m_ulFailSum[2];		//验签失败次数
    ULONG	m_ulBypassSum[2];	//验签缺位次数
    ULONG	m_ulErrCode[2];		//验签失败错误码
    ULONG	m_ulFrameNum;		//签名数据对应的帧序号
} SIGN_VERIFY_RESULT, * PSIGN_VERIFY_RESULT;

/*
* 2.11证书数据结构
*/

typedef struct stru_Cert_Param
{
    char signCert[CERT_SIZE]; 		//签名证书
    ULONG signCertLen;			//签名证书长度
    char encCert[CERT_SIZE];      	//加密证书
    ULONG encCertLen;				//加密证书长度
    char ID[CAMERA_ID_SIZE];	//证书对应ID
} CERT_PARAM, * PCERT_PARAM;


/*
* 2.12摄像机VKEK数据结构
*/
typedef struct Struct_IpcVkek_Info
{
    char DeviceID[CAMERA_ID_SIZE];		//IPC设备标号
    char cryptkey[256];				//Vkek密文
    char cryptkeyversion[128];			//Vkek版本
} IPC_VKEK_INFO, * PIPC_VKEK_INFO;


/*
* 2.13VKEK查询结构
*/
typedef struct stru_vkek_query_param
{
    char policeno[40];		//用户编码
    char idcardno[32];		//身份证号
    char decoderid[32];		//解码器ID
    char deviceid[32];     //媒体流发送者设备编码
    char starttime[32];    //开始时间，实时点播获取密文取值为“now”
    char endtime[32];     //结束时间，实时点播获取密文取值为“now”
} VKEK_Query_Param;


/*
*  2.14VKEK查询返回结构
*/
typedef struct stru_vkek_item
{
    char VKEKTime[32]; 	// VKEK产生时间
    char VKEKVersion[32]; 	// VKEK Version
    char VKEKValue[256]; 	//使用请求方SM2算法加密后的VKEK
}VKEK_ITEM;

typedef struct stru_vkek_query_result
{
    char 			deviceid[32];     	//媒体流发送者设备编码
    int 				numsVKEK;        //查询到的VKEK的数量
    VKEK_ITEM   pVKEKITEM[0];  //变长结构体，PVKEKITEM数据长度为
    // numsVKEK定义
} VKEK_Query_Result;

typedef struct stru_ChanParamInfo
{
    bool		bSignVerify;
    char		chCameraID[CAMERA_ID_SIZE];	//前端摄像机ID
    char    	chStartTime[32];  //视频流开始时间
    char    	chEndtime[32];   //视频流结束时间
}CHAN_PARAM_INFO;


//3.2回调函数注册码
typedef enum
{
    CODE_CBFUN_DEVEVENTMONITOR = 0x00,  //UKEY热插拔事件
    CODE_CBFUN_SIGNVERIFYNOTIFY = 0x01, 	//验签结果实时通知
    CODE_CBFUN_MAX = 0x02
} ENUM_CODE_CBFUN;

/*
 UKEY热插拔检测
*/
typedef int (* FUNC_SUT_DEVEVENTMONITOR)(char* szDevName, unsigned int uiEvent);

/*
验签实时结果通知
*/
typedef int (* FUNC_SUT_SIGNVERIFYNOTIFY)(unsigned int uiChan, ULONG ulRetCode, char* streamId, char* time);


ULONG FRI_MUT_RequestChan(unsigned int* puiChan);

ULONG FRI_MUT_VideoDataSecDecodeExt(unsigned int uiChan, IMG_FRAME_UNIT* pstImgData, IMG_FRAME_UNIT** ppstOutData);

ULONG FRI_MUT_VkekImport(unsigned int uiChan, IPC_VKEK_INFO* pstIpcVkekInfo, ULONG ulVkekCnt);

ULONG FRI_MUT_CertImport(unsigned int uiChan, IPC_CERT_INFO* pstIpcCertInfo);

ULONG FRI_MUT_CertImport2(unsigned int uiChan, const char* pcertPath);

VOID FRI_MUT_SafeFree(IMG_FRAME_UNIT** ppstOutData);

ULONG FRI_MUT_SetCallbackFunction(ENUM_CODE_CBFUN ecbFunCode, void* pcbFunName);
#endif //FILEDEMO_CORE_API_H

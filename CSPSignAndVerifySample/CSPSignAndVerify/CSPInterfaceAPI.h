#include "stdafx.h"
#include <Windows.h>
#include <WinCrypt.h>


/************************************************************************/
/* Author	:LinJunHAN													*/
/* Content	:Use Win CSP API to Sign And Verify							*/
/* Time		:2018-08-29													*/
/************************************************************************/

#define  DEFAULT_CSP_NAME	"****** Cryptographic Service Provider *****"		//CSP名称
#define  DEFAULT_CSP_CONT	"178CCC7A-7791-4902-B40D-4A1E74E05BC8"				//包含证书的容器

/*****************************************************
*函数名：SignHash
*功  能：对一段数据进行哈稀签名,并导出公钥
*入  参：IN BYTE* pData,        //欲进行哈稀签名的数据
		 IN DWORD dwDataLen,	//数据长度
*出  参：OUT BYTE** pSignature, //哈稀签名数据的地址，使用完后由调用者释放
		 OUT DWORD* dwSigLen,	//签名实际长度
		 OUT BYTE** pPublicKey, //公钥数据的地址，使用完后由调用者释放
		 OUT DWORD* dwPubKeyLen);//公钥实际长度
*返回值：BOOL，TRU为签名成功，FALSE为签名失败
******************************************************/
BOOL CSP_SignHash(IN BYTE* pData, IN DWORD dwDataLen, OUT BYTE** pSignature, OUT DWORD* dwSigLen, OUT BYTE** pPublicKey, OUT DWORD* dwPubKeyLen);


/*****************************************************
*函数名：VerifySignature
*功  能：对一段数据进行签名验证
*入  参：IN BYTE* pData,        //欲进行哈稀验证的数据
		 IN DWORD dwDataLen,	//数据长度
		 IN BYTE* pSignature,	//签名
		 IN DWORD dwSigLen,		//签名长度
		 IN BYTE* pPublicKey,	//公钥
		 IN DWORD dwPublicKeyLen);//公钥长度
*出  参：无
*返回值：BOOL，TRU为验证签名成功，FALSE为验证签名失败
******************************************************/
BOOL CSP_VerifySignature(IN BYTE* pData, IN DWORD dwDataLen, IN BYTE* pSignature, IN DWORD dwSigLen, IN BYTE* pPublicKey, IN DWORD dwPublicKeyLen);


DWORD HexToStr(IN CONST BYTE *pbHex, IN DWORD dwHexLen, OUT BYTE *pbStr);
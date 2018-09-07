// CSPSignAndVerify.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "CSPInterfaceAPI.h"

int _tmain(int argc, _TCHAR* argv[])
{

	CHAR* pData = (CHAR*)"kasdkagdkj981392721khkk%dasda22";
	BYTE* pSignature = NULL;
	DWORD dwSigLen = 0;
	BYTE* pPublicKey = NULL;
	DWORD dwPublicKeyLen = 0;
	CSP_SignHash((BYTE*)pData, strlen(pData),  &pSignature, &dwSigLen, &pPublicKey, &dwPublicKeyLen);

	char SignResult[1024] = {0};
	HexToStr(pSignature, dwSigLen, (BYTE*)SignResult);

	char PubKey[1024] = {0};
	HexToStr(pPublicKey, dwPublicKeyLen, (BYTE*)PubKey);

	Log("Signature:%s\n\n PubKey:%s\n\n", SignResult, PubKey);

	CSP_VerifySignature((BYTE*)pData, strlen(pData), pSignature, dwSigLen, pPublicKey,dwPublicKeyLen);

	if(pPublicKey)
		free(pPublicKey);
	if(pSignature)
		free(pSignature);

	system("pause");
	return 0;
}



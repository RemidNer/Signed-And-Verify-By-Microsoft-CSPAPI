#include "stdafx.h"
#include "CSPInterfaceAPI.h"

BOOL CSP_SignHash(IN BYTE* pData, IN DWORD dwDataLen, OUT BYTE** pSignature, OUT DWORD* dwSigLen, OUT BYTE** pPublicKey, OUT DWORD* dwPubKeyLen)
{
	//Get a CSP Handle
	HCRYPTPROV hCryptProv;
	BOOL bRet = CryptAcquireContext(
		&hCryptProv,
		DEFAULT_CSP_CONT,				//密钥容器名，NULL表示使用默认容器
		DEFAULT_CSP_NAME,				//CSP_NAME
		PROV_RSA_FULL,
		0
		);
	if(!bRet)
	{
		bRet = CryptAcquireContext(
			&hCryptProv,
			DEFAULT_CSP_CONT,			//密钥容器名，NULL表示使用默认容器
			DEFAULT_CSP_NAME,			//CSP_NAME
			PROV_RSA_FULL,
			CRYPT_NEWKEYSET				//创建密钥容器
			);
		if(!bRet)
		{
			Log("CryptAcquireContext fail!");
			return FALSE;
		}
	}

	//Get Sign Public Key
	HCRYPTKEY hKey;
	bRet = CryptGetUserKey(hCryptProv,AT_SIGNATURE,&hKey);
	if(!bRet)
	{
		//获取失败，现在创建新的RSA密钥对。\n");   
		bRet = CryptGenKey(hCryptProv, 2, CRYPT_EXPORTABLE | 0X04000000, &hKey);
		if(!bRet)
		{
			Log("CryptGenKey fail!\n");
			return FALSE;
		}
	}

	//Export Public Key
	if(CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL, dwPubKeyLen))  
		Log("Get the length of the public key.\n");  
	else  
		Log("CryptExportKey erro.\n"); 

	if(*pPublicKey = (BYTE*)malloc(*dwPubKeyLen))  
		Log("Get the memory.\n");  
	else  
		Log("Malloc erro.\n"); 

	if(CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, *pPublicKey,dwPubKeyLen))  
		Log("Export the public key.\n");  
	else  
		Log("CryptExportKeya error.\n"); 

	//Hash Data
	HCRYPTHASH hHash;
	if(CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash))  
		Log("CreateHash succeed.\n");  
	else  
		Log("CreatHash error.\n");  

	if(CryptHashData(hHash, pData, dwDataLen, 0))  
		Log("HashData succeed.\n ");  
	else  
		Log("HashData error.\n");  
	//Get SignData Length
	if(CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, dwSigLen))  
		Log("Get the length of signature.\n");  
	else  
		Log("CryptSignHash error.\n");  
	if(*pSignature = (BYTE*) malloc(*dwSigLen))  
		Log("Get the memory.\n");  
	else  
		Log("memory error.\n"); 
	//Sign Data
	if(CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, *pSignature, dwSigLen))  
		Log("Signature Succeed.\n");  
	else 
	{
		Log("Signature error.\n"); 
		return FALSE;
	}

	if(hKey)
		CryptDestroyKey(hKey);
	if(hHash)
		CryptDestroyHash(hHash);
	if(hCryptProv)
		CryptReleaseContext(hCryptProv, 0);

	return TRUE;
}


BOOL CSP_VerifySignature(IN BYTE* pData, IN DWORD dwDataLen, IN BYTE* pSignature, IN DWORD dwSigLen, IN BYTE* pPublicKey, IN DWORD dwPublicKeyLen)
{
	//Get a CSP Handle
	HCRYPTPROV hCryptProv;
	BOOL bRet = CryptAcquireContext(
		&hCryptProv,
		DEFAULT_CSP_CONT,				//密钥容器名，NULL表示使用默认容器
		DEFAULT_CSP_NAME,				//CSP_NAME
		PROV_RSA_FULL,
		0
		);
	if(!bRet)
	{
		bRet = CryptAcquireContext(
			&hCryptProv,
			DEFAULT_CSP_CONT,			//密钥容器名，NULL表示使用默认容器
			DEFAULT_CSP_NAME,			//CSP_NAME
			PROV_RSA_FULL,
			CRYPT_NEWKEYSET				//创建密钥容器
			);
		if(!bRet)
		{
			Log("CryptAcquireContext fail!\n");
			return FALSE;
		}
	}

	//import public Key
	HCRYPTKEY hPubKey;
	if(CryptImportKey(hCryptProv, pPublicKey, dwPublicKeyLen, 0, 0, &hPubKey))  
		Log("Import the Public Key.\n");  
	else  
		Log("CryptImportKey Error!\n");  

	//Hash Data
	HCRYPTHASH hHash;
	if(CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash))  
		Log("Create Hash Object Succee!\n");  
	else  
		Log("Create Hash Object Failed!"); 

	if(CryptHashData(hHash, pData, dwDataLen, 0))  
		Log("Hash Data Done!\n");  
	else  
		Log("Hash Data Error!\n");

	//Verify Hash Data
	if(CryptVerifySignature(hHash, pSignature, dwSigLen, hPubKey, NULL, 0))  
		Log("Verify Succed!\n");  
	else  
		Log("Verify Failed!");   

	if(hHash)  
		CryptDestroyHash(hHash);  
	if(hCryptProv)  
		CryptReleaseContext(hCryptProv,0);

	return TRUE;
}

DWORD HexToStr(IN CONST BYTE *pbHex, IN DWORD dwHexLen, OUT BYTE *pbStr)
{
	DWORD i = 0;
	for(i=0; i<dwHexLen; i++)
	{
		if (((pbHex[i]&0xf0)>>4)>=0 && ((pbHex[i]&0xf0)>>4)<=9)
			pbStr[2*i]=((pbHex[i]&0xf0)>>4)+0x30;
		else if (((pbHex[i]&0xf0)>>4)>=10 && ((pbHex[i]&0xf0)>>4)<=16)
			pbStr[2*i]=((pbHex[i]&0xf0)>>4)+0x37;
		else 
			return -1;	//won't happen

		if ((pbHex[i]&0x0f)>=0 && (pbHex[i]&0x0f)<=9)
			pbStr[2*i+1]=(pbHex[i]&0x0f)+0x30;
		else if ((pbHex[i]&0x0f)>=10 && (pbHex[i]&0x0f)<=16)
			pbStr[2*i+1]=(pbHex[i]&0x0f)+0x37;
		else 
			return -1;  //won't happen
	}
	return 0;
}

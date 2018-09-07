// CSPAPI_SignAndVerify.h : main header file for the CSPAPI_SignAndVerify DLL
//

#pragma once

//#ifndef __AFXWIN_H__
//	#error "include 'stdafx.h' before including this file for PCH"
//#endif

//#include "resource.h"		// main symbols
#include <Windows.h>
#include <WinCrypt.h>

#define  DEFAULT_CSP_NAME	"HaiTai Cryptographic Service Provider 00001"
#define  DEFAULT_CSP_CONT	"178CCC7A-7791-4902-B40D-4A1E74E05BC8"


// CCSPAPI_SignAndVerifyApp
// See CSPAPI_SignAndVerify.cpp for the implementation of this class
//

//class CCSPAPI_SignAndVerifyApp : public CWinApp
//{
//public:
//	CCSPAPI_SignAndVerifyApp();
//
//// Overrides
//public:
//	virtual BOOL InitInstance();
//
//	DECLARE_MESSAGE_MAP()
//};

BOOL __stdcall SignHash(IN BYTE* pData, IN DWORD dwDataLen, OUT BYTE** pSignature, OUT DWORD* dwSigLen, OUT BYTE** pPublicKey, OUT DWORD* dwPubKeyLen);

BOOL __stdcall VerifySignature(IN BYTE* pData, IN DWORD dwDataLen, IN BYTE* pSignature, IN DWORD dwSigLen, IN BYTE* pPublicKey, IN DWORD dwPublicKeyLen);


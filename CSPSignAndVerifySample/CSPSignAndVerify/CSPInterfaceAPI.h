#include "stdafx.h"
#include <Windows.h>
#include <WinCrypt.h>


/************************************************************************/
/* Author	:LinJunHAN													*/
/* Content	:Use Win CSP API to Sign And Verify							*/
/* Time		:2018-08-29													*/
/************************************************************************/

#define  DEFAULT_CSP_NAME	"****** Cryptographic Service Provider *****"		//CSP����
#define  DEFAULT_CSP_CONT	"178CCC7A-7791-4902-B40D-4A1E74E05BC8"				//����֤�������

/*****************************************************
*��������SignHash
*��  �ܣ���һ�����ݽ��й�ϡǩ��,��������Կ
*��  �Σ�IN BYTE* pData,        //�����й�ϡǩ��������
		 IN DWORD dwDataLen,	//���ݳ���
*��  �Σ�OUT BYTE** pSignature, //��ϡǩ�����ݵĵ�ַ��ʹ������ɵ������ͷ�
		 OUT DWORD* dwSigLen,	//ǩ��ʵ�ʳ���
		 OUT BYTE** pPublicKey, //��Կ���ݵĵ�ַ��ʹ������ɵ������ͷ�
		 OUT DWORD* dwPubKeyLen);//��Կʵ�ʳ���
*����ֵ��BOOL��TRUΪǩ���ɹ���FALSEΪǩ��ʧ��
******************************************************/
BOOL CSP_SignHash(IN BYTE* pData, IN DWORD dwDataLen, OUT BYTE** pSignature, OUT DWORD* dwSigLen, OUT BYTE** pPublicKey, OUT DWORD* dwPubKeyLen);


/*****************************************************
*��������VerifySignature
*��  �ܣ���һ�����ݽ���ǩ����֤
*��  �Σ�IN BYTE* pData,        //�����й�ϡ��֤������
		 IN DWORD dwDataLen,	//���ݳ���
		 IN BYTE* pSignature,	//ǩ��
		 IN DWORD dwSigLen,		//ǩ������
		 IN BYTE* pPublicKey,	//��Կ
		 IN DWORD dwPublicKeyLen);//��Կ����
*��  �Σ���
*����ֵ��BOOL��TRUΪ��֤ǩ���ɹ���FALSEΪ��֤ǩ��ʧ��
******************************************************/
BOOL CSP_VerifySignature(IN BYTE* pData, IN DWORD dwDataLen, IN BYTE* pSignature, IN DWORD dwSigLen, IN BYTE* pPublicKey, IN DWORD dwPublicKeyLen);


DWORD HexToStr(IN CONST BYTE *pbHex, IN DWORD dwHexLen, OUT BYTE *pbStr);
#ifndef MYDES_H_5ADB0909_F61A_491b_9138_E726F31CDD9B
#define MYDES_H_5ADB0909_F61A_491b_9138_E726F31CDD9B

#include <stdio.h>
#include <Windows.h>
#include <WinCrypt.h>
#pragma comment(lib,"Crypt32.lib")

#define MYDES_MAXTEXT 64

void MyByte2Hex(char* sz,DWORD& dSize)
{
	char hex_table[16] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	char *pszTemp = new char[dSize*2];
	ZeroMemory(pszTemp,dSize*2);
	for ( int i = 0; i < dSize; i++)
	{
		BYTE _by = sz[i];
		pszTemp[2*i] = hex_table[(_by >> 4)&0x0F];
		pszTemp[2*i+1]=hex_table[_by & 0x0F];
	}
	ZeroMemory(sz,MYDES_MAXTEXT);
	memcpy(sz,pszTemp,dSize*2);
	delete[] pszTemp;
}

void MyHex2Byte(char* sz,DWORD& dSize)
{
	DWORD dTemp = dSize/2;
	char* pszTemp = new char[dTemp];
	ZeroMemory(pszTemp,dTemp);
	for (int i = 0 ; i < dTemp; i++)
	{
		char szTemp[2];
		szTemp[0] = sz[i*2];
		szTemp[1] = sz[i*2+1];
		unsigned long j = strtoul(szTemp,NULL,16);
		*(pszTemp+i) = (char)j;
	}
	ZeroMemory(sz,MYDES_MAXTEXT);
	memcpy(sz,pszTemp,dTemp);
	dSize = dTemp;
	delete[] pszTemp;
}

void CutString(char* sz,DWORD dSize)
{
	char* pszTemp = new char[dSize];
	memcpy(pszTemp,sz,dSize);
	ZeroMemory(sz,MYDES_MAXTEXT);
	memcpy(sz,pszTemp,dSize);
	delete[] pszTemp;
}

extern "C" BOOL __stdcall My3DesEnCrypt(char* szText, LPCSTR szPassword)
{
	HCRYPTKEY hKey = NULL;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD dTextLen = strlen(szText);
	DWORD dPassLen = strlen(szPassword);
	BOOL bResult = FALSE;
	char* szTemp = NULL;

	if (dTextLen < 1 || dTextLen > 15 || dPassLen < 1 || dPassLen> 31)
		return FALSE;

	if (!CryptAcquireContext(
		&hProv,
		NULL,
		NULL,
		PROV_RSA_SCHANNEL,
		CRYPT_VERIFYCONTEXT))
	{
		goto Exit_My3Des;
	}

	if (!CryptCreateHash(
		hProv,
		CALG_SHA,
		NULL,
		NULL,
		&hHash))
	{
		goto Exit_My3Des;
	}

	if(!CryptHashData(
		hHash,
		(BYTE*)szPassword,
		dPassLen,
		0))
	{
		goto Exit_My3Des;
	}

	if(!CryptDeriveKey(
		hProv,
		CALG_3DES,
		hHash,
		0,
		&hKey))
	{
		goto Exit_My3Des;
	}

	// 	DWORD dCipher = dTextLen;
	// 	if (!CryptEncrypt(
	// 		hKey,
	// 		NULL,
	// 		TRUE,
	// 		0,
	// 		NULL,
	// 		&dCipher,
	// 		dTextLen))
	// 	{
	// 		goto Exit_My3Des;
	// 	}

	if (!CryptEncrypt(
		hKey,
		NULL,
		TRUE,
		0,
		(BYTE*)szText,
		&dTextLen,
		MYDES_MAXTEXT))
	{
		goto Exit_My3Des;
	}

	MyByte2Hex(szText,dTextLen);

	// 	DWORD dCipLen = 0;
	// 	if (!CryptBinaryToString(
	// 		(BYTE*)szText,
	// 		dTextLen,
	// 		CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
	// 		NULL,
	// 		&dCipLen))
	// 	{
	// 		goto Exit_My3Des;
	// 	}
	// 
	// 	if (dCipLen > MYDES_MAXTEXT)
	// 	{
	// 		goto Exit_My3Des;
	// 	}
	// 	szTemp = new char[dCipLen];
	// 	ZeroMemory(szTemp,dCipLen);
	// 	
	// 	if (!CryptBinaryToString(
	// 		(BYTE*)szText,
	// 		dTextLen,
	// 		CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
	// 		szTemp,
	// 		&dCipLen))
	// 	{
	// 		goto Exit_My3Des;
	// 	}
	// 	ZeroMemory(szText,MYDES_MAXTEXT);
	// 	memcpy(szText,szTemp,dCipLen);

	bResult = TRUE;


Exit_My3Des:
	{
		if (!bResult)
		{
			DWORD dError = GetLastError();
			char szTemp[256]="";
			sprintf(szTemp,"%d\r\n",dError);
			OutputDebugString(szTemp);
		}

		if (szTemp)
		{
			delete[] szTemp;
			szTemp = NULL;
		}

		if (hHash)
		{
			CryptDestroyHash(hHash);
			hHash = NULL;
		}
		if (hKey)
		{
			CryptDestroyKey(hKey);
			hKey = NULL;
		}
		if (hProv)
		{
			CryptReleaseContext(hProv,0);
			hProv = NULL;
		}

	}
	return bResult;
}

extern "C" BOOL __stdcall My3DesDeCrypt(char* szText, LPCSTR szPassword)
{
	HCRYPTKEY hKey = NULL;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD dTextLen = strlen(szText);
	DWORD dPassLen = strlen(szPassword);
	BOOL bResult = FALSE;
	char* szTemp = NULL;

	if (dTextLen < 1 || dTextLen > 32 || dPassLen < 1 || dPassLen> 31)
		return FALSE;

	if (!CryptAcquireContext(
		&hProv,
		NULL,
		NULL,
		PROV_RSA_SCHANNEL,
		CRYPT_VERIFYCONTEXT))
	{
		goto Exit_My3Des;
	}

	if (!CryptCreateHash(
		hProv,
		CALG_SHA,
		NULL,
		NULL,
		&hHash))
	{
		goto Exit_My3Des;
	}

	if(!CryptHashData(
		hHash,
		(BYTE*)szPassword,
		dPassLen,
		0))
	{
		goto Exit_My3Des;
	}

	if(!CryptDeriveKey(
		hProv,
		CALG_3DES,
		hHash,
		0,
		&hKey))
	{
		goto Exit_My3Des;
	}

	// 	DWORD dCipher = dTextLen;
	// 	if (!CryptEncrypt(
	// 		hKey,
	// 		NULL,
	// 		TRUE,
	// 		0,
	// 		NULL,
	// 		&dCipher,
	// 		dTextLen))
	// 	{
	// 		goto Exit_My3Des;
	// 	}

	MyHex2Byte(szText,dTextLen);

	if (!CryptDecrypt(
		hKey,
		NULL,
		TRUE,
		0,
		(BYTE*)szText,
		&dTextLen))
	{
		goto Exit_My3Des;
	}

	//²Ã¼ô×Ö·û´®
	CutString(szText,dTextLen);

	// 	DWORD dCipLen = 0;
	// 	if (!CryptBinaryToString(
	// 		(BYTE*)szText,
	// 		dTextLen,
	// 		CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
	// 		NULL,
	// 		&dCipLen))
	// 	{
	// 		goto Exit_My3Des;
	// 	}
	// 
	// 	if (dCipLen > MYDES_MAXTEXT)
	// 	{
	// 		goto Exit_My3Des;
	// 	}
	// 	szTemp = new char[dCipLen];
	// 	ZeroMemory(szTemp,dCipLen);
	// 	
	// 	if (!CryptBinaryToString(
	// 		(BYTE*)szText,
	// 		dTextLen,
	// 		CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,
	// 		szTemp,
	// 		&dCipLen))
	// 	{
	// 		goto Exit_My3Des;
	// 	}
	// 	ZeroMemory(szText,MYDES_MAXTEXT);
	// 	memcpy(szText,szTemp,dCipLen);
	bResult = TRUE;


Exit_My3Des:
	{
		if (!bResult)
		{
			DWORD dError = GetLastError();
			char szTemp[256]="";
			sprintf(szTemp,"%d\r\n",dError);
			OutputDebugString(szTemp);
		}

		if (szTemp)
		{
			delete[] szTemp;
			szTemp = NULL;
		}

		if (hHash)
		{
			CryptDestroyHash(hHash);
			hHash = NULL;
		}
		if (hKey)
		{
			CryptDestroyKey(hKey);
			hKey = NULL;
		}
		if (hProv)
		{
			CryptReleaseContext(hProv,0);
			hProv = NULL;
		}

	}
	return bResult;
}

#endif   // MYDES_H_5ADB0909_F61A_491b_9138_E726F31CDD9B
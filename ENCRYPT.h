#pragma once

#include "DES.h"

class Encrypt{
public : 
	void ec(unsigned char key[8],char* data,DWORD& dSize);
	void dc(unsigned char key[8],char* data,DWORD& dSize);



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
		ZeroMemory(sz,64);
		memcpy(sz,pszTemp,dSize*2);
		dSize = dSize*2;
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
		ZeroMemory(sz,64);
		memcpy(sz,pszTemp,dTemp);
		dSize = dTemp;
		delete[] pszTemp;
	}
};

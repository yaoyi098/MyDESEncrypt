#include "StdAfx.h"
#include "ENCRYPT.h"

//Encrypt.cpp

#include <stdio.h>

void Encrypt::ec(unsigned char key[8],char* data,DWORD& dSize)
{
	DES des ;
	char* temp = new char[100];
	ZeroMemory(temp,100);
	dSize = strlen(data);
	memcpy(temp,data,dSize);
	int iBlock = 1;
	if (dSize <= 8)
	{
		dSize = 8;
	}
	else if (dSize>8 && dSize < 16)
	{
		iBlock = 2;
		dSize = 16;
	}
	des.encrypt(key,(unsigned char *)temp,iBlock);
	ZeroMemory(data,64);
	
	memcpy(data,temp,dSize);
	delete[] temp;
	MyByte2Hex(data,dSize);
	return;
}

void Encrypt::dc(unsigned char key[8],char* data,DWORD& dSize)
{
	MyHex2Byte(data,dSize);
	char* temp = new char[256];
	ZeroMemory(temp,256);
	memcpy(temp,data,64);
	DES des;
	int iBlock = 1;
	if (dSize == 16)
	{
		iBlock = 2;
	}
	des.decrypt(key,(unsigned char*) temp,iBlock);
	ZeroMemory(data,64);
	memcpy(data,temp,strlen(temp));
	delete[] temp;
}


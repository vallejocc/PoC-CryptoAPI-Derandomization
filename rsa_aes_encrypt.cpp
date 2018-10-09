//Author: Javier Vicente Vallejo
//Related article: http://www.vallejo.cc/2018/09/cryptoapi-derandomization.html

//#ifndef _WIN32_WINNT
//#define _WIN32_WINNT 0x0500
//#endif						

#include <stdio.h>
#include <tchar.h>
#include <windows.h>

#pragma comment(lib, "Crypt32")

//hooks for cryptoapi rnd funcs, fill input buffers with non-random data ("\x01\x01\x01\x01...")

//bcryptprimitives.dll!ProcessPrng
signed __int64 __fastcall MyProcessPrng(void * buf, SIZE_T len)
{
	memset(buf, 0x1, len);
	return 1;
}

//rsaenh!AesCtrWithFipsChecks (internal func, necesary to find it by searching patters
int __stdcall MyAesCtrWithFipsChecks(void *pbBuffer, int cbBuffer, int a, int b)
{
	memset(pbBuffer, 0x1, cbBuffer);
	return 0;
}

void hook(void * ptr, void * hookptr) {
#ifdef _WIN64
	//HOOK ProcessPrng to disable random padding
	{DWORD temp; SIZE_T temp2;
	if (ptr) {
		//mov rax, addr_hook / push rax / ret
		unsigned char bufProcessPrng[] = { 0x48, 0xb8, 0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0xFF , 0x50, 0xC3 };
		*((void**)&bufProcessPrng[2]) = hookptr;
		VirtualProtect(ptr, 30, PAGE_EXECUTE_READWRITE, &temp);
		WriteProcessMemory((HANDLE)-1, ptr, bufProcessPrng, sizeof(bufProcessPrng), (SIZE_T*)&temp2);
	}};
#else
	//HOOK ProcessPrng to disable random padding
	{DWORD temp; SIZE_T temp2;
	if (ptr) {
		//mov eax, addr_hook / push eax / ret
		unsigned char bufProcessPrng[] = { 0xb8, 0xFF , 0xFF , 0xFF , 0xFF , 0x50, 0xC3 };
		*((void**)&bufProcessPrng[1]) = (void*)hookptr;
		VirtualProtect(ptr, 30, PAGE_EXECUTE_READWRITE, &temp);
		WriteProcessMemory((HANDLE)-1, ptr, bufProcessPrng, sizeof(bufProcessPrng), (SIZE_T*)&temp2);
	}};
#endif
}

void* SearchAesCtrWithFipsChecks()
{
	/*.text:0AC04423                               _CPGenRandom@12 proc near; DATA XREF : .text : off_AC01564
	.text : 0AC04423
	.text : 0AC04423                               arg_0 = dword ptr  8
	.text : 0AC04423                               arg_4 = dword ptr  0Ch
	.text : 0AC04423                               Src = dword ptr  10h
	.text : 0AC04423
	.text : 0AC04423; FUNCTION CHUNK AT.text:0AC20665 SIZE 00000016 BYTES
	.text : 0AC04423
	.text : 0AC04423 8B FF                                       mov     edi, edi
	.text : 0AC04425 55                                          push    ebp
	.text : 0AC04426 8B EC                                       mov     ebp, esp
	.text : 0AC04428 6A 00                                       push    0
	.text : 0AC0442A FF 75 08                                    push[ebp + arg_0]
	.text:0AC0442D E8 D5 D3 FF FF                                call    _NTLCheckList@8; NTLCheckList(x,x)
	.text:0AC04432 85 C0                                         test    eax, eax
	.text : 0AC04434 0F 84 2B C2 01 00                           jz      loc_AC20665
	.text : 0AC0443A 6A 00                                       push    0; int
	.text:0AC0443C 6A 00                                         push    0; int
	.text:0AC0443E FF 75 0C                                      push[ebp + arg_4]; int
	.text:0AC04441 FF 75 10                                      push[ebp + Src]; Src
	.text:0AC04444 E8 BC E8 FF FF                                call    _AesCtrWithFipsChecks@16; AesCtrWithFipsChecks(x,x,x,x)
	.text:0AC04449
	.text : 0AC04449                               loc_AC04449 : ; CODE XREF : CPGenRandom(x,x,x) + 1C247*/
	unsigned char * pCPGenRandom = (unsigned char *)GetProcAddress(LoadLibrary("rsaenh.dll"), "CPGenRandom");
	unsigned int i = 0;
	for (i = 0; i < 100; i++) {
		if (pCPGenRandom[i] == 0xff && pCPGenRandom[i + 1] == 0x75 && pCPGenRandom[i + 2] == 0xc &&
			pCPGenRandom[i + 3] == 0xff && pCPGenRandom[i + 4] == 0x75 && pCPGenRandom[i + 5] == 0x10 &&
			pCPGenRandom[i + 6] == 0xe8)
		{
			DWORD temp = (*(DWORD*)(pCPGenRandom + i + 6 + 1));
			temp = ((DWORD)((pCPGenRandom + i + 6 + 5 + temp)) & 0xffffffff);
			return (void*)temp;
		}
	}
	return NULL;
}

int main(int argc, _TCHAR* argv[])
{
	//__asm int 3;

	hook(GetProcAddress(LoadLibrary("bcryptprimitives.dll"), "ProcessPrng"), MyProcessPrng);
	hook(SearchAesCtrWithFipsChecks(), MyAesCtrWithFipsChecks);
	
	BYTE* plain = (BYTE*)"lalalalalalalalalalalalalalalala";
	DWORD dwplainLen = (DWORD)strlen((char*)plain);
	char * pem = "-----BEGIN RSA PRIVATE KEY-----"
		"MIICXQIBAAKBgQCnPswx7NWNY5AGaD7D9LVA7+aNJ/z17Pt/6s7CvK519iw7oHoG"
		"1YcifTaHIfwZz1D3XtcsyrGFb9UG4QRstyO+Q2d9mwjsX/LSE71V395KiVFGtQVe"
		"/b0CjlCpRm1yfs1WbahLXeYM/kD5RDd9CZp2E0pokka14byKE1snxZNT4QIDAQAB"
		"AoGBAJCwWYQPuykZK67/XN22xWCqq7EPGV/BaEvgXoRHLD/Ne7MSQL/M155U6Wm7"
		"UxkZLJj2Kf4MVcx1Vb0fyu4q+vXn39DNfTa8xv/Cy7Fb1cM9WFndqaabARC677x6"
		"ugqfE/boSsVC/Kjo1VuVmsXM+CQYkt1RyvRYIIjwxAjxUIfhAkEAzyClC06ASDR/"
		"nhejvTZbfie0ymHS9Mck/3zdx77SnV5dX5GQgNIr4bvkpTceFoZQQtOHYaEIfY8Z"
		"TJklkA05bQJBAM61GlUO6vEBMGXv3rqocZJUbB2bqY+mGh13xQ3dPeyC0lBaxnf3"
		"OgaqUdL6boA4+j1pHjIeLVGW1A8F32Zzz8UCQC5Gitk11q9LG2AExA5YAKT01g2J"
		"QYpym6+BBEPGPGPwW0goy3IcgrVSN0k6QTyjEXd8rvh+89ipiet1I9FFQxkCQBNx"
		"DSz63jYUuoyb5wL/XM86iYCvZ19PbB1hanNHX8+i7k0IfKpD4n1F/7QsQcBlm4Oz"
		"I1frZq/J0+Al2UE1m1ECQQCO7csOphDIjkuVQErkErhEmNOnZf/7wl5pEapVhrge"
		"A4IdLRgbJ6od+Dq6zC2tTHbRI/62xGv0Tey2mIDwD1d0"
		"-----END RSA PRIVATE KEY-----";
	
	HCRYPTPROV hProv = NULL;
	HCRYPTPROV hProvAES = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hKeyAES = NULL;
	BOOL bStatus = FALSE;
	LPBYTE pEncryptedData = NULL;
	DWORD i, dwKeyLen = 0, dwValLen = 0;
	DWORD dwEncryptedDataLen = 0;
	DWORD err = 0;
	
	bStatus = CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0);
	err = GetLastError();
	if (bStatus == 0) { bStatus = CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET); err = GetLastError(); }
	bStatus = CryptAcquireContext(&hProvAES, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0);
	err = GetLastError();
	if (bStatus == 0) { bStatus = CryptAcquireContext(&hProvAES, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0); err = GetLastError(); }

	//Test ProcessPrng/AesCtrWithFipsChecks HOOK
	{BYTE tempbuf[100]; CryptGenRandom(hProv, 100, tempbuf); }

	printf("Plain:\n");
	for (i = 0; i< dwplainLen; i++) printf("\\x%.2X", plain[i]); printf("\n\n");

	//Gen random AES key (because we have hooked ProcessPrng, the generated AES key will be \x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01)
	BYTE * plainAES = (BYTE*)malloc(dwplainLen*3);
	memcpy(plainAES, plain, dwplainLen);
	bStatus = CryptGenKey(hProvAES, CALG_AES_128, CRYPT_EXPORTABLE, &hKeyAES);
	err = GetLastError();

	//use CBC cipher mode
	DWORD mode = CRYPT_MODE_CBC;
	bStatus = CryptSetKeyParam(hKeyAES, KP_MODE, (BYTE*)&mode, 0);
	err = GetLastError();
	
	//PKCS 5 padding method
	DWORD padData = PKCS5_PADDING;
	bStatus = CryptSetKeyParam(hKeyAES, KP_PADDING, (BYTE*)&padData, 0);
	err = GetLastError();

	//Set IV
	BYTE *iv = (BYTE*)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x01";
	bStatus = CryptSetKeyParam(hKeyAES, KP_IV, iv, 0);
	err = GetLastError();
	
	// Export and print AES key
	BYTE exportKey[1024];
	DWORD exportKeyLen;
	bStatus = CryptExportKey(hKeyAES, NULL, PLAINTEXTKEYBLOB, 0, exportKey, &exportKeyLen);
	err = GetLastError();
	printf("Generated AES key:\n");
	for (i = 0; i< exportKeyLen; i++) printf("\\x%.2X", exportKey[i]); printf("\n\n");

	//Encrypt with random AES key (if we have set ProcessPrng, the generated AES key will be always the same key: \x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01)
	bStatus = CryptEncrypt(hKeyAES, NULL, TRUE, 0, (BYTE*)plainAES, &dwplainLen, dwplainLen*3);
	err = GetLastError();
	plain = plainAES;
	//in spite of the fact that our plaintext length is aligned to 128 bits, 
	//CryptoAPI add 16 unuseful padding bytes Lets remove that unuseful padding
	dwplainLen -= 16;
	
	printf("Plain+AES:\n");
	for (i = 0; i< dwplainLen; i++) printf("\\x%.2X", plain[i]); printf("\n\n");
	
	//key PEM -> key BLOB
	DWORD dwBufferLen;
	LPBYTE pbBuffer;
	bStatus = CryptStringToBinaryA(pem, 0, CRYPT_STRING_BASE64HEADER, NULL, &dwBufferLen, NULL, NULL);
	err = GetLastError();
	pbBuffer = (LPBYTE)malloc(dwBufferLen);
	bStatus = CryptStringToBinaryA(pem, 0, CRYPT_STRING_BASE64HEADER, pbBuffer, &dwBufferLen, NULL, NULL);
	err = GetLastError();
	DWORD cbKeyBlob=0;
	bStatus = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, (BYTE*)pbBuffer, dwBufferLen, 0, NULL, NULL, &cbKeyBlob);
	err = GetLastError();
	LPBYTE pbKeyBlob = (LPBYTE)malloc(cbKeyBlob);
	bStatus = CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, (BYTE*)pbBuffer, dwBufferLen, 0, NULL, pbKeyBlob, &cbKeyBlob);
	err = GetLastError();
	bStatus = CryptImportKey(hProv, pbKeyBlob, cbKeyBlob, 0, 0, &hKey);
	err = GetLastError();
	dwValLen = sizeof(DWORD);
	bStatus = CryptGetKeyParam(hKey, KP_KEYLEN, (LPBYTE) &dwKeyLen, &dwValLen, 0);
	err = GetLastError();

	//CryptoAPI docu describes ZERO_PADDING or RANDOM_PADDING padding types, but they dont work, it only works PKCS5_PADDING	
	//Previously we have hooked ProcessPrng and in this way we can control the padding
	//DWORD paddingtype = ZERO_PADDING;  -> NOT WORKING; DISABLED; ONLY PKCS5_PADDING WORKS
	//DWORD paddingtype = RANDOM_PADDING;  -> NOT WORKING; DISABLED; ONLY PKCS5_PADDING WORKS
	//DWORD paddingtype = PKCS5_PADDING; -> NOT NECESARY TO SET THIS, IT IS SET BY DEFAULT
	//CryptSetKeyParam(hKey, KP_PADDING, (BYTE*)&paddingtype, 0);
	//GetLastError();
		
	dwKeyLen = (dwKeyLen + 7) / 8; // tranform to bytes length
	pEncryptedData = (LPBYTE) LocalAlloc(0, dwKeyLen);
	CopyMemory(pEncryptedData, plain, dwplainLen);
	dwEncryptedDataLen = dwplainLen;

	bStatus = CryptEncrypt(hKey, NULL, TRUE, 0, pEncryptedData, &dwEncryptedDataLen, dwKeyLen);
	err = GetLastError();
	
	printf("Plain+AES+RSA:\n");
	for (i=0; i< dwEncryptedDataLen; i++) printf("\\x%.2X", pEncryptedData[i]); printf("\n\n");

	bStatus = CryptDecrypt(hKey, NULL, TRUE, 0, pEncryptedData, &dwEncryptedDataLen);
	err = GetLastError();

	printf("Plain+AES+RSA-RSA:\n");
	for (i = 0; i< dwEncryptedDataLen; i++) printf("\\x%.2X", pEncryptedData[i]); printf("\n\n");

	bStatus = CryptDecrypt(hKeyAES, NULL, TRUE, 0, pEncryptedData, &dwEncryptedDataLen);
	err = GetLastError();

	printf("Plain+AES+RSA-RSA-AES:\n");
	for (i = 0; i< dwEncryptedDataLen; i++) printf("\\x%.2X", pEncryptedData[i]); printf("\n\n");

	LocalFree(pEncryptedData);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);
	CryptDestroyKey(hKeyAES);
	CryptReleaseContext(hProvAES, 0);
	free(pbKeyBlob);
	free(pbBuffer);

	return 0;
}

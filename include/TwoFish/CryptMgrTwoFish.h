#pragma once

#define CRYPT_KEY_TXT    "620C724A2FF22C975B5A2B9C21430820227B3D2800193AAA4CF3128803AC3ABD"
#define CRYPT_CIPHER_IV  "56B83E3F68B60F0F29357BED335E5642" 
#define MAX_PATH 260

#ifndef CA_CRYPTMGR_TWOFISH__H__
#define CA_CRYPTMGR_TWOFISH__H__

#ifndef CA_CRYPTMGR_TWOFISH_IMPL__H__
extern "C"
{
#include "cryptmgr_twofish_impl.h"
};
#endif

#include <iostream>
#include <Windows.h>

class CCryptMgrTwoFish
{
public:

	CCryptMgrTwoFish();
	CCryptMgrTwoFish(const char* key, const char* cipherIV);
	~CCryptMgrTwoFish();

	void SetKey(const char* key, const char* cipherIV);

	int EncryptAlmost(void* buffer, int size);
	int DecryptAlmost(void* buffer, int size);

	void DecryptSixteenBytes(std::istream& is, std::ostream& os);

	// if using fstreams be sure to open them in binary mode
	void Encrypt(std::istream& is, std::ostream& os);

	// if using fstreams be sure to open them in binary mode
	void Decrypt(std::istream& is, std::ostream& os);

	static long getFileSize(const char* filename);
	static char* ReadFile(const char* filename, long& fileSize);

	static std::string Encrypt(__inout char* buffer, __in const long size);
	static std::string Decrypt(__inout char* buffer, __in const long size);

	static bool EncryptFile(const char* szFileName); //use these if you want to encrypt file on disc to later be decrypted at runtime by ::Decrypt()
	static bool DecryptFile(const char* szFileName);
	static void save_buffer_to_file(const char* filename, const char* buffer, size_t buffer_size);

private:
	twofish_cipherInstance m_CipherEncode;
	twofish_keyInstance m_KeyEncode;

	twofish_cipherInstance m_CipherDecode;
	twofish_keyInstance m_KeyDecode;
};


#endif // #ifndef CA_CRYPTMGR_TWOFISH__H__

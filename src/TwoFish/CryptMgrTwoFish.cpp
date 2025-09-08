#include "../../include/TwoFish/CryptMgrTwoFish.h"

#pragma intrinsic(memcpy)
#pragma intrinsic(memset)


CCryptMgrTwoFish::CCryptMgrTwoFish()
	: m_CipherEncode()
	, m_KeyEncode()
	, m_CipherDecode()
	, m_KeyDecode()
{
}


CCryptMgrTwoFish::CCryptMgrTwoFish(const char* key, const char* cipherIV)
	: m_CipherEncode()
	, m_KeyEncode()
	, m_CipherDecode()
	, m_KeyDecode()
{
	SetKey(key, cipherIV);
}


CCryptMgrTwoFish::~CCryptMgrTwoFish()
{
}



void CCryptMgrTwoFish::SetKey(const char* key, const char* cipherIV)
{
	char defaultKey[64];
	char defaultIV[32];
	memset(defaultKey, '0', sizeof(defaultKey));
	memset(defaultIV, '0', sizeof(defaultIV));

	if (!key || strlen(key) < 64)
	{
		key = defaultKey;
	}
	if (!cipherIV || strlen(cipherIV) < 32)
	{
		cipherIV = defaultIV;
	}

	bool succeeded = true;

	succeeded &= twofish_cipherInit(&m_CipherEncode, TWOFISH_MODE_CBC, cipherIV) > 0;
	succeeded &= twofish_makeKey(&m_KeyEncode, TWOFISH_DIR_ENCRYPT, TWOFISH_MAX_KEY_BITS, key) > 0;
	succeeded &= twofish_cipherInit(&m_CipherDecode, TWOFISH_MODE_CBC, cipherIV) > 0;
	succeeded &= twofish_makeKey(&m_KeyDecode, TWOFISH_DIR_DECRYPT, TWOFISH_MAX_KEY_BITS, key) > 0;

	if (!succeeded)
	{
		twofish_cipherInit(&m_CipherEncode, TWOFISH_MODE_CBC, defaultIV);
		twofish_makeKey(&m_KeyEncode, TWOFISH_DIR_ENCRYPT, TWOFISH_MAX_KEY_BITS, defaultKey);
		twofish_cipherInit(&m_CipherDecode, TWOFISH_MODE_CBC, defaultIV);
		twofish_makeKey(&m_KeyDecode, TWOFISH_DIR_DECRYPT, TWOFISH_MAX_KEY_BITS, defaultKey);
	}
}

void CCryptMgrTwoFish::Encrypt(std::istream& is, std::ostream& os)
{
	int n = 0;
	BYTE bufR[TWOFISH_BLOCK_BYTES];
	BYTE bufW[TWOFISH_BLOCK_BYTES];

	while (!is.eof())
	{
		memset(bufR, 0, TWOFISH_BLOCK_BYTES);
		memset(bufW, 0, TWOFISH_BLOCK_BYTES);
		is.read(reinterpret_cast<char*>(bufR), TWOFISH_BLOCK_BYTES);
		n = static_cast<int>(is.gcount());
		twofish_blockEncrypt(&m_CipherEncode, &m_KeyEncode, bufR, TWOFISH_BLOCK_SIZE, bufW);
		os.write(reinterpret_cast<const char*>(bufW), TWOFISH_BLOCK_BYTES);
	}
	os.put(static_cast<char>(n));
}



void CCryptMgrTwoFish::Decrypt(std::istream& is, std::ostream& os)
{
	int n = 0;
	int prevDecoded = 0;
	BYTE bufR[TWOFISH_BLOCK_BYTES];
	BYTE bufW[TWOFISH_BLOCK_BYTES];

	while (!is.eof())
	{
		is.read(reinterpret_cast<char*>(bufR), TWOFISH_BLOCK_BYTES);
		n = static_cast<int>(is.gcount());

		if (n == TWOFISH_BLOCK_BYTES)
		{
			if (prevDecoded > 0)
			{
				os.write(reinterpret_cast<const char*>(bufW), prevDecoded);
			}

			twofish_blockDecrypt(&m_CipherDecode, &m_KeyDecode, bufR, TWOFISH_BLOCK_SIZE, bufW);
			prevDecoded = n;
		}
		else
		{
			int decoded = bufR[0];
			if (prevDecoded > 0 && decoded > 0)
			{
				os.write(reinterpret_cast<const char*>(bufW), decoded);
			}
			prevDecoded = 0;
		}
	}
}


int CCryptMgrTwoFish::EncryptAlmost(void* buffer, int size)
{
	if (!buffer)
	{
		return 0;
	}
	if (size < 0 || size >(INT_MAX / 8))
	{
		return 0;
	}

	BYTE* p = static_cast<BYTE*>(buffer);
	int alignDown = size & ~(TWOFISH_BLOCK_BYTES - 1);

	BYTE encoded[TWOFISH_BLOCK_BYTES];
	for (int i = 0; i < alignDown; i += TWOFISH_BLOCK_BYTES)
	{
		twofish_blockEncrypt(&m_CipherEncode, &m_KeyEncode, p, TWOFISH_BLOCK_SIZE, encoded);
		memcpy(p, encoded, TWOFISH_BLOCK_BYTES);
		p += TWOFISH_BLOCK_BYTES;
	}

	return size;
}

int CCryptMgrTwoFish::DecryptAlmost(void* buffer, int size)
{
	if (!buffer)
	{
		return 0;
	}
	if (size < 0 || size >(INT_MAX / 8))
	{
		return 0;
	}

	BYTE* p = static_cast<BYTE*>(buffer);
	int alignDown = size & ~(TWOFISH_BLOCK_BYTES - 1);

	BYTE encoded[TWOFISH_BLOCK_BYTES]{ 0 };
	for (int i = 0; i < alignDown; i += TWOFISH_BLOCK_BYTES)
	{
		twofish_blockDecrypt(&m_CipherDecode, &m_KeyDecode, p, TWOFISH_BLOCK_SIZE, encoded);
		memcpy(p, encoded, TWOFISH_BLOCK_BYTES);
		p += TWOFISH_BLOCK_BYTES;
	}

	return size;
}

void CCryptMgrTwoFish::DecryptSixteenBytes(std::istream& is, std::ostream& os)
{
	int n = 0;
	BYTE bufR[TWOFISH_BLOCK_BYTES];
	BYTE bufW[TWOFISH_BLOCK_BYTES];

	while (!is.eof())
	{
		memset(bufR, 0, TWOFISH_BLOCK_BYTES);
		memset(bufW, 0, TWOFISH_BLOCK_BYTES);
		is.read(reinterpret_cast<char*>(bufR), TWOFISH_BLOCK_BYTES);
		n = static_cast<int>(is.gcount());

		if (n == TWOFISH_BLOCK_BYTES)
		{
			twofish_blockDecrypt(&m_CipherDecode, &m_KeyDecode, bufR, TWOFISH_BLOCK_SIZE, bufW);
			os.write(reinterpret_cast<const char*>(bufW), TWOFISH_BLOCK_BYTES);
		}
		else
		{
			os.write(reinterpret_cast<const char*>(bufR), TWOFISH_BLOCK_BYTES);
		}
	}
}

std::string CCryptMgrTwoFish::Encrypt(__inout char* buffer, __in const long size)
{
	const char* szCryptKey = NULL;
	const char* szCryptIV = NULL;

	szCryptKey = CRYPT_KEY_TXT;
	szCryptIV = CRYPT_CIPHER_IV;

	if (buffer == NULL)
		return "";

	// encrypt
	if (szCryptKey && szCryptIV)
	{
		CCryptMgrTwoFish cryptMgr(szCryptKey, szCryptIV);
		cryptMgr.EncryptAlmost((char*)buffer, size);
	}

	return std::string(buffer);
}

/*
	Decrypt - decrypts `buffer` with `size` bytes
	** warning: This is a block encryption routine, with 16 bytes per block, meaning that your buffer must be aligned to 16 bytes or have +16 bytes of buffer size past `size`
*/	
std::string CCryptMgrTwoFish::Decrypt(__inout char* buffer, __in const long size)
{
	const char* szCryptKey = NULL;
	const char* szCryptIV = NULL;

	szCryptKey = CRYPT_KEY_TXT;
	szCryptIV = CRYPT_CIPHER_IV;

	if (buffer == NULL)
		return "";

	// decrypt
	if (szCryptKey && szCryptIV)
	{
		CCryptMgrTwoFish cryptMgr(szCryptKey, szCryptIV);
		cryptMgr.DecryptAlmost((char*)buffer, size);
	}

	buffer[size] = '\0'; //null terminate string

	return std::string(buffer);
}

char* CCryptMgrTwoFish::ReadFile(const char* filename, long& fileSize)
{
	FILE* file = fopen(filename, "rb"); 
	if (file == nullptr)
	{
		//printf("File was NULL, check file path!\n");
		return nullptr;  
	}

	// Get file size
	fseek(file, 0, SEEK_END);
	fileSize = ftell(file);
	rewind(file);

	char* buffer = (char*)malloc(fileSize);
	if (buffer == nullptr)
	{
		fclose(file);
		return nullptr;
	}

	size_t bytesRead = fread(buffer, 1, fileSize, file);
	if (bytesRead != fileSize)
	{
		free(buffer);
		fclose(file);
		return nullptr;
	}

	fclose(file);
	return buffer;
}

long CCryptMgrTwoFish::getFileSize(const char* filename)
{
	FILE* file = fopen(filename, "rb");
	if (file == nullptr)
	{
		return -1;
	}

	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	fclose(file);
	return fileSize;
}

void CCryptMgrTwoFish::save_buffer_to_file(const char* filename, const char* buffer, size_t buffer_size)
{

	char cwd[MAX_PATH];
	if (GetCurrentDirectoryA(MAX_PATH, cwd))
	{
		char full_path[MAX_PATH];
		snprintf(full_path, sizeof(full_path), "%s\\%s", cwd, filename);

		FILE* file = fopen(full_path, "wb");
		if (file == NULL)
		{
			perror("Error opening file");
			return;
		}

		size_t written_size = fwrite(buffer, sizeof(char), buffer_size, file);
		if (written_size != buffer_size)
		{
			perror("Error writing to file");
		}
		else
		{
			printf("File written successfully to %s\n", full_path);
		}

		fclose(file);
	}
	else
	{
		perror("Error getting current working directory");
	}
}

bool CCryptMgrTwoFish::DecryptFile(const char* szFileName)
{
	const char* szCryptKey = NULL;
	const char* szCryptIV = NULL;

	szCryptKey = CRYPT_KEY_TXT;
	szCryptIV = CRYPT_CIPHER_IV;

	long dwFileSize = 0;
	char* buff = CCryptMgrTwoFish::ReadFile(szFileName, dwFileSize);

	if (buff == NULL)
		return false;

	// decrypt
	if (szCryptKey && szCryptIV)
	{
		CCryptMgrTwoFish cryptMgr(szCryptKey, szCryptIV);
		cryptMgr.DecryptAlmost((char*)buff, dwFileSize);
	}

	int size_output_filename = strlen(szFileName) + strlen("_decrypt") + 1;
	char* filename_dec = new char[size_output_filename];

	for (int i = 0; i < size_output_filename; i++)
	{
		filename_dec[i] = 0x00;
	}

	strcat(filename_dec, szFileName);
	//strcat(filename_dec, "_decrypt");

	save_buffer_to_file(filename_dec, buff, dwFileSize);

	delete[] filename_dec;
	return true;
}


bool CCryptMgrTwoFish::EncryptFile(const char* szFileName)
{
	const char* szCryptKey = NULL;
	const char* szCryptIV = NULL;

	szCryptKey = CRYPT_KEY_TXT;
	szCryptIV = CRYPT_CIPHER_IV;

	long dwFileSize = 0;

	char* buff = CCryptMgrTwoFish::ReadFile(szFileName, dwFileSize);

	if (buff == NULL)
		return false;

	// encrypt
	if (szCryptKey && szCryptIV)
	{
		CCryptMgrTwoFish cryptMgr(szCryptKey, szCryptIV);
		cryptMgr.EncryptAlmost((char*)buff, dwFileSize);
	}

	int size_output_filename = strlen(szFileName) + strlen("_encrypt") + 1;
	char* filename_dec = new char[size_output_filename];

	for (int i = 0; i < size_output_filename; i++)
	{
		filename_dec[i] = 0x00;
	}

	strcat(filename_dec, szFileName);

	save_buffer_to_file(filename_dec, buff, dwFileSize);

	return true;
}
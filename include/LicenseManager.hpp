#pragma once
#include "HttpClient.hpp"
#include "License.hpp"
#include <wincrypt.h>
#include <bcrypt.h>
#include <fstream>
#include <string>
#include <vector>
#include "XorStr.hpp"

#pragma comment(lib, "bcrypt.lib")


class LicenseManager final //Not finished yet
{
public:
	LicenseManager(std::string LicenseServerEndpoint, bool bAllowOfflineProductUsage, std::string LicenseFileName) 
		: LicenseServerEndpoint(LicenseServerEndpoint), bAllowOfflineProductUsage(bAllowOfflineProductUsage), LicenseFileName(LicenseFileName)
	{
	}

	~LicenseManager()
	{
		if (RSAPubKeyPinned != nullptr)
			delete[] RSAPubKeyPinned;

		if (PINNED_PUB_KEY_X != nullptr)
			delete[] PINNED_PUB_KEY_X;

		if (PINNED_PUB_KEY_Y != nullptr)
			delete[] PINNED_PUB_KEY_Y;
	}

	bool SendLicenseInfo(__in const bool bUsingEncryption);

	static bool Sha256_CNG(const void* data, size_t len, std::vector<uint8_t>& out32);
	static bool DerEcdsaToP1363(const uint8_t* der, size_t derLen, uint8_t out64[64]);

	BCRYPT_KEY_HANDLE import_es256_pubkey(__in std::vector<uint8_t>& x, __in std::vector<uint8_t>& y);
    bool VerifyLicenseJWT_ES256(__in const std::string& token);

	const uint8_t* GetPubX() const  { return PINNED_PUB_KEY_X; }
	const uint8_t* GetPubY() const { return PINNED_PUB_KEY_Y; }

	bool IsOfflineUsageAllowed() const { return bAllowOfflineProductUsage; }

private:
	
	char* RSAPubKeyPinned = nullptr;

	std::string LicenseKey;
	std::vector<uint8_t> LicenseSignature; //grabbed from file or registry or w/e
	std::string LicenseFileName;

	std::string LicenseServerEndpoint;

	bool bAllowOfflineProductUsage = false;

	std::vector<uint8_t> LoadPublicKeyContents(const std::string& pubKeyText);
	BCRYPT_KEY_HANDLE LoadRSAPublicKey(const std::vector<uint8_t> derData);
	bool VerifySignature(BCRYPT_KEY_HANDLE hKey, const std::vector<uint8_t>& licenseData, const std::vector<uint8_t>& signature);

	//pinned public key -> replace with your public key X/Y from dump_xy.py  (we originally generate an ECDSA keypair with openssl, then make a license.jwt file which embeds license details)
	const uint8_t* PINNED_PUB_KEY_X = new uint8_t[32] { 0x0e,0x8a,0x31,0x1e,0x93,0x8d,0xc5,0x14,0x8e,0xb7,0x9c,0xb1,0x70,0xd9,0xca,0x35,0x3a,0x44,0x9b,0xb9,0xe1,0x65,0xa0,0xc3,0xfb,0xc6,0xb8,0x73,0x2b,0xd8,0xcd,0xc8 };
	const uint8_t* PINNED_PUB_KEY_Y = new uint8_t[32] { 0xfe,0x24,0xf5,0x84,0xeb,0x0e,0x20,0x39,0xd3,0x66,0xbe,0x76,0x14,0x3c,0xdb,0xc0,0xc1,0x97,0xca,0x96,0x83,0x55,0x99,0x0f,0xc1,0x18,0x5b,0x1d,0x7d,0x94,0x48,0x67 };
};
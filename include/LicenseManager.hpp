#pragma once
#include "HttpClient.hpp"
#include "License.hpp"
#include "TwoFish/CryptMgrTwoFish.h"
#include "Utility.hpp"
#include <wincrypt.h>
#include <bcrypt.h>
#include <fstream>
#include <string>
#include <vector>
#include "XorStr.hpp"

#pragma comment(lib, "bcrypt.lib")

enum LicenseRequestStatus
{
	OK = 1,
	UNKNOWN_LEASE,
	UNKNOWN_TOKEN,
	LEASE_EXPIRED,
	BANNED_MACHINE_ID,
	INCORRECT_API_VERSION,
	CALL_PARAMETER_ERROR,
	JSON_ERROR,
	REQUEST_ERROR,
	RESPONSE_ERROR,
	UNKNOWN_ERROR,
};

class LicenseManager final
{
public:
	LicenseManager(std::string LicenseServerEndpoint, bool bAllowOfflineProductUsage, std::string LicenseFileName) 
		: LicenseServerEndpoint(LicenseServerEndpoint), bAllowOfflineProductUsage(bAllowOfflineProductUsage), LicenseFileName(LicenseFileName)
	{
	}

	~LicenseManager()
	{
		if (DEFAULT_PUB_KEY_X != nullptr)
			delete[] DEFAULT_PUB_KEY_X;

		if (DEFAULT_PUB_KEY_Y != nullptr)
			delete[] DEFAULT_PUB_KEY_Y;

		if (PublicKeyX != nullptr)
			delete[] PublicKeyX;

		if (PublicKeyY != nullptr)
			delete[] PublicKeyY;
	}

	LicenseRequestStatus ActivateLicense(__in const bool bEncryptBody, __in const std::string& machine_id, __in const std::string& software_version);
	LicenseRequestStatus SendHeartbeat( __in const bool bEncryptBody);
	LicenseRequestStatus DeactivateLicense(__in const bool bEncryptBody);

    bool VerifyLicenseJWT_ES256(__in const std::string& token);

	void SetPubXY(__in const uint8_t* arrX, __in const uint8_t* arrY)
	{
		if (this->PublicKeyX == nullptr)
			this->PublicKeyX = new uint8_t[32]{ 0 };

		if (this->PublicKeyY == nullptr)
			this->PublicKeyY = new uint8_t[32]{ 0 };

		for (int i = 0; i < 32; i++)
		{
			this->PublicKeyX[i] = arrX[i];
			this->PublicKeyY[i] = arrY[i];
		}
	}

	const uint8_t* GetPubX() const { if (this->PublicKeyX == nullptr) return DEFAULT_PUB_KEY_X; else return this->PublicKeyX; }
	const uint8_t* GetPubY() const { if (this->PublicKeyY == nullptr) return DEFAULT_PUB_KEY_Y; else return this->PublicKeyY; }

	bool IsOfflineUsageAllowed() const { return bAllowOfflineProductUsage; }

	void SetLicenseToken(__in const std::string& jwtToken) { this->LicenseToken = jwtToken; }

	//std::string GetLeaseId() const noexcept { return this->LeaseId; }

	bool IsLeaseExpired() const noexcept { return GetTickCount64() >= this->LeaseExpiresAt; }

	static std::string GetHardwareID();

private:
	
	std::string LicenseToken;
	std::string LicenseFileName;
	std::string LicenseServerEndpoint;
	
	std::string LeaseId; //server gives this on successful activate
	uint64_t LeaseAcquireTime = 0;
	uint64_t LeaseExpiresAt = 0;

	bool bEncryptRequestBodies = false;
	bool bAllowOfflineProductUsage = false;

	static bool Sha256_CNG(__in const void* data, __in  const size_t len, __out std::vector<uint8_t>& out32);
	static bool DerEcdsaToP1363(__in  const uint8_t* der, __in  const size_t derLen, __out uint8_t out64[64]);

	BCRYPT_KEY_HANDLE import_es256_pubkey(__in std::vector<uint8_t>& x, __in std::vector<uint8_t>& y);

	uint8_t* PublicKeyX = nullptr; //32 length byte array
	uint8_t* PublicKeyY = nullptr; //32 length byte array

	//pinned DEFAULT public key -> replace with your public key X/Y from running `python dump_xy.py`  (we originally generate an ES256 keypair with openssl, then make a license.jwt file which embeds license details)
	// If you're just using default license from github, use the fixed key below, otherwise if you use your own license/keys use `SetPublicXY(your_x, your_y)`
	const uint8_t* DEFAULT_PUB_KEY_X = new uint8_t[32] { 0x0e,0x8a,0x31,0x1e,0x93,0x8d,0xc5,0x14,0x8e,0xb7,0x9c,0xb1,0x70,0xd9,0xca,0x35,0x3a,0x44,0x9b,0xb9,0xe1,0x65,0xa0,0xc3,0xfb,0xc6,0xb8,0x73,0x2b,0xd8,0xcd,0xc8 };
	const uint8_t* DEFAULT_PUB_KEY_Y = new uint8_t[32] { 0xfe,0x24,0xf5,0x84,0xeb,0x0e,0x20,0x39,0xd3,0x66,0xbe,0x76,0x14,0x3c,0xdb,0xc0,0xc1,0x97,0xca,0x96,0x83,0x55,0x99,0x0f,0xc1,0x18,0x5b,0x1d,0x7d,0x94,0x48,0x67 };
};
#include "../include/LicenseManager.hpp"

std::vector<uint8_t> LicenseManager::LoadPublicKeyContents(const std::string& pubKeyText)
{
	if (pubKeyText.empty())
	{
		throw std::runtime_error("Public key contents cannot be empty");
	}

	size_t pubKeyStart = pubKeyText.find("-----BEGIN PUBLIC KEY-----");
	size_t pubKeyEnd = pubKeyText.find("-----END PUBLIC KEY-----");

	if (pubKeyStart == std::string::npos || pubKeyEnd == std::string::npos || pubKeyEnd <= pubKeyStart)
	{
		throw std::runtime_error("Invalid PEM format for public key");
	}

	std::string b64Content = pubKeyText.substr(pubKeyStart + std::string("-----BEGIN PUBLIC KEY-----").size(), pubKeyEnd - (pubKeyStart + std::string("-----BEGIN PUBLIC KEY-----").size()));

	b64Content.erase(std::remove(b64Content.begin(), b64Content.end(), '\n'), b64Content.end());
	b64Content.erase(std::remove(b64Content.begin(), b64Content.end(), '\r'), b64Content.end());

	DWORD decodedLen = 0;

	if (!CryptStringToBinaryA(b64Content.c_str(), b64Content.size(), CRYPT_STRING_BASE64, nullptr, &decodedLen, nullptr, nullptr))
		throw std::runtime_error("CryptStringToBinaryA failed (len)");

	std::vector<uint8_t> b64DecodedPubKey(decodedLen); //X.509 SubjectPolicyKeyInfo

	if (!CryptStringToBinaryA(b64Content.c_str(), b64Content.size(), CRYPT_STRING_BASE64, b64DecodedPubKey.data(), &decodedLen, nullptr, nullptr))
		throw std::runtime_error("CryptStringToBinaryA failed");

	return b64DecodedPubKey;
}

BCRYPT_KEY_HANDLE LicenseManager::LoadRSAPublicKey(const std::vector<uint8_t> derData)
{
    CERT_PUBLIC_KEY_INFO* pubKeyInfo = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
    DWORD size = 0;

    const BYTE* pubKeyData = derData.data();

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pubKeyData, derData.size(), CRYPT_DECODE_ALLOC_FLAG, nullptr, &pubKeyInfo, &size)) 
	{
        throw std::runtime_error("Could not decode X509 pub key");
    }

    if (FAILED(CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,pubKeyInfo, 0,nullptr,&hKey))) 
	{
        LocalFree(pubKeyInfo);
        throw std::runtime_error("CryptImportPublicKeyInfoEx2 failed");
    }

    LocalFree(pubKeyInfo);
    return hKey;
}

bool LicenseManager::VerifySignature(BCRYPT_KEY_HANDLE hKey, const std::vector<uint8_t>& licenseData, const std::vector<uint8_t>& signature)
{
	if (!hKey || licenseData.empty() || signature.empty())
		throw std::invalid_argument("Invalid arguments provided for signature verification");

	NTSTATUS status = BCryptVerifySignature(
		hKey,
		nullptr,
		(PUCHAR)licenseData.data(),
		(ULONG)licenseData.size(),
		(PUCHAR)signature.data(),
		(ULONG)signature.size(),
		BCRYPT_PAD_PKCS1);

	return (status == 0);
}

bool LicenseManager::VerifyLicense()
{
	if (this->LicenseFileName.empty())
	{
		throw std::runtime_error("Key file path cannot be empty");
	}

	std::vector<uint8_t> publicKeyContents;

	try
	{
		publicKeyContents = LoadPublicKeyContents(std::string(this->RSAPubKeyPinned));
	}
	catch (const std::runtime_error& e)
	{
		throw std::runtime_error("Failed to load public key contents: " + std::string(e.what()));
	}

	if (publicKeyContents.empty())
	{
		throw std::runtime_error("Public key contents are empty");
	}

	try
	{
		BCRYPT_KEY_HANDLE hKey = LoadRSAPublicKey(publicKeyContents);

		if (hKey == nullptr)
		{
			throw std::runtime_error("Failed to load RSA public key");
		}

		return VerifySignature(hKey, publicKeyContents, this->LicenseSignature);
	}
	catch (const std::runtime_error& e)
	{
		throw std::runtime_error("Failed to load RSA public key: " + std::string(e.what()));
	}
}
#include "../include/LicenseManager.hpp"


/**
 * @brief Loads the public key contents from a PEM formatted string
 *
 * This function extracts the base64 encoded public key from a PEM formatted string.
 *
 * @param pubKeyText The PEM formatted public key text
 *
 * @return A vector of bytes containing the decoded public key
 *
 * @details The PEM format should contain "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----" markers.
 */ 
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

/**
 * @brief Loads the RSA public key from DER encoded data
 *
 * This function imports the RSA public key from DER encoded data.
 *
 * @param derData The DER encoded public key data
 *
 * @return A handle to the imported RSA public key
 *
 * @details The DER data should be in the format of X.509 SubjectPublicKeyInfo.
 */
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

/**
 * @brief Verifies the signature of the license data using the public key
 *
 * This function verifies the signature of the license data using the provided public key.
 *
 * @param hKey Handle to the RSA public key
 * @param licenseData The license data to verify
 * @param signature The signature to verify against the license data
 *
 * @return True if the signature is valid, false otherwise
 *
 * @details The licenseData should be the same as what was signed with the private key.
 */
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

/**
 * @brief Verifies the license using the public key
 *
 * This function verifies the license by loading the public key and checking the signature.
 *
 * @return True if the license is valid, false otherwise
 *
 * @details The license key should be loaded previously from a local file on disc
 *
 *  @example
 *
 * @usage
 * bool verified = LicenseManager->VerifyLicense();
 */
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

/**
 * @brief Checks license key online via HTTP(S)
 *
 * This function checks the local license against the license server
 * using a POST HTTP request. 
 *
 * @param bUsingEncryption If true, the HTTP post body will be encrypted
 *
 * @return True if the license is valid, false otherwise
 *
 * @details The license key should be loaded previously from a local file on disc
 *
 *  @example
 *
 * @usage
 * bool verified = LicenseManager->VerifyLicenseOnline(true); 
 */
bool LicenseManager::VerifyLicenseOnline(bool bUsingEncryption)
{
	if (this->LicenseServerEndpoint.empty() || this->LicenseKey.empty())
	{
		//throw std::runtime_error("License information cannot be empty @ VerifyLicenseOnline");
		return false;
	}

	std::vector<std::string> headers = 
	{
		"Content-Type: application/json",
		"Accept: application/json"
	};

	std::string postBody = "({\"action\": \"verify_license\", \"license_key\": " + this->LicenseKey + "})"; //can be encrypted further to reduce HTTP interception/sniffing
	
	if (bUsingEncryption) //encrypt HTTP post body
	{
		//todo: implement this, haven't decided on encryption method yet
	}

	HttpRequest requestInfo;
	requestInfo.url = this->LicenseServerEndpoint;
	requestInfo.requestHeaders = headers;
	requestInfo.body = postBody;

	if (!HttpClient::PostRequest(requestInfo))
	{
		return false; //failed to send request
	}

	if (requestInfo.responseText.empty() || std::find(requestInfo.responseHeaders.begin(), requestInfo.responseHeaders.end(), "HTTP/1.1 200 OK") == requestInfo.responseHeaders.end())
	{
		return false;
	}

	if (bUsingEncryption) //decrypt http response body
	{
		//todo: implement this, haven't decided on encryption method yet
	}

	return (requestInfo.responseText.find("\"status\": \"valid\"") != std::string::npos) ? true : false;
}
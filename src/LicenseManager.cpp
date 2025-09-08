#include "../include/LicenseManager.hpp"

/**
 * @brief Checks license key online via HTTP(S)
 *
 * This function checks the local license against the license server
 * using a POST HTTP request. 
 *
 * @param bEncryptBody If true, the HTTP post body will be encrypted
 *
 * @return True if the license is valid, false otherwise
 *
 * @details The license key should be loaded previously from a local file on disc
 *
 *  @example
 *
 * @usage
 * bool verified = LicenseManager->ActivateLicense(true, "machine-123", "1"); 
 */
LicenseRequestStatus LicenseManager::ActivateLicense(__in const bool bEncryptBody, __in const std::string& machine_id, __in const std::string& software_version)
{
	if (this->LicenseServerEndpoint.empty() || machine_id.empty() || software_version.empty())
	{
		//throw std::runtime_error("License information cannot be empty @ VerifyLicenseOnline");
		return LicenseRequestStatus::CALL_PARAMETER_ERROR;
	}

	std::vector<std::string> headers = 
	{
		"Content-Type: application/json",
		"Accept: application/json"
	};

	LicenseActivateRequest request;
	request.license_token = this->LicenseToken;
	request.machine_id = machine_id;
	request.software_version = software_version;

	json j;
	to_json(j, request);
		
	std::string requestBody = j.dump();

	if (bEncryptBody) //encrypt HTTP post body
	{
		char* buf_cpy = new char[requestBody.length() + 16] {0}; //block cipher pads to nearest 16 bytes, add extra buffer space or risk overflow
		memcpy(buf_cpy, requestBody.data(), requestBody.length());
		requestBody = CCryptMgrTwoFish::Encrypt(buf_cpy, requestBody.length());
	}

	HttpRequest requestInfo;
	requestInfo.url = this->LicenseServerEndpoint + "/v1/activate";
	requestInfo.requestHeaders = headers;
	requestInfo.body = requestBody;

	if (!HttpClient::PostRequest(requestInfo))
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "POST Request failed @ LicenseManager::ActivateLicense\n";
		OutputDebugStringA("POST Request failed @ LicenseManager::ActivateLicense\n");
#endif
		return LicenseRequestStatus::REQUEST_ERROR; //failed to send request
	}

	if (requestInfo.responseText.empty() || std::find(requestInfo.responseHeaders.begin(), requestInfo.responseHeaders.end(), "HTTP/1.1 200 OK\r\n") == requestInfo.responseHeaders.end())
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "POST Request had bad response @ LicenseManager::ActivateLicense\n";
		OutputDebugStringA("POST Request had bad response @ LicenseManager::ActivateLicense\n");
#endif
		return LicenseRequestStatus::RESPONSE_ERROR;
	}

	if (bEncryptBody) //decrypt http response body
	{
		char* buf_cpy = new char[requestInfo.responseText.length() + 16] {0}; //block cipher pads to nearest 16 bytes, add extra buffer space or risk overflow
		memcpy(buf_cpy, requestInfo.responseText.data(), requestInfo.responseText.length());
		requestInfo.responseText = CCryptMgrTwoFish::Decrypt(buf_cpy, requestInfo.responseText.length());
	}

	LicenseActivateResponse response;
	
	try
	{
		nlohmann::json jstxt = nlohmann::json::parse(requestInfo.responseText);
		jstxt.get_to(response);
	}
	catch (...)
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "Parsing license response JSON failed @ ActivateLicense" << std::endl;
		OutputDebugStringW(L"Parsing license response JSON failed @ ActivateLicense \n");
#endif

		return LicenseRequestStatus::JSON_ERROR;
	}

	this->LeaseId = response.lease_id;
	this->LeaseAcquireTime = GetTickCount64();
	this->LeaseExpiresAt = GetTickCount64() + (response.lease_expires_in * 1000);

	if (response.ok && !this->LeaseId.empty())
		return LicenseRequestStatus::OK;
	else if (this->IsLeaseExpired())
		return LicenseRequestStatus::LEASE_EXPIRED;
	else
		return LicenseRequestStatus::UNKNOWN_ERROR;
}

/**
 * @brief Logs off the leaseId associated with a license
 *
 * This function logs out from the leaseId using a POST HTTP request.
 *
 * @param bEncryptBody If true, the HTTP post body will be encrypted
 *
 * @return True if the request succeeded and the lease was signed off properly
 *
 * @details The ActivateLicense routine must be called prior to this, and have a valid `leaseId`
 *
 *  @example
 *
 * @usage
 * bool deactivate = LicenseManager->DeactivateLicense(bEncryptBody);
 */
LicenseRequestStatus LicenseManager::DeactivateLicense(__in const bool bEncryptBody)
{
	if (this->LicenseServerEndpoint.empty() || this->LeaseId.empty())
	{
		//throw std::runtime_error("License information cannot be empty @ VerifyLicenseOnline");
		return LicenseRequestStatus::CALL_PARAMETER_ERROR;
	}

	std::vector<std::string> headers =
	{
		"Content-Type: application/json",
		"Accept: application/json"
	};

	LicenseDeactivateRequest request;
	request.lease_id = this->LeaseId;

	json j;
	to_json(j, request);

	std::string requestBody = j.dump();

	if (bEncryptBody) //encrypt HTTP post body
	{
		char* buf_cpy = new char[requestBody.length() + 16] {0}; //block cipher pads to nearest 16 bytes, add extra buffer space or risk overflow
		memcpy(buf_cpy, requestBody.data(), requestBody.length());
		requestBody = CCryptMgrTwoFish::Encrypt(buf_cpy, requestBody.length());
	}

	HttpRequest requestInfo;
	requestInfo.url = this->LicenseServerEndpoint + "/v1/deactivate";
	requestInfo.requestHeaders = headers;
	requestInfo.body = requestBody;

	if (!HttpClient::PostRequest(requestInfo))
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "POST Request failed @ LicenseManager::DeactivateLicense\n";
		OutputDebugStringA("POST Request failed @ LicenseManager::DeactivateLicense\n");
#endif
		return LicenseRequestStatus::REQUEST_ERROR; //failed to send request
	}

	if (requestInfo.responseText.empty() || std::find(requestInfo.responseHeaders.begin(), requestInfo.responseHeaders.end(), "HTTP/1.1 200 OK\r\n") == requestInfo.responseHeaders.end())
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "POST Request had bad response @ LicenseManager::DeactivateLicense\n";
		OutputDebugStringA("POST Request had bad response @ LicenseManager::DeactivateLicense\n");
#endif
		return LicenseRequestStatus::RESPONSE_ERROR;
	}

	if (bEncryptBody) //decrypt http response body
	{
		char* buf_cpy = new char[requestInfo.responseText.length() + 16] {0}; //block cipher pads to nearest 16 bytes, add extra buffer space or risk overflow
		memcpy(buf_cpy, requestInfo.responseText.data(), requestInfo.responseText.length());
		requestInfo.responseText = CCryptMgrTwoFish::Decrypt(buf_cpy, requestInfo.responseText.length());
	}

	LicenseDeactivateResponse response;
	try
	{
		nlohmann::json jstxt = nlohmann::json::parse(requestInfo.responseText);
		jstxt.get_to(response);
	}
	catch (...)
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "Parsing license response JSON failed @ DeactivateLicense" << std::endl;
		OutputDebugStringW(L"Parsing license response JSON failed @ DeactivateLicense \n");
#endif

		return LicenseRequestStatus::JSON_ERROR;
	}

	bool success = response.ok;//requestInfo.responseText.substr(leaseId_pos + std::string("lease_id\":\"").size(), leaseId_end - leaseId_pos - std::string("lease_id\":\"").size());

	if (success)
		return LicenseRequestStatus::OK;
	else
		return LicenseRequestStatus::UNKNOWN_ERROR;
}

/**
 * @brief Sends keepalive request to the license server
 * 
 * @param bEncryptBody If true, the HTTP post body will be encrypted
 *
 * @return True if the request succeeded and the lease is valid
 *
 * @details The ActivateLicense routine must be called prior to this, and have a valid `leaseId`
 *
 * @usage
 * bool deactivate = LicenseManager->DeactivateLicense(bEncryptBody);
 */
LicenseRequestStatus LicenseManager::SendHeartbeat(__in const bool bEncryptBody)
{
	if (this->LicenseServerEndpoint.empty() || this->LeaseId.empty())
	{
		return LicenseRequestStatus::CALL_PARAMETER_ERROR;
	}

	HeartbeatRequest hb;
	hb.lease_id = this->LeaseId;

	std::string msg = "Lease id (HB):" + hb.lease_id;
	OutputDebugStringA(msg.c_str());

	std::vector<std::string> headers =
	{
		"Content-Type: application/json",
		"Accept: application/json"
	};

	json j;
	to_json(j, hb);

	std::string requestBody = j.dump();
	OutputDebugStringA(requestBody.c_str());
	HttpRequest request;
	request.url = LicenseServerEndpoint + "/v1/heartbeat";
	request.body = requestBody;
	request.cookie = "";
	request.requestHeaders = headers;

	if (bEncryptBody)
	{
		char* buf_cpy = new char[requestBody.length() + 16] {0}; //block cipher pads to nearest 16 bytes, add extra buffer space or risk overflow
		memcpy(buf_cpy, requestBody.data(), requestBody.length());
		requestBody = CCryptMgrTwoFish::Encrypt(buf_cpy, requestBody.length());
	}

	if (!HttpClient::PostRequest(request))
	{
#ifdef _LOGGING_ENABLED
		OutputDebugStringA("Failed to send heartbeat!\n");
#endif
		return LicenseRequestStatus::REQUEST_ERROR;
	}

	if (request.responseText.empty() || std::find(request.responseHeaders.begin(), request.responseHeaders.end(), "HTTP/1.1 200 OK\r\n") == request.responseHeaders.end())
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "POST Request had bad response @ LicenseManager::SendHeartbeat\n";
		OutputDebugStringA("POST Request had bad response @ LicenseManager::SendHeartbeat\n");
#endif
		return LicenseRequestStatus::RESPONSE_ERROR;
	}

	if (bEncryptBody) //decrypt http response body
	{
		char* buf_cpy = new char[request.responseText.length() + 16] {0}; //block cipher pads to nearest 16 bytes, add extra buffer space or risk overflow
		memcpy(buf_cpy, request.responseText.data(), request.responseText.length());
		request.responseText = CCryptMgrTwoFish::Decrypt(buf_cpy, request.responseText.length());
	}

	HeartbeatResponse response;

	try
	{
		nlohmann::json jstxt = nlohmann::json::parse(request.responseText);
		jstxt.get_to(response);
	}
	catch (...)
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "Parsing Heartbeat response JSON failed @ SendHeartbeat" << std::endl;
		OutputDebugStringW(L"Parsing Heartbeat response JSON failed  @ SendHeartbeat \n");
#endif

		return LicenseRequestStatus::JSON_ERROR;
	}

#ifdef _LOGGING_ENABLED
	std::string expirymsg = "Lease expires in: " + std::to_string(response.lease_expires_in) + "\n";
	std::string tickmsg = "GetTickCount64=" + std::to_string(GetTickCount64()) + "\n";
	OutputDebugStringA(expirymsg.c_str());
	OutputDebugStringA(tickmsg.c_str());
#endif
	if (response.ok && !this->IsLeaseExpired())
		return LicenseRequestStatus::OK;
	else if (this->IsLeaseExpired())
		return LicenseRequestStatus::LEASE_EXPIRED;
	else
		return LicenseRequestStatus::UNKNOWN_ERROR;
}


/**
 * @brief Fetches a BCRYPT_KEY_HANDLE for the pinned ECDSA public key
 *
 * @return  BCRYPT_KEY_HANDLE 
 *
 * @details You can use the python script below to extract x,y from your .pem file containing a public key

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import binascii, sys
pub = serialization.load_pem_public_key(open("vendor_pub.pem","rb").read())
nums = pub.public_numbers()
print("X=", binascii.hexlify(nums.x.to_bytes(32,'big')).decode())
print("Y=", binascii.hexlify(nums.y.to_bytes(32,'big')).decode())

 */
BCRYPT_KEY_HANDLE LicenseManager::import_es256_pubkey(__in std::vector<uint8_t>& x, __in std::vector<uint8_t>& y)
{
	uint8_t* _x = x.data();
	uint8_t* _y = y.data();

	NTSTATUS st;
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
	
	if (st) 
		throw std::runtime_error("ECDSA alg open failed");

	struct 
	{
		BCRYPT_ECCKEY_BLOB hdr;
		uint8_t xy[64];
	} blob{};

	blob.hdr.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
	blob.hdr.cbKey = 32;

	for (int i = 0; i < 32; i++)
	{
		blob.xy[i] = _x[i];
		blob.xy[32 + i] = _y[i];
	}

	BCRYPT_KEY_HANDLE hKey = nullptr;
	st = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &hKey, (PUCHAR)&blob, sizeof(blob), 0);
	BCryptCloseAlgorithmProvider(hAlg, 0);
	
	if (st) 
		throw std::runtime_error("ECDSA pub import failed");
	
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
bool LicenseManager::Sha256_CNG(const void* data, const size_t len, std::vector<uint8_t>& out32)
{
	if (data == nullptr || len == 0)
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "Parameter error @ Sha256_CNG\n";
#endif
		return false;
	}

	NTSTATUS st;
	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_HASH_HANDLE hHash = nullptr;

	DWORD cbData = 0, cbHashObject = 0, cbHash = 0;

	st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
	if (st) 
	{ 
#ifdef _LOGGING_ENABLED
		std::printf("BCryptOpenAlgorithmProvider: 0x%08X\n", st); 
#endif
    	return false; 
	}

	st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbData, 0);
	if (st || cbHashObject == 0)
	{ 
#ifdef _LOGGING_ENABLED
		std::printf("BCRYPT_OBJECT_LENGTH st=0x%08X len=%u\n", st, cbHashObject); 
#endif
		BCryptCloseAlgorithmProvider(hAlg, 0); 
		return false; 
	}

	st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbData, 0);
	
	if (st || cbHash != 32) 
	{ 
#ifdef _LOGGING_ENABLED
		std::printf("BCRYPT_HASH_LENGTH st=0x%08X len=%u\n", st, cbHash); 
#endif
		BCryptCloseAlgorithmProvider(hAlg, 0); 
		return false; 
	}

	std::vector<uint8_t> hashObject(cbHashObject);
	out32.assign(cbHash, 0);

	st = BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, nullptr, 0, 0);

	if (st) 
	{ 
#ifdef _LOGGING_ENABLED
		std::printf("BCryptCreateHash: 0x%08X (obj=%u)\n", st, cbHashObject); 
#endif
		BCryptCloseAlgorithmProvider(hAlg, 0); 
		return false; 
	}

	st = BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);

	if (st) 
	{ 
#ifdef _LOGGING_ENABLED
		std::printf("BCryptHashData: 0x%08X\n", st);
#endif
		BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); 
		return false; 
	}

	st = BCryptFinishHash(hHash, out32.data(), cbHash, 0);

	if (st) 
	{ 
#ifdef _LOGGING_ENABLED
		std::printf("BCryptFinishHash: 0x%08X\n", st); 
#endif
		BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); 
		return false; 
	}

	BCryptDestroyHash(hHash);
	BCryptCloseAlgorithmProvider(hAlg, 0);
	return true;
}

/**
 * @brief Verifies the signature of the license data using the public key
 *
 * This function verifies the signature of the license data using the provided public key.
 *
 * @param `token` base64 encoded JWT which contains license details
 *
 * @return True if the `token` properly matches the pinned keypairs
 *
 * @details 
 */
bool LicenseManager::VerifyLicenseJWT_ES256(__in const std::string& token) 
{
	if (token.empty())
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "token was empty @ VerifyLicenseJWT_ES256\n";
#endif
		return false;
	}

	size_t p1 = token.find('.');  	//split token into 3 parts, separated by each '.'

	if (p1 == std::string::npos) 
		return false;

	size_t p2 = token.find('.', p1 + 1);

	if (p2 == std::string::npos) 
		return false;

	std::string header_b64 = token.substr(0, p1);
	std::string payload_b64 = token.substr(p1 + 1, p2 - p1 - 1);
	std::string sig_b64 = token.substr(p2 + 1);

	std::string signingInput = header_b64 + "." + payload_b64; 	// get SHA-256 for ASCII "header.payload"
	std::vector<uint8_t> digest;

	if (!Sha256_CNG(signingInput.data(), signingInput.size(), digest))
		return false; // debug already printed

	std::vector<uint8_t> sig_der; 	// decode DER signature and convert to P-1363 r||s (64 bytes)

	try 
	{ 
		sig_der = License::b64urldec(sig_b64); 
	}
	catch (const std::runtime_error& ex) 
	{ 
#ifdef _LOGGING_ENABLED
		std::cerr << "b64urldec exception: " << ex.what() << std::endl;
#endif
		return false; 
	}
	
	uint8_t* X = (uint8_t*)GetPubX();
	uint8_t* Y = (uint8_t*)GetPubY();

	std::vector<uint8_t> PUB_X_vec(X, X + 32);
	std::vector<uint8_t> PUB_Y_vec(Y, Y + 32);

	uint8_t sig64[64]{ 0 }; //2x extra space
	
	if (!DerEcdsaToP1363(sig_der.data(), sig_der.size(), sig64))
		return false;

	BCRYPT_KEY_HANDLE hKey = nullptr; 

	try 
	{ 
		hKey = import_es256_pubkey(PUB_X_vec, PUB_Y_vec); 	// import public key and verify
	}
	catch (const std::runtime_error& ex) 
	{ 
#ifdef _LOGGING_ENABLED
		std::cerr << "import_es256_pubkey exception: " << ex.what() << std::endl;
#endif
		return false; 
	}

	NTSTATUS st = BCryptVerifySignature(hKey, nullptr,digest.data(), (ULONG)digest.size(),sig64, 64,0);
	BCryptDestroyKey(hKey);

	if (st != 0)
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "Invalid sig: BCryptVerifySignature did not pass\n";
#endif
		return false; //invalid sig
	}

	std::unique_ptr<License> license = std::make_unique<License>();
	License::LicenseCheckResult res = license->Check(header_b64, payload_b64);

	return (res.status == License::LicenseStatus::Ok);
}


// --- DER (ASN.1 SEQUENCE of two INTEGERs) -> P-1363 (r||s, 32+32) ---
bool LicenseManager::DerEcdsaToP1363(__in const uint8_t* der, __in const size_t derLen, __out uint8_t out64[64])
{
	// Minimal parser (assumes well-formed ECDSA DER from cryptography)
	size_t i = 0;
	if (derLen < 8 || der[i++] != 0x30) 
		return false;

	size_t seqLen = der[i++];

	if (seqLen & 0x80) 
	{
		size_t n = seqLen & 0x7F; if (n == 0 || i + n > derLen) 
			return false;

		seqLen = 0; 
		
		while (n--) 
		{ 
			seqLen = (seqLen << 8) | der[i++]; 
		}
	}
	
	if (i >= derLen || der[i++] != 0x02) 
		return false; // INTEGER r

	size_t rLen = der[i++];

	if (rLen & 0x80) 
	{
		size_t n = rLen & 0x7F; if (n == 0 || i + n > derLen) 
			return false;

		rLen = 0; 

		while (n--) 
		{ 
			rLen = (rLen << 8) | der[i++]; 
		}
	}

	if (i + rLen > derLen) 
		return false;

	const uint8_t* rPtr = der + i; i += rLen;

	if (i >= derLen || der[i++] != 0x02) 
		return false; // INTEGER s

	size_t sLen = der[i++];

	if (sLen & 0x80)
	{
		size_t n = sLen & 0x7F; if (n == 0 || i + n > derLen) 
			return false;
		sLen = 0; 

		while (n--) 
		{ 
			sLen = (sLen << 8) | der[i++];
		}
	}
	if (i + sLen > derLen) 
		return false;

	const uint8_t* sPtr = der + i;

	//strip optional leading 0x00 if present (DER INTEGER sign bit)
	auto strip = [](const uint8_t* p, size_t len, uint8_t* out32) 
	{
		while (len > 0 && *p == 0x00 && len > 32) 
		{
			++p; --len;
		} // if over 32, shave zeros

		if (len > 32) 
			return false;

		size_t pad = 32 - len;
		memset(out32, 0, pad);
		memcpy(out32 + pad, p, len);
		return true;
	};

	return strip(rPtr, rLen, out64 + 0) && strip(sPtr, sLen, out64 + 32);
}

/**
* @brief Fetches a pseudo-hardware ID for the machine
* @details This custom hardware ID is the PC username hyphenated with the machine GUID
*
* @return string object of the hardware id
*/
std::string LicenseManager::GetHardwareID()
{
	wchar_t buf[256]{ 0 };
	DWORD cb = sizeof(buf);
	LONG rc = RegGetValueW(HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Cryptography",
		L"MachineGuid",
		RRF_RT_REG_SZ, nullptr, buf, &cb);

	//Get computer name
	char computerName[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = sizeof(computerName) / sizeof(computerName[0]);

	if (!GetComputerNameA(computerName, &size))
	{
		strcpy_s(computerName, "UNKNOWN");
	}

	std::string result = std::string(computerName) + std::string("-") + Utility::ConvertWStringToString(buf);
	return result;
}

#include "../include/LicenseManager.hpp"

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
 * bool verified = LicenseManager->SendLicenseInfo(true); 
 */
bool LicenseManager::SendLicenseInfo(__in const bool bUsingEncryption)
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
		//todo: twofish encryption, will add soon
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
		//todo: add twofish encryption
	}

	return (requestInfo.responseText.find("\"status\": \"valid\"") != std::string::npos) ? true : false;
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

	//delete[] x;
	//delete[] y;

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
bool LicenseManager::Sha256_CNG(const void* data, size_t len, std::vector<uint8_t>& out32)
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
bool LicenseManager::DerEcdsaToP1363(const uint8_t* der, size_t derLen, uint8_t out64[64]) 
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
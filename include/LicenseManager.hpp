#pragma once
#include "HttpClient.hpp"
#include <windows.h>
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
		auto pubKeyEncrypted = make_encrypted("-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjvVM0FPoNZEXm6I0LLrXW26f3MuUKNaTcrtLEzm9G3Xh12krtLLzJovw9ThHiY7GMe72V0VVERMX7/LoqW5xai0hGoEcO975JlO5zVZ0XKuXiFjgiBAaYHXrAIqG69MMuZO4D4nLnayXV/tZUFYRX4P0zH1E4xigln1dluQ5F93ZnD+IneCOOlcJp1g/SZXMwlIE+H9ADVSdYlmzKKGd6+t26L2HeX854gVQuxAX8pbY9Sd2FR26QZi7yS4w9QdZd/6ATNjfT1UdpFRUwDAQJBru/MZIYm2bk3RWbcPG/IuPQqNpjggvTxmiFzNaDLoOrB3yt3UTOT4qaJTp2ohqPwIDAQAB-----END PUBLIC KEY-----");
		RSAPubKeyPinned = new char[pubKeyEncrypted.getSize() + 1];
		pubKeyEncrypted.decrypt(RSAPubKeyPinned); //store the encrypted public key in a string
	}

	~LicenseManager()
	{
		if (RSAPubKeyPinned != nullptr)
			delete[] RSAPubKeyPinned;
	}

	bool VerifyLicense();

private:
	
	char* RSAPubKeyPinned = nullptr;

	std::vector<uint8_t> LicenseSignature; //grabbed from file or registry or w/e
	std::string LicenseFileName;

	std::string LicenseServerEndpoint;

	bool bAllowOfflineProductUsage = false;

	std::vector<uint8_t> LoadPublicKeyContents(const std::string& pubKeyText);
	BCRYPT_KEY_HANDLE LoadRSAPublicKey(const std::vector<uint8_t> derData);
	bool VerifySignature(BCRYPT_KEY_HANDLE hKey, const std::vector<uint8_t>& licenseData, const std::vector<uint8_t>& signature);
};

/*
 Priv key to match above pub key:
-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAjvVM0FPoNZEXm6I0LLrXW26f3MuUKNaTcrtLEzm9G3Xh12kr
tLLzJovw9ThHiY7GMe72V0VVERMX7/LoqW5xai0hGoEcO975JlO5zVZ0XKuXiFjg
iBAaYHXrAIqG69MMuZO4D4nLnayXV/tZUFYRX4P0zH1E4xigln1dluQ5F93ZnD+I
neCOOlcJp1g/SZXMwlIE+H9ADVSdYlmzKKGd6+t26L2HeX854gVQuxAX8pbY9Sd2
FR26QZi7yS4w9QdZd/6ATNjfT1UdpFRUwDAQJBru/MZIYm2bk3RWbcPG/IuPQqNp
jggvTxmiFzNaDLoOrB3yt3UTOT4qaJTp2ohqPwIDAQABAoIBABgeeLw5O9c1yIbg
ge7+AvGRI3WL/044jZ3wzYTL3ATzCYxfWRlei7l4KMommaMyrGumRneI4gZEc2hv
UiOr14SzYn9nQw0y3FREEff72xv7c1B0tkUeemTF4EUyGftVmzMAIjC07d6HTO1y
Iap1Ku8zgyyxAdtSv11Ef3LCxIMrD/KbPc+R4SU85rlrdhzTizOicU3W7uyVcm2H
shhrBtS5YqU2M2HXHQmMXTDUZ9RdGcNcAaF9tMgZnLKM1gNBxa0L5vTCqc2Wlf0t
Zy3m0u1BZ5SMAvuBy6TVHiFyhhcf05We0fIqJUrJ6mew0N2JJfD4QFLKvDKB10j7
dfBcHAECgYEA6pSlcg8J+naTl83OQdbccQJWqToVFT2Iu4VgqE5v/+0CO2zGgfD8
PVpVJE5dE41HEZBPqI8TrV6oKUgO7MRjTl68sff3dRqXDiBaohwSf1gdE+EscwiM
NlN9MmCRzI/Ix3RXzl9IJHkO2Qj1pG5FHQizZ5ijdSuBNc+mKt6uUgECgYEAnAL3
i87RAQUTh+4YKKT/I+DSGgGw7XHnRY85F3HdW8jeFltG3JkloysRX/VJZvZdgWpn
rJyswvbXjIEKUsA9OTkgAL4wJPNH1EvYEl7jgKJmz6X4obVctB3j2v3UbbvUVkcM
/O8T9eJmoLuOtUN3VzramJI19jDKXZ9UIj5qPD8CgYEAnOpoLX7v3tH48r/hq9sN
RK8ax0KqHbY2w7F5sbweYWTqbFPcCcnpASVu9MVSr6R+mLoe/xMOR5edB1hDW5AX
GbJ3qNjFeFkcGH/+AJikqviHIugqMpzSJfj9M3izrtGzrfAeWFcWTAeKrhW3M5Hr
u3s5fx/0n4lFenh3oA+rLgECgYAAhq4JBaiExVycf7wLHwtRNqfeuJS9KD4saOA7
aQHjFllRX/tsMQQEede0KCKYO0pzbkVtOpYGjkiJy8GaJ9XNBJlMB1goN73NRHg1
D6bavzFzj8631OG8JcGn8mUt/Y0owVKU48WAdcP81MUVbWXQoH0uOIgADYgRKsFg
4C8BhwJ/L3uKfSA/jjmXC4dskE9VtE0nswINsOveUCO/+ZVUwGL3jd7gYQiMzoVu
/Etn9qb+Q/lXdilFT3lbVvaBYWZImZsBo/iGhJOE/lfX0YRzI7yUg2/UtfCZRjUh
AIxHPwy21ayTXuGbssBXbT8LBVOhe+JT6yq39XFEPkNentIwnw==
-----END RSA PRIVATE KEY-----

*/
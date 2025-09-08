#pragma once
#include <string>
#include <optional>
#include <vector>
#include <stdint.h>
#include "json/json.hpp"
#include <unordered_set>

class License final
{
public:
	enum class LicenseStatus
	{
		Ok = 0,
		MalformedToken,
		BadBase64,
		BadJson,
		WrongAlgOrTyp,
		WrongIssuer,
		WrongProduct,
		InvalidPlan,
		InvalidSeats,
		MissingRequiredField,
		Expired,
		NotYetValid,
		ClockSkew,
		InvalidSignature,
		JtiReusedOrRevoked,
	};

	struct LicenseHeader
	{
		std::string alg;
		std::string kid;
		std::string typ;
	};

	struct LicenseClaims
	{
		std::string iss;
		std::string product;
		std::string org;
		std::string plan;                   // "floating" | "named-device" | "site"
		uint64_t seats;                     // 0 for "site"
		std::vector<std::string> features;  // e.g. ["rules-signing","gpu-gate","webhook"]
		int64_t iat = 0;                    // seconds since epoch (UTC)
		int64_t exp = 0;                    // seconds since epoch (UTC)
		std::string jti;
	};

	struct LicenseCheckResult
	{
		LicenseStatus status = LicenseStatus::MalformedToken;
		LicenseHeader header{};
		LicenseClaims claims{};
	};

	inline LicenseStatus parseHeader(const std::string& headerJson, LicenseHeader& out) 
	{
		using nlohmann::json;
		auto j = json::parse(headerJson, nullptr,false);

		if (j.is_discarded() || !j.is_object()) 
			return LicenseStatus::BadJson;

		if (!j.contains("alg") || !j.contains("typ")) 
			return LicenseStatus::MissingRequiredField;

		out.alg = j.value("alg", "");
		out.typ = j.value("typ", "");
		out.kid = j.value("kid", ""); // optional but we emit it

		if (out.alg != "ES256" || out.typ != "JWT") 
			return LicenseStatus::WrongAlgOrTyp;
		
		return LicenseStatus::Ok;
	}

	inline LicenseStatus parsePayload(const std::string& payloadJson, LicenseClaims& c) 
	{
		using nlohmann::json;

		auto j = json::parse(payloadJson, nullptr, false);

		if (j.is_discarded() || !j.is_object()) 
			return LicenseStatus::BadJson;

		auto req = [&](const char* k) 
		{ 
				return j.contains(k) && !j[k].is_null(); 
		};

		//required string fields
		if (!req("iss") || !req("product") || !req("org") || !req("plan") || !req("jti"))
			return LicenseStatus::MissingRequiredField;
		
		c.iss = j.value("iss", "");
		c.product = j.value("product", "");
		c.org = j.value("org", "");
		c.plan = j.value("plan", "");
		c.jti = j.value("jti", "");

		//iat/exp required numbers
		if (!req("iat") || !req("exp")) 
			return LicenseStatus::MissingRequiredField;

		c.iat = j["iat"].is_number_integer() ? j["iat"].get<int64_t>() : 0;
		c.exp = j["exp"].is_number_integer() ? j["exp"].get<int64_t>() : 0;

		//optional array
		c.features.clear();

		if (j.contains("features") && j["features"].is_array()) 
		{
			for (auto& f : j["features"]) 
				if (f.is_string()) 
				    c.features.emplace_back(f.get<std::string>());
		}

		//seats can be null
		if (j.contains("seats") && !j["seats"].is_null()) 
		{
			if (!j["seats"].is_number_integer()) 
				return LicenseStatus::InvalidSeats;
			
			c.seats = j["seats"].get<int64_t>();
		}
		else 
		{
			c.seats = 1;
		}

		// Semantic constraints from your signer:
		if (c.iss != "UltimateDRM") 
			return LicenseStatus::WrongIssuer;

		if (c.product != "UltimateDRM/agent") 
			return LicenseStatus::WrongProduct;

		static const std::unordered_set<std::string> kPlans = { "trial", "monthly","ongoing", "infinite" };

		if (!kPlans.count(c.plan)) 
			return LicenseStatus::InvalidPlan;

		//seats rule: null for "site", present & >=1 otherwise
		if (c.plan == "trial") 
		{
			if (c.seats != 1) 
				return LicenseStatus::InvalidSeats;
		}
		else 
		{
			if (c.seats == 0) 
				return LicenseStatus::InvalidSeats;
		}

		return LicenseStatus::Ok;
	}

	static std::string b64url_pad(__inout std::string s)
	{
		while (s.size() % 4)
			s.push_back('=');

		for (auto& c : s)
			if (c == '-')
				c = '+';

		for (auto& c : s)
			if (c == '_')
				c = '/';

		return s;
	}

	static std::vector<uint8_t> b64urldec(__in const std::string& in)
	{
		std::string stdb64 = b64url_pad(in);
		DWORD need = 0;

		if (!CryptStringToBinaryA(stdb64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &need, nullptr, nullptr))
			throw std::runtime_error("CryptStringToBinaryA failed: throwing exception");

		std::vector<uint8_t> out(need);
		if (!CryptStringToBinaryA(stdb64.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &need, nullptr, nullptr))
			throw std::runtime_error("CryptStringToBinaryA failed: throwing exception");

		out.resize(need);
		return out;
	}

	LicenseCheckResult Check(__in const std::string& header_b64, __in const std::string& payload_b64)
	{
		std::string headerJson, payloadJson;
		LicenseCheckResult licenseResult;

		try
		{
			auto decodedHeader = b64urldec(header_b64);
			headerJson.assign(decodedHeader.begin(), decodedHeader.end());
		}
		catch (...)
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Invalid b64 header\n";
#endif
			licenseResult.status = License::LicenseStatus::BadBase64;
			return licenseResult;
		}

		if (License::parseHeader(headerJson, licenseResult.header) != License::LicenseStatus::Ok)
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Invalid license header: License::parseHeader did not pass\n";
#endif
			licenseResult.status = License::LicenseStatus::BadJson;
			return licenseResult;
		}

		try
		{
			auto praw = b64urldec(payload_b64);
			payloadJson.assign(reinterpret_cast<const char*>(praw.data()), praw.size());
		}
		catch (...)
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Invalid b64 payload\n";
#endif
			licenseResult.status = License::LicenseStatus::BadBase64;
			return licenseResult;
		}

		if (License::parsePayload(payloadJson, licenseResult.claims) != License::LicenseStatus::Ok)
		{
#ifdef _LOGGING_ENABLED
			std::cerr << "Invalid license payload: License::parsePayload did not pass\n";
#endif
			licenseResult.status = License::LicenseStatus::BadJson;
			return licenseResult;
		}

		const int64_t now = static_cast<int64_t>(std::time(nullptr));
		constexpr int64_t kSkew = 300; // 5 minutes
		if (licenseResult.claims.exp <= now - kSkew)
		{
			licenseResult.status = License::LicenseStatus::Expired;
			return licenseResult;
		}
		//iat = 1756694840
		//now = 1756683456
		if (licenseResult.claims.iat > now + kSkew)
		{
			licenseResult.status = License::LicenseStatus::ClockSkew;
			return licenseResult;
		}

		if (licenseResult.claims.iat > licenseResult.claims.exp)
		{
			licenseResult.status = License::LicenseStatus::BadJson;
			return licenseResult;
		}

		// if (IsJtiRevokedOrSeen(R.claims.jti)) { R.status = LicenseStatus::JtiReusedOrRevoked; return R; }

		licenseResult.status = License::LicenseStatus::Ok;
		return licenseResult;
	}

	inline bool IsJtiRevokedOrSeen(const std::string& jti) 
	{
		// TODO: look up in your store
		return false;
	}
};

using json = nlohmann::json;

struct LicenseActivateRequest
{
	std::string license_token;
	std::string machine_id;
	std::string software_version;
};

struct LicenseDeactivateRequest
{
	std::string lease_id;
};

struct HeartbeatRequest
{
	std::string lease_id;
};

struct LicenseActivateResponse
{
	bool ok;
	std::string lease_id;
	uint64_t lease_expires_in;
};

struct LicenseDeactivateResponse
{
	bool ok;
};

struct HeartbeatResponse
{
	bool ok;
	uint64_t lease_expires_in;
};

static void to_json(json& j, const LicenseActivateRequest& request)
{
	j = json{
			{"license_token", request.license_token},
			{"machine_id", request.machine_id},
			{"software_version", request.software_version},
	};
}

static inline void from_json(const nlohmann::json& j, LicenseActivateRequest& request)
{
	if (j.contains("license_token") && !j["license_token"].is_null())
		j["license_token"].get_to(request.license_token);

	if (j.contains("machine_id") && !j["machine_id"].is_null())
		j["machine_id"].get_to(request.machine_id);

	if (j.contains("software_version") && !j["software_version"].is_null())
		j["software_version"].get_to(request.software_version);
}

static void to_json(json& j, const LicenseActivateResponse& response)
{
	j = json{
			{"ok", response.ok},
			{"lease_id", response.lease_id},
			{"lease_expires_in", response.lease_expires_in},
	};
}

static void from_json(const nlohmann::json& j, LicenseActivateResponse& response)
{
	j.at("ok").get_to(response.ok);
	j.at("lease_id").get_to(response.lease_id);
	j.at("lease_expires_in").get_to(response.lease_expires_in);
}

static void to_json(json& j, const LicenseDeactivateRequest& request)
{
	j = json{
			{"lease_id", request.lease_id}
	};
}

static inline void from_json(const nlohmann::json& j, LicenseDeactivateRequest& request)
{
	if (j.contains("lease_id") && !j["lease_id"].is_null())
		j["lease_id"].get_to(request.lease_id);
}

static void to_json(json& j, const LicenseDeactivateResponse& response)
{
	j = json{
			{"ok", response.ok}
	};
}

static void from_json(const nlohmann::json& j, LicenseDeactivateResponse& response)
{
	j.at("ok").get_to(response.ok);
}

static void to_json(json& j, const HeartbeatRequest& request)
{
	j = json{
			{"lease_id", request.lease_id}
	};
}

static inline void from_json(const nlohmann::json& j, HeartbeatRequest& request)
{
	if (j.contains("lease_id") && !j["lease_id"].is_null())
		j["lease_id"].get_to(request.lease_id);
}

static void to_json(json& j, const HeartbeatResponse& response)
{
	j = json{ {"ok", response.ok}, {"lease_expires_in", response.lease_expires_in}
	};
}

static void from_json(const nlohmann::json& j, HeartbeatResponse& response)
{
	j.at("ok").get_to(response.ok);
	j.at("lease_expires_in").get_to(response.lease_expires_in);
}
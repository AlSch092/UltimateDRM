//By AlSch092 @ Github, part of UltimateDRM project
#pragma once

#include <list>
#include <stdexcept>

//Settings don't come in a .ini or .cfg file as we don't want end-users modifying program flow on compiled releases
class DRMSettings final
{
public:

	static DRMSettings* CreateInstance(
		const std::string LicenseServerEndpoint,
		const bool bShutdownOnViolation,
		const bool bAllowOfflineUsage,
		const bool bUsingLicensing,
		const bool bRequireCodeSigning,
		const bool bEnforceSecureBoot,
		const bool bEnforceDSE,
		const bool bEnforceNoKDbg,
		const bool bUseAntiDebugging,
		const bool bCheckIntegrity,
		const bool bCheckHypervisor,
		const bool bRequireRunAsAdministrator,
		const std::list<std::wstring> lAllowedParentNames
	)
	{
		DRMSettings* Instance = new DRMSettings(
			LicenseServerEndpoint,
			bShutdownOnViolation,
			bAllowOfflineUsage,
			bUsingLicensing,
			bRequireCodeSigning,
			bEnforceSecureBoot,
			bEnforceDSE,
			bEnforceNoKDbg,
			bUseAntiDebugging,
			bCheckIntegrity,
			bCheckHypervisor,
			bRequireRunAsAdministrator,
			lAllowedParentNames
			);

		return Instance;
	}

	DRMSettings(const DRMSettings&) = delete; //prevent copying
	DRMSettings& operator=(const DRMSettings&) = delete;
	
	std::string LicenseServerEndpoint;
	bool bShutdownOnViolation = false;
	bool bAllowOfflineUsage = true;
	bool bRequireCodeSigning = true;
	bool bEnforceSecureBoot = true;
	bool bEnforceDSE = true;
	bool bEnforceNoKDbg = true;
	bool bCheckHypervisor = true;
	bool bUseAntiDebugging = true;
	bool bCheckIntegrity = true;
	bool bRequireRunAsAdministrator = false;

	bool bUsingLicensing;

	std::list<std::wstring> lAllowedParentNames;

	DRMSettings(
		const std::string LicenseServerEndpoint,
		const bool bShutdownOnViolation,
		const bool bAllowOfflineUsage,
		const bool bUsingLicensing,
		const bool bRequireCodeSigning,
		const bool bEnforceSecureBoot,
		const bool bEnforceDSE,
		const bool bEnforceNoKDbg,
		const bool bUseAntiDebugging,
		const bool bCheckIntegrity,
		const bool bCheckHypervisor,
		const bool bRequireRunAsAdministrator,
		const std::list<std::wstring> lAllowedParentNames)
		: LicenseServerEndpoint(LicenseServerEndpoint), bShutdownOnViolation(bShutdownOnViolation), bAllowOfflineUsage(bAllowOfflineUsage), bUsingLicensing(bUsingLicensing), bRequireCodeSigning(bRequireCodeSigning), bEnforceSecureBoot(bEnforceSecureBoot), bEnforceDSE(bEnforceDSE), bEnforceNoKDbg(bEnforceNoKDbg), bUseAntiDebugging(bUseAntiDebugging), bCheckIntegrity(bCheckIntegrity), bCheckHypervisor(bCheckHypervisor), bRequireRunAsAdministrator(bRequireRunAsAdministrator), lAllowedParentNames(lAllowedParentNames)
	{
	}
};
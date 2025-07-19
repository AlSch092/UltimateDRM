// UltimateDRM.cpp : Defines the functions for the static library.
// C++ 14 is being used to help compatability with older projects

#include "../include/DRM.hpp"
#include "../include/Settings.hpp"
#include "../include/MapProtectedClass.hpp"
#include "../include/NAuthenticode.hpp"
#include "../include/remap.hpp"
#include "../include/Logger.hpp"
#include "../include/LicenseManager.hpp"

#pragma comment(linker, "/ALIGN:0x10000") //for section remapping

Settings* Settings::Instance = nullptr; //singleton static instance decl to avoid compilation errors

/*
	The DRM class provides runtime DRM through integrity checks and licensing
	** There is no such thing as an 'uncrackable DRM', and allowing offline product usage makes things much tougher to enforce **
	** Any parts of code which run on the client side will never be tamper-proof **

	This class is designed to handle a single module. The protected program should include this .lib and .hpp and use the DRM class
*/
struct DRM::Impl
{
	ProtectedMemory* ProtectedSettings = nullptr;

	Impl(const bool bAllowOfflineUsage, 
		const bool bUsingLicensing, 
		const bool bCheckHypervisor, 
		const std::list<std::wstring> lAllowedParents)
	{
		this->ProtectedSettings = new ProtectedMemory(sizeof(Settings));

		const bool bEnforceSecureBoot = true;
		const bool bEnforceDSE = true;
		const bool bEnforceNoKDbg = true;
		const bool bUseAntiDebugging = true;
		const bool bCheckIntegrity = true;
		const bool bRequireRunAsAdministrator = false;

		Settings::Instance = this->ProtectedSettings->Construct<Settings>(
			bAllowOfflineUsage,
			bUsingLicensing,
			bEnforceSecureBoot,
			bEnforceDSE,
			bEnforceNoKDbg,
			bUseAntiDebugging,
			bCheckIntegrity,
			bCheckHypervisor,
			bRequireRunAsAdministrator,
			lAllowedParents);

		try
		{
			this->ProtectedSettings->Protect();
		}
		catch (const std::runtime_error& ex)
		{
			throw std::runtime_error("Could not create protected memory for DRM settings");
		}
	}

	~Impl() 
	{
		 this->ProtectedSettings->Reset();
		 delete this->ProtectedSettings;
	}
};

DRM::DRM(const bool bAllowOfflineUsage, const bool bUsingLicensing, const bool bCheckHypervisor, const std::list<std::wstring> lAllowedParents) : pImpl(new DRM::Impl(bAllowOfflineUsage, bUsingLicensing, bCheckHypervisor, lAllowedParents))
{
}

bool DRM::Protect()
{
	//add other integrity check setup here...

#ifndef _DEBUG
	if (Settings::Instance->bCheckIntegrity)
	{
		if (!RmpRemapImage((ULONG_PTR)GetModuleHandle(NULL)))
		{
			throw std::runtime_error("Failed to remap program sections");
		}
	}
#endif

	return true;
}
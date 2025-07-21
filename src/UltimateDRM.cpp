// UltimateDRM.cpp : Defines the functions for the static library.
// C++ 14 is being used to help compatability with older projects
// This project aims to take the good parts of UltimateAnticheat while improving the parts which were messy or implemented poorly

#include "../include/DRM.hpp"
#include "../include/Settings.hpp"
#include "../include/MapProtectedClass.hpp"
#include "../include/remap.hpp"
#include "../include/Logger.hpp"
#include "../include/LicenseManager.hpp"
#include "../include/Integrity.hpp"

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

	std::unique_ptr<Integrity> IntegrityChecker = nullptr; //integrity checker for the current process

	std::unique_ptr<LicenseManager> LicenseManagerPtr = nullptr; //license manager for the current process

	Impl(const std::string& LicenseServerEndpoint,
		const bool bAllowOfflineUsage, 
		const bool bUsingLicensing, 
		const bool bCheckHypervisor,
		const bool bRequireCodeSigning,
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
			bRequireCodeSigning,
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
			this->ProtectedSettings->Protect(); //remap the protected memory to prevent tampering (this doesn't call DRM::Protect)
		}
		catch (const std::runtime_error& ex)
		{
			throw std::runtime_error("Could not create protected memory for DRM settings");
		}

		try
		{
			if (Settings::Instance->bUsingLicensing)
			{
				this->LicenseManagerPtr = std::make_unique<LicenseManager>(LicenseServerEndpoint, Settings::Instance->bAllowOfflineUsage, "license.json");
			}

			this->IntegrityChecker = std::make_unique<Integrity>();
		}
		catch (const std::runtime_error& ex)
		{
			throw std::runtime_error("Could not initialize smart ptrs: " + std::string(ex.what()));
		}
	}

	~Impl() 
	{
		 this->ProtectedSettings->Reset();
		 delete this->ProtectedSettings;
	}
};

DRM::DRM(const std::string& LicenseServerEndpoint, const bool bAllowOfflineUsage, const bool bUsingLicensing, const bool bCheckHypervisor, const bool bRequireCodeSigning, const std::list<std::wstring> lAllowedParents)
	: pImpl(new DRM::Impl(LicenseServerEndpoint, bAllowOfflineUsage, bUsingLicensing, bCheckHypervisor, bRequireCodeSigning, lAllowedParents))
{
}


/**
 * @brief Launches the DRM protection checks
 *
 * This function launches various DRM protections based on the settings provided
 *
 * @return true/false if the checks ran successfully
 *
 * @details If return false, one of the checks failed, and the program cannot continue running since security cannot be guaranteed
 *
 *  @example DRMTest.cpp
 *
 * @usage
 * try { drm->Protect(); } catch(std::runtime_error& ex) { std::cerr << "DRM protection failed: " << ex.what() << std::endl; }
 */
bool DRM::Protect()
{
	if (Settings::Instance->bUsingLicensing)
	{
		if (this->pImpl->LicenseManagerPtr == nullptr)
		{
			throw std::runtime_error("LicenseManagerPtr is not initialized");
		}

		if (!this->pImpl->LicenseManagerPtr->VerifyLicense())
		{
			throw std::runtime_error("License verification failed");
		}
	}

	if (!Settings::Instance->allowedParents.empty())
	{
		bool verifiedParent = false;
		DWORD parentPid = Process::GetParentProcessId();

		for (std::wstring parent : Settings::Instance->allowedParents) 	//check parent process name, then check code signing cert
		{
			std::wstring parentProcName = Process::GetProcessName(parentPid);

			if (parentProcName != parent)
				continue;

			std::wstring parentProcDirectory = Services::GetProcessDirectoryW(parentPid);

			if (Settings::Instance->bRequireCodeSigning)
			{
				if (!Authenticode::HasSignature(std::wstring(parentProcDirectory + parentProcName).c_str(), TRUE))
				{
					throw std::runtime_error("Parent process was not code signed, possible imposter");
				}
				else
				{
					verifiedParent = true;
					break;
				}				
			}
			else
			{
				verifiedParent = true;
				break; //if we don't require code signing, just check the process name
			}

		}
	}

	if (Settings::Instance->bCheckIntegrity)
	{
#ifndef _DEBUG
		if (!RmpRemapImage((ULONG_PTR)GetModuleHandle(NULL)))
		{
			throw std::runtime_error("Failed to remap program sections");
		}
#endif

		uint64_t moduleChecksum = Integrity::CalculateChecksum(GetModuleHandle(NULL));

		if (moduleChecksum == 0)
		{
			throw std::runtime_error("Failed to calculate module checksum");
		}

		this->pImpl->IntegrityChecker->StoreModuleChecksum(GetModuleHandle(NULL), moduleChecksum); //tested and working


	}

	if (Settings::Instance->bRequireCodeSigning)
	{
		std::wstring currentProcName = Process::GetProcessName(GetCurrentProcessId());
		std::wstring processDirectory = Services::GetProcessDirectoryW(GetCurrentProcessId());
		std::wstring fullProcessPath = (processDirectory + currentProcName);

		if (!currentProcName.empty() && !processDirectory.empty())
		{
			std::wcout << L"Checking code signature of: " << fullProcessPath << std::endl;

			if (!Authenticode::HasSignature(fullProcessPath.c_str(), TRUE)) //check if the current process has a valid signature
			{
				return false;
			}
		}
		else
		{
			throw std::runtime_error("Failed to get current process name");
		}
	}

	return true;
}
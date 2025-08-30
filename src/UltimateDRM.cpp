// UltimateDRM.cpp : Defines the functions for the static library.
// C++ 14 is being used to help compatability with older projects
// By AlSch092 @ Github

#ifdef _M_X64
#include "../include/remap.hpp"
#endif
#include "../include/UltimateDRM.hpp" //keep majority of includes in this .cpp instead of .hpp to hide implementation details from lib user and reduce number of header files needing to distribute
#include "../include/DRMSettings.hpp"
#include "../include/MapProtectedClass.hpp"
#include "../include/Logger.hpp"
#include "../include/LicenseManager.hpp"
#include "../include/Integrity.hpp"
#include "../include/Definitions.hpp"
#include "../include/AntiDebug/DebuggerDetections.hpp"
#include "../include/DRMException.hpp"

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved);
LONG WINAPI g_VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);

EXTERN_C
#ifdef _M_X64
#pragma comment(linker, "/ALIGN:0x10000") //for section remapping
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#pragma const_seg (".CRT$XLB") //store tls callback inside the correct section
const
PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_tls_callback")
#pragma data_seg(push, old, ".CRT$XLB")
EXTERN_C __declspec(allocate(".CRT$XLB"))  PIMAGE_TLS_CALLBACK tls_callback = TLSCallback;
#pragma data_seg(pop, old)
#endif

/*
	* The DRM class provides runtime DRM through integrity checks and licensing
	*  *There is no such thing as an 'uncrackable DRM', and allowing offline product usage makes things much tougher to enforce *
	* 
	* The protected program should include this .lib and .hpp and use the DRM class
*/
struct UltimateDRM::Impl
{
	ProtectedMemory* ProtectedSettings = nullptr;

	std::unique_ptr<Integrity> IntegrityChecker = nullptr; //integrity checker for the current process

	std::unique_ptr<LicenseManager> LicenseManagerPtr = nullptr; //license manager for the current process

	std::unique_ptr<DebuggerDetections> AntiDebugger = nullptr; //debugger detections for the current process

	DRMSettings* Config = nullptr;

	Impl(DRMSettings* s)
	{
		this->ProtectedSettings = new ProtectedMemory(sizeof(DRMSettings));

		//since we're mapping our settings instance into protected memory, re-make an object with the same options that the user provided
		this->Config = this->ProtectedSettings->Construct<DRMSettings>( 
			s->LicenseServerEndpoint,
			s->bShutdownOnViolation,
			s->bAllowOfflineUsage,
			s->bUsingLicensing,
			s->bRequireCodeSigning,
			s->bEnforceSecureBoot,
			s->bEnforceDSE,
			s->bEnforceNoKDbg,
			s->bUseAntiDebugging,
			s->bCheckIntegrity,
			s->bCheckHypervisor,
			s->bRequireRunAsAdministrator,
			s->lAllowedParentNames);

		try
		{
			this->ProtectedSettings->Protect(); //remap the protected memory to prevent write-tampering
		}
		catch (const std::runtime_error& ex)
		{
			throw std::runtime_error("Could not create protected memory for DRM settings");
		}

		try
		{
			if (this->Config->bUsingLicensing)
			{
				this->LicenseManagerPtr = std::make_unique<LicenseManager>(this->Config->LicenseServerEndpoint, this->Config->bAllowOfflineUsage, "license.json");
			}

			this->IntegrityChecker = std::make_unique<Integrity>(this->Config);
		}
		catch (const std::bad_alloc&  ex)
		{
			throw std::runtime_error("Could not initialize smart ptrs: " + std::string(ex.what()));
		}

#ifndef _DEBUG
		if (this->Config->bUseAntiDebugging)
		{
			try
			{
				this->AntiDebugger = std::make_unique<DebuggerDetections>(this->Config);
				this->AntiDebugger->StartAntiDebugThread();
			}
			catch (const std::bad_alloc& ex)
			{
				throw std::runtime_error("Could not initialize AntiDebugger: " + std::string(ex.what()));
			}
		}
#endif
	}

	~Impl() 
	{
		 this->ProtectedSettings->Reset();
		 delete this->ProtectedSettings;
	}

	bool StopMultipleProcessInstances();
};

UltimateDRM::UltimateDRM(DRMSettings* s)
	: pImpl(new UltimateDRM::Impl(s))
{
}

/**
 * @brief Fetches violations from protective objects and combines into a returned list
 *
 * @return vector of DRMViolation structures, representing all violations that have occurred
 *
 * @usage
 *  std::vector<DRMViolation> violationList = DRM->GetViolations();
 */
std::vector<DRMViolation> UltimateDRM::GetViolations() const noexcept
{
	std::vector<DRMViolation> violationList;

	if (this->pImpl == nullptr || this->pImpl->IntegrityChecker == nullptr)
		return {};

	if (this->pImpl->IntegrityChecker != nullptr && this->pImpl->IntegrityChecker.get() != nullptr)
	{
		auto IntegrityViolations = this->pImpl->IntegrityChecker.get()->GetViolations();

		for (const auto& integrityViolation : IntegrityViolations)
		{
			violationList.emplace_back(DRMViolation{ DRMViolation::Type::Integrity, integrityViolation.address,  integrityViolation.description });
		}
	}

	if (this->pImpl->AntiDebugger != nullptr && this->pImpl->AntiDebugger.get() != nullptr)
	{
		auto DebuggerViolations = this->pImpl->AntiDebugger.get()->GetDetectedMethods();

		for (const auto& debugViolation : DebuggerViolations)
		{
			violationList.emplace_back(DRMViolation{ DRMViolation::Type::Debugging, (uintptr_t)debugViolation.type, L"" });
		}
	}
	    
	return violationList;
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
bool UltimateDRM::Protect()
{
	if (!this->pImpl->StopMultipleProcessInstances()) //prevent multiple client instances by using shared memory-mapped region
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Err, "Could not initialize program: shared memory check failed, make sure only one instance of the program is open. Shutting down.");
#endif
		terminate();
	}

	if (this->pImpl->Config->bUsingLicensing)
	{
		if (this->pImpl->LicenseManagerPtr == nullptr)
		{
			throw std::runtime_error("LicenseManagerPtr is not initialized");
		}

		if (!this->pImpl->Config->bAllowOfflineUsage)
		{
			//if (!this->pImpl->LicenseManagerPtr->VerifyLicenseOnline(false)) //licensing is not finished yet!
			//{
			//	throw DRMException(DRMException::LicenseVerificationFailed);
			//}
		}
		else
		{
			//if (!this->pImpl->LicenseManagerPtr->VerifyLicense())
			//{
			//	throw DRMException(DRMException::LicenseVerificationFailed);
			//}
		}
	}

	if (!this->pImpl->Config->lAllowedParentNames.empty()) //check parent process
	{
		bool verifiedParent = false;
		DWORD parentPid = Process::GetParentProcessId();

		for (std::wstring parent : this->pImpl->Config->lAllowedParentNames) 	//check parent process name, then check code signing cert
		{
			std::wstring parentProcName = Process::GetProcessName(parentPid);

			if (parentProcName != parent)
				continue;

			std::wstring parentProcDirectory = Services::GetProcessDirectoryW(parentPid);

			if (this->pImpl->Config->bRequireCodeSigning)
			{
				if (!Authenticode::HasSignature(std::wstring(parentProcDirectory + parentProcName).c_str(), TRUE))
				{
#ifdef _LOGGING_ENABLED
					Logger::logf(Err, "Parent process lacks a valid code signature!");
#endif
					throw DRMException(DRMException::CodeSigningFailed);
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

		if (!verifiedParent)
		{
#ifdef _LOGGING_ENABLED
			Logger::logf(Err, "Could not initialize program: Parent process is not allowed or does not have a valid code signature");
#endif
			throw DRMException::BadParentProcess;
		}
	}

	if (this->pImpl->Config->bCheckIntegrity)
	{
#ifdef _M_X64
#ifdef _TARGET_STATIC_LIB //if this lib is used in a .DLL to remap a host process (.exe) module, it will crash. need to debug it further (still works to compile this .lib into a .exe and remap)
#ifndef _DEBUG  //todo: check if currently in .dll or .lib linked
		if (!RmpRemapImage((ULONG_PTR)GetModuleHandleA(NULL))) //possibly  causes Defender false positive? Debug compilation does not throw false positive, where this is excluded
		{
			throw std::runtime_error("Failed to remap program sections");
		}
#endif
#endif
#endif
		auto ModuleList = Process::GetLoadedModules();

		for (auto module : ModuleList) //store hashes of all loaded modules for all non-writable sections
		{
			ModuleChecksumData moduleChecksum;
			moduleChecksum.hMod = module.hModule;
			moduleChecksum.Name = module.baseName;
			moduleChecksum.Path = module.nameWithPath;

			auto nonWritableSections = Process::FindNonWritableSections(Utility::ConvertWStringToString(module.baseName)); //.rdata is not a 'guaranteed' section name, especially on WoW64

			for (const auto& section : nonWritableSections)
			{
				uintptr_t checksum = Integrity::CalculateChecksumFromSection(Utility::ConvertWStringToString(module.baseName), section.name.c_str());
				moduleChecksum.SectionChecksums[section.name.c_str()] = checksum;

#ifdef _LOGGING_ENABLED	
				Logger::logf(Info, "Section %s checksum: %llx", section.name.c_str(), checksum);
#endif
			}

			this->pImpl->IntegrityChecker->StoreModuleChecksum(moduleChecksum); //tested and working fine
		}		
	}

	if (this->pImpl->Config->bRequireCodeSigning)
	{
		std::wstring currentProcName = Process::GetProcessName(GetCurrentProcessId());
		std::wstring processDirectory = Services::GetProcessDirectoryW(GetCurrentProcessId());
		std::wstring fullProcessPath = (processDirectory + currentProcName);

		if (!currentProcName.empty() && !processDirectory.empty())
		{
			if (!Authenticode::HasSignature(fullProcessPath.c_str(), TRUE)) //check if the current process has a valid signature
			{
#ifdef _LOGGING_ENABLED
				Logger::logf(Err, "Could not initialize program: Parent process lacked proper code signature");
#endif
				return false;
			}
		}
		else
		{
			throw std::runtime_error("Failed to get current process name");
		}
	}

	if (this->pImpl->Config->bCheckHypervisor)
	{
		if (Services::IsHypervisorPresent())
		{
			const std::string hypervisorVendor = Services::GetHypervisorVendor();

			if (!hypervisorVendor.empty())
			{
				if (hypervisorVendor == "Microsoft Hv" ||
					hypervisorVendor == "KVMKVMKVM" ||
					hypervisorVendor == "VMwareVMware" ||
					hypervisorVendor == "XenVMMXenVMM" ||
					hypervisorVendor == "VBoxVBoxVBox")
				{
#ifdef _LOGGING_ENABLED
						Logger::logf(Err, "Hypervisor detected: %s. Shutting down.", hypervisorVendor.c_str());
#endif
						throw DRMException(DRMException::HypervisorDetected);
				}
			}
		}
	}

	return true;
}

/**
 * @brief Maps a shared memory region with name "UDRM" to prevent multiple instances of the program
 *
 * This function checks if the shared memory region is already mapped, and if so, it returns false to indicate that another instance is already running.
 *
 * @return true if the shared memory region was successfully created and mapped, false if another instance is already running
 *
 * @details 
 *
 *  @example UltimateDRM.cpp
 *
 * @usage
 * this->pImpl->StopMultipleProcessInstances();
 */
bool UltimateDRM::Impl::StopMultipleProcessInstances()
{
	HANDLE hSharedMemory = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(int), "UDRM");

	if (hSharedMemory == NULL)
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Err, "Failed to create shared memory. Error code: %lu\n", GetLastError());
#endif
		return false;
	}

	int* pIsRunning = (int*)MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(int));

	if (pIsRunning == NULL)
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Err, "Failed to map view of file. Error code : % lu\n", GetLastError());
#endif
		CloseHandle(hSharedMemory);
		return false;
	}

	if (*pIsRunning == 1) //duplicate instance found, these instructions can be obfuscated if desired
	{
		UnmapViewOfFile(pIsRunning);
		CloseHandle(hSharedMemory);
		return false;
	}

	*pIsRunning = 1;

	return true;
}

/**
 * @brief TLS callback helper to end unknown threads without patching over their start address or calling ExitThread
 *
 * This function is executed by writing over the start address of new unknown threads in the tls callback

 * @return None
 *
 * @usage
 *  N/A
 */
void ExitThreadGracefully()
{
}

/**
 * @brief TLS callback
 *
 * This function is executed on thread attach/detach and process attach/detach
 *
 * @param pHandle  Handle to the module instance
 * @param dwReason  Type of event which triggered the callback
 * @param Reserved  Unused
 * 
 * @return None
 * 
 * @details On Windows 10, the callback can be used to block execution of foreign or unknown threads by 
 *  checking the stack for the thread's execution address and calling ExitThread(GetCurrentThreadId())
 *  if execution address is not within the valid range of any known & verified loaded module.
 *
 * @usage
 *  N/A
 */
void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved)
{
	static uintptr_t ThreadExecutionAddressStackOffset = 0; //** Windows10 only, this offset on the stack does not have a return address on Windows 11
	static bool bFirstProcessAttach = true;
	static WindowsVersion WinVersion = WindowsVersion::ErrorUnknown;

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{

//#ifndef _DEBUG
//		if (!Debugger::AntiDebug::HideThreadFromDebugger(GetCurrentThread())) //hide thread from debuggers, placing this in the TLS callback allows all threads to be hidden
//		{
//#ifdef _LOGGING_ENABLED
//			Logger::logf(Warning, " Failed to hide thread from debugger @ TLSCallback: thread id %d\n", GetCurrentThreadId());
//#endif
//		}
//#endif
		WinVersion = Services::GetWindowsVersion();

		if (WinVersion == Windows10) //Windows 11 no longer has the thread's start address on its stack when the tls callback is hit
#ifdef _M_X64
			ThreadExecutionAddressStackOffset = 0x378; //are there any reliable ways to get this across all windows builds?
#else
			ThreadExecutionAddressStackOffset = 0x26C;
#endif

		SetUnhandledExceptionFilter(g_VectoredExceptionHandler);

		if (!AddVectoredExceptionHandler(1, g_VectoredExceptionHandler))
		{
#ifdef _LOGGING_ENABLED
			Logger::logf(Err, " Failed to register Vectored Exception Handler @ TLSCallback: %d\n", GetLastError());
#endif
			throw std::runtime_error("Failed to register Vectored Exception Handler");
		}
		
	}break;

	case DLL_PROCESS_DETACH: //program exit, clean up any memory allocated if required
	{
	}break;

	case DLL_THREAD_ATTACH: //add to our thread list, or if thread is not executing valid address range, patch over execution address
	{
//#ifndef _DEBUG
//		if (!Debugger::AntiDebug::HideThreadFromDebugger(GetCurrentThread())) //hide thread from debuggers, placing this in the TLS callback allows all threads to be hidden
//		{
//#ifdef _LOGGING_ENABLED
//			Logger::logf(Warning, " Failed to hide thread from debugger @ TLSCallback: thread id %d\n", GetCurrentThreadId());
//#endif
//		}
//#endif

		if (WinVersion == WindowsVersion::Windows11) //thread start address is not on the stack in windows 11
			return;

		uintptr_t stackThreadStartSlot = (uintptr_t)_AddressOfReturnAddress() + ThreadExecutionAddressStackOffset;
		uintptr_t ThreadStartAddress = *(uintptr_t*)((uintptr_t)_AddressOfReturnAddress() + ThreadExecutionAddressStackOffset);

		if (!ThreadStartAddress) //ideal way to do this is make a global structure for new thread creations acting as a whitelist
			return;

		auto moduleList = Process::GetLoadedModules();

		for (auto module : moduleList)
		{
			if (ThreadStartAddress > ((uintptr_t)module.dllInfo.lpBaseOfDll) && ThreadStartAddress < ((uintptr_t)module.dllInfo.lpBaseOfDll + module.dllInfo.SizeOfImage))
			{
				// <--- we should also make sure the module is signed, ideally using a cache
				return; // thread is executing within a valid module range, no need to suppress/exit it
			}
		}

		*(uintptr_t*)stackThreadStartSlot = (uintptr_t)&ExitThreadGracefully;
				
	}break;

	case DLL_THREAD_DETACH:
	{
	}break;
	};
}

/**
 * @brief Vectored Exception Handler
 *
 * This function catches program-wide unhandled exceptions
 *
 * @param ExceptionInfo  Registers, excpetion code, exception address, etc
 *
 * @return EXCEPTION_CONTINUE_SEARCH - do not handle the exception, just log info and keep searching
 *
 * @details Certain unhandled exceptions might be indicative of tampering
 *
 *  @example
 *
 * @usage
 *  AddVectoredExceptionHandler(1, g_VectoredExceptionHandler)
 */
LONG WINAPI g_VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

#ifdef _LOGGING_ENABLED
	Logger::logf(Err, "Vectored Exception Handler at %llX called with exception code : 0x%08X\n", ExceptionInfo->ExceptionRecord->ExceptionAddress, exceptionCode);
#endif
	return EXCEPTION_CONTINUE_SEARCH;
}

/**
 * @brief Checks license token string (base64'd JWT) for validity
 *
 * @param `LicenseTokenString`  b64 format license string found in `license.jwt` (or similar)
 *
 * @return true/false indicating whether the license key is valid
 *
 * @details Certain unhandled exceptions might be indicative of tampering. This routine should be heavily obfuscated in release builds
 *
 *  @example
 *
 * @usage
 *  bool licensed = DRM->CheckLicenseVerified("eyJhbGciOiJFUzI1NiIsImtpZCI6InYxIiwidHlwIjoiSldUIn0.eyJleHAiOjE3ODcyNzI2NDIsImZlYXR1cmV...");
 */
bool UltimateDRM::CheckLicenseVerified(__in const std::string& LicenseTokenString, __in const bool bAllowOfflineLicense)
{
	if (this->pImpl != nullptr && !this->pImpl->Config->bUsingLicensing)
	{
		return false;
	}

	if (this->pImpl != nullptr && this->pImpl->LicenseManagerPtr != nullptr)
	{
		bool bSuccess = this->pImpl->LicenseManagerPtr->VerifyLicenseJWT_ES256(LicenseTokenString);

		if (bAllowOfflineLicense && bSuccess)
			return true;
		else if (!bAllowOfflineLicense && bSuccess)
		{
			//todo: get back license info from VerifyLicenseJWT_ES256 (need change return type) then send to server to verify online

			//if(VerifyLicenseOnline(...))
			//    return true;
			//else
			//    return false;
		}
		else
			return false;
	}
	else
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Err, "NULLPTR issue @ UltimateDRM::CheckLicenseVerified");
#endif
	}

	return false;
}

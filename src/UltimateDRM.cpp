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
#include "../include/Definitions.hpp"
#include "../include/AntiDebug/DebuggerDetections.hpp"
#include "../include/DRMException.hpp"

#pragma comment(linker, "/ALIGN:0x10000") //for section remapping
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved);
LONG WINAPI g_VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);

EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB") //store tls callback inside the correct section
const
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()

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

	std::unique_ptr<DebuggerDetections> AntiDebugger = nullptr; //debugger detections for the current process

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
		catch (const std::bad_alloc&  ex)
		{
			throw std::runtime_error("Could not initialize smart ptrs: " + std::string(ex.what()));
		}

		try
		{
			if (Settings::Instance->bUseAntiDebugging)
			{
				this->AntiDebugger = std::make_unique<DebuggerDetections>(Settings::Instance);
				this->AntiDebugger->StartAntiDebugThread();
			}
		}
		catch (const std::bad_alloc& ex)
		{
			throw std::runtime_error("Could not initialize AntiDebugger: " + std::string(ex.what()));
		}
	}

	~Impl() 
	{
		 this->ProtectedSettings->Reset();
		 delete this->ProtectedSettings;
	}

	bool StopMultipleProcessInstances();
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
	if (!this->pImpl->StopMultipleProcessInstances()) //prevent multiple client instances by using shared memory-mapped region
	{
#ifdef LOGGING_ENABLED
		Logger::logf(Err, "Could not initialize program: shared memory check failed, make sure only one instance of the program is open. Shutting down.");
#endif
		terminate();
	}

	if (Settings::Instance->bUsingLicensing)
	{
		if (this->pImpl->LicenseManagerPtr == nullptr)
		{
			throw std::runtime_error("LicenseManagerPtr is not initialized");
		}

		if (!this->pImpl->LicenseManagerPtr->VerifyLicense())
		{
			throw DRMException(DRMException::LicenseVerificationFailed);
		}
	}

	if (!Settings::Instance->allowedParents.empty()) //check parent process
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
	}

	if (Settings::Instance->bCheckIntegrity)
	{
#ifndef _DEBUG
		if (!RmpRemapImage((ULONG_PTR)GetModuleHandle(NULL))) //possibly  causes Defender false positive? Debug compilation does not throw false positive, where this is excluded
		{
			throw std::runtime_error("Failed to remap program sections");
		}
#endif
		uint64_t moduleChecksum = Integrity::CalculateChecksum(GetModuleHandle(NULL));

		if (moduleChecksum == 0)
		{
			throw std::runtime_error("Failed to calculate module checksum");
		}

		this->pImpl->IntegrityChecker->StoreModuleChecksum(GetModuleHandle(NULL), moduleChecksum); //tested and working fine
	}

	if (Settings::Instance->bRequireCodeSigning)
	{
		std::wstring currentProcName = Process::GetProcessName(GetCurrentProcessId());
		std::wstring processDirectory = Services::GetProcessDirectoryW(GetCurrentProcessId());
		std::wstring fullProcessPath = (processDirectory + currentProcName);

		if (!currentProcName.empty() && !processDirectory.empty())
		{
			if (!Authenticode::HasSignature(fullProcessPath.c_str(), TRUE)) //check if the current process has a valid signature
			{
#ifdef LOGGING_ENABLED
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

	if (Settings::Instance->bCheckHypervisor)
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
					hypervisorVendor == "prl hyperv" ||
					hypervisorVendor == "VBoxVBoxVBox")
				{
#ifdef LOGGING_ENABLED
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
bool DRM::Impl::StopMultipleProcessInstances()
{
	HANDLE hSharedMemory = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(int), "UDRM");

	if (hSharedMemory == NULL)
	{
#ifdef LOGGING_ENABLED
		Logger::logf(Err, "Failed to create shared memory. Error code: %lu\n", GetLastError());
#endif
		return false;
	}

	int* pIsRunning = (int*)MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(int));

	if (pIsRunning == NULL)
	{
#ifdef LOGGING_ENABLED
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
	static uint32_t ThreadExecutionAddressStackOffset = 0; //** Windows10 only, this offset on the stack does not have a return address on Windows 11
	static bool bFirstProcessAttach = true;
	static WindowsVersion WinVersion = WindowsVersion::ErrorUnknown;

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		if (bFirstProcessAttach)
		{
			bFirstProcessAttach = false;

			WinVersion = Services::GetWindowsVersion();

			if (WinVersion == Windows10)
				ThreadExecutionAddressStackOffset = 0x378;

			SetUnhandledExceptionFilter(g_VectoredExceptionHandler);

			if (!AddVectoredExceptionHandler(1, g_VectoredExceptionHandler))
			{
#ifdef LOGGING_ENABLED
				Logger::logf(Err, " Failed to register Vectored Exception Handler @ TLSCallback: %d\n", GetLastError());
#endif
				throw std::runtime_error("Failed to register Vectored Exception Handler");
			}
		}
	}break;

	case DLL_PROCESS_DETACH: //program exit, clean up any memory allocated if required
	{
	}break;

	case DLL_THREAD_ATTACH: //add to our thread list, or if thread is not executing valid address range, patch over execution address
	{
#ifndef _DEBUG
		if (!Debugger::AntiDebug::HideThreadFromDebugger(GetCurrentThread())) //hide thread from debuggers, placing this in the TLS callback allows all threads to be hidden
		{
#ifdef LOGGING_ENABLED
			Logger::logf(Warning, " Failed to hide thread from debugger @ TLSCallback: thread id %d\n", GetCurrentThreadId());
#endif
		}
#endif

		if (WinVersion == WindowsVersion::Windows11) //thread start address is not on the stack in windows 11
			return;

		uint64_t ThreadStartAddress = *(uint64_t*)((uint64_t)_AddressOfReturnAddress() + ThreadExecutionAddressStackOffset);

		if (!ThreadStartAddress)
			return;

		auto moduleList = Process::GetLoadedModules();

		for (auto module : moduleList)
		{
			if (ThreadStartAddress > ((uint64_t)module.dllInfo.lpBaseOfDll) && ThreadStartAddress < ((uint64_t)module.dllInfo.lpBaseOfDll + module.dllInfo.SizeOfImage))
			{
				return; // thread is executing within a valid module range, no need to suppress/exit it
			}
		}

		DWORD dwOldProt = 0;

		if (!VirtualProtect((LPVOID)ThreadStartAddress, sizeof(uint8_t), PAGE_EXECUTE_READWRITE, &dwOldProt)) //make thread start address writable
		{
#ifdef LOGGING_ENABLED
			Logger::logf(Warning, "Failed to call VirtualProtect on ThreadStart address @ TLSCallback: %llX", ThreadStartAddress);
#endif
		}
		else
		{
		    *(uint8_t*)ThreadStartAddress = 0xC3; //patch over any functions which are scheduled to execute next by this thread and not inside our whitelisted address range	
			ExitThread(0);
		}
		
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

#ifdef LOGGING_ENABLED
	Logger::logf(Err, "Vectored Exception Handler called with exception code : 0x % 08X\n", exceptionCode);
#endif
	return EXCEPTION_CONTINUE_SEARCH;
}


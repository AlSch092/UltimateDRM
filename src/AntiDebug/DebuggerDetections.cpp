#include "../../include/AntiDebug/DebuggerDetections.hpp"

using namespace Debugger;

bool DebuggerDetections::_IsKernelDebuggerPresent()
{
	typedef long NTSTATUS;
	HANDLE hProcess = GetCurrentProcess();

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION { bool DebuggerEnabled; bool DebuggerNotPresent; } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	enum SYSTEM_INFORMATION_CLASS { SystemKernelDebuggerInformation = 35 };
	typedef NTSTATUS(__stdcall* NT_QUERY_SYSTEM_INFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
	NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation;
	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;

	HMODULE hModule = GetModuleHandleA("ntdll.dll");

	if (hModule == NULL)
	{
#ifdef LOGGING_ENABLED
		Logger::logf(Err, "Error fetching module ntdll.dll @ _IsKernelDebuggerPresent: %d", GetLastError());
#endif
		return false;
	}

	NtQuerySystemInformation = (NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hModule, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL)
		return false;

	if (!NtQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL))
	{
		if (Info.DebuggerEnabled && !Info.DebuggerNotPresent)
		{
			this->AddFlagged(DebuggerMethod::DEBUG_KERNEL_DEBUGGER);
			return true;
		}			
		else
			return false;
	}

	return false;
}

bool DebuggerDetections::_IsKernelDebuggerPresent_SharedKData()
{
	_KUSER_SHARED_DATA* sharedData = USER_SHARED_DATA;
	bool bDebuggerEnabled = false;

	if (sharedData != nullptr && sharedData->KdDebuggerEnabled)
	{
		bDebuggerEnabled = true;
		this->AddFlagged(DebuggerMethod::DEBUG_KERNEL_DEBUGGER);
	}

	return bDebuggerEnabled;
}

/*
	_IsDebuggerPresent_HeapFlags - checks heap flags in the PEB, certain combination can indicate a debugger is present
*/
bool DebuggerDetections::_IsDebuggerPresent_HeapFlags()
{
#ifdef _M_IX86
	DWORD_PTR pPeb64 = (DWORD_PTR)__readfsdword(0x30);
#else
	DWORD_PTR pPeb64 = (DWORD_PTR)__readgsqword(0x60);
#endif

	if (pPeb64)
	{
		PVOID ptrHeap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb64 + 0x30);
		PDWORD heapForceFlagsPtr = (PDWORD)((PBYTE)ptrHeap + 0x74);

		__try
		{
			if (*heapForceFlagsPtr >= 0x40000060)
			{
				this->AddFlagged(DebuggerMethod::DEBUG_HEAP_FLAG);
				return true;
			}
				
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
#ifdef LOGGING_ENABLED
			Logger::logf(Warning, "Failed to dereference heapForceFlagsPtr @ _IsDebuggerPresent_HeapFlags");
#endif
			return false;
		}
	}

	return false;
}

/*
  _IsDebuggerPresent_CloseHandle - calls CloseHandle with an invalid handle, if an exception is thrown then a debugger is present
*/
bool DebuggerDetections::_IsDebuggerPresent_CloseHandle()
{
#ifndef _DEBUG
	__try
	{
		CloseHandle((HANDLE)1);
	}
	__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode() ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		this->AddFlagged(DebuggerMethod::DEBUG_CLOSEHANDLE);
		return true;
	}
#endif
	return false;
}

bool DebuggerDetections::_IsDebuggerPresent_RemoteDebugger()
{
	BOOL bDebugged = false;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugged))
	{
		if (bDebugged)
		{
			this->AddFlagged(DebuggerMethod::DEBUG_REMOTE_DEBUGGER);
			return true;
		}
	}
		
	return false;
}

bool DebuggerDetections::_IsDebuggerPresent_DbgBreak()
{
#ifdef _DEBUG
	return false;  //only use __fastfail in release build , since it will trip up our execution when debugging this project
#else
	__try
	{
		DebugBreak();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

#ifdef LOGGING_ENABLED
	Logger::logf(Info, "Calling __fastfail() to prevent further execution since a debugger was found running.");
#endif

	this->AddFlagged(DebuggerMethod::DEBUG_DBG_BREAK);
	__fastfail(1); //code should not reach here unless process is being debugged
	return true;
#endif
}

/*
	_IsDebuggerPresent_VEH - Checks if vehdebug-x86_64.dll is loaded and exporting InitiallizeVEH. If so, the first byte of this routine is patched and the module's internal name is changed to STOP_CHEATING
	returns true if CE's VEH debugger is found, but this won't stop home-rolled VEH debuggers via APC injection
*/
bool DebuggerDetections::_IsDebuggerPresent_VEH()
{
	bool bFound = false;

	HMODULE veh_debugger = GetModuleHandleA("vehdebug-x86_64.dll"); //if someone renames this dll we'll still stop them from debugging since our TLS callback patches over first byte of new thread funcs

	if (veh_debugger != NULL)
	{
		UINT64 veh_addr = (UINT64)GetProcAddress(veh_debugger, "InitializeVEH"); //check for named exports of cheat engine's VEH debugger

		if (veh_addr > 0)
		{
			bFound = true;

			this->AddFlagged(DebuggerMethod::DEBUG_VEH_DEBUGGER);

			DWORD dwOldProt = 0;

			if (!VirtualProtect((void*)veh_addr, 1, PAGE_EXECUTE_READWRITE, &dwOldProt))
			{
#ifdef LOGGING_ENABLED
				Logger::logf(Warning, "VirtualProtect failed @ _IsDebuggerPresent_VEH");
#endif
				return true; //return true since we found the routine, even though we can't patch over it. if virtualprotect fails, the program will probably crash if trying to patch it
			}

			memcpy((void*)veh_addr, "\xC3", sizeof(BYTE)); //patch first byte of `InitializeVEH` with a ret, stops call to InitializeVEH from succeeding.

			if (!VirtualProtect((void*)veh_addr, 1, dwOldProt, &dwOldProt)) //change back to old prot's
			{
#ifdef LOGGING_ENABLED
				Logger::logf(Warning, "VirtualProtect failed @ _IsDebuggerPresent_VEH");
#endif
			}
		}
	}

	return bFound;
}

/*
     _IsDebuggerPresent_PEB - checks the PEB for the BeingDebugged flag
     returns `true` if byte is set to 1, indicating a debugger is present
*/
bool DebuggerDetections::_IsDebuggerPresent_PEB()
{
#ifdef _M_IX86
	MYPEB* _PEB = (MYPEB*)__readfsdword(0x30);
#else
	MYPEB* _PEB = (MYPEB*)__readgsqword(0x60);
#endif

	bool bDebuggerPresent = false;

	if (_PEB != nullptr && _PEB->BeingDebugged)
	{
		this->AddFlagged(DebuggerMethod::DEBUG_PEB);
		bDebuggerPresent = true;
	}

	return bDebuggerPresent;
}

/*
	_IsDebuggerPresent_DebugPort - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x07 to check for debuggers
*/
bool DebuggerDetections::_IsDebuggerPresent_DebugPort()
{
	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESS_INFORMATION_CLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength);

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess)
		{
			const PROCESS_INFORMATION_CLASS ProcessDebugPort = (PROCESS_INFORMATION_CLASS)7;
			DWORD dwProcessDebugPort, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwProcessDebugPort, sizeof(DWORD), &dwReturned);

			if (NT_SUCCESS(status) && (dwProcessDebugPort == -1))
			{
				this->AddFlagged(DebuggerMethod::DEBUG_DEBUG_PORT);
				return true;
			}				
		}
		else
		{
#ifdef LOGGING_ENABLED
			Logger::logf(Warning, "Failed to fetch NtQueryInformationProcess address @ _IsDebuggerPresent_DebugPort ");
#endif
		}
	}
	else
	{
#ifdef LOGGING_ENABLED
		Logger::logf(Warning, "Failed to fetch ntdll.dll address @ _IsDebuggerPresent_DebugPort ");
#endif
	}

	return false;
}

/*
	_IsDebuggerPresent_ProcessDebugFlags - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x1F to check for debuggers
*/
bool DebuggerDetections::_IsDebuggerPresent_ProcessDebugFlags()
{
	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESS_INFORMATION_CLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength);

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess)
		{
			PROCESS_INFORMATION_CLASS pic = (PROCESS_INFORMATION_CLASS)0x1F;
			DWORD dwProcessDebugFlags, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(GetCurrentProcess(), pic, &dwProcessDebugFlags, sizeof(DWORD), &dwReturned);

			if (NT_SUCCESS(status) && (dwProcessDebugFlags == 0))
			{
				this->AddFlagged(DebuggerMethod::DEBUG_PROCESS_DEBUG_FLAGS);
				return true;
			}			
		}
	}
	else
	{
#ifdef LOGGING_ENABLED
		Logger::logf(Warning, "Failed to fetch ntdll.dll address @ _IsDebuggerPresent_ProcessDebugFlags ");
#endif
	}
	return false;
}


/*
	_ExitCommonDebuggers - create remote thread on `ExitProcess` in any common debugger processes
	This can of course be bypassed with a simple process name change, preferrably we would use a combination of artifacts to find these processes
*/
bool DebuggerDetections::_ExitCommonDebuggers()
{
	bool triedEndDebugger = false;

	for (std::wstring debugger : this->CommonDebuggerProcesses)
	{
		std::list<DWORD> pids = Process::GetProcessIdsByName(debugger);
		
		for (auto pid: pids)
		{
			UINT64 K32Base = (UINT64)GetModuleHandleW(L"kernel32.dll");

			if (K32Base == NULL)
			{
#ifdef LOGGING_ENABLED
				Logger::logf(Warning, "Failed to fetch kernel32.dll address @ _ExitCommonDebuggers ");
#endif
				return false;
			}

			UINT64 ExitProcessAddr = (UINT64)GetProcAddress((HMODULE)K32Base, "ExitProcess");

			if (ExitProcessAddr == NULL)
			{
#ifdef LOGGING_ENABLED
				Logger::logf(Warning, "Failed to fetch ExitProcess address @ _ExitCommonDebuggers ");
#endif
				return false;
			}

			UINT64 ExitProcessOffset = ExitProcessAddr - K32Base;

			HANDLE remoteProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

			if (remoteProcHandle)
			{
				uint64_t FunctionAddr_ExitProcess = (uint64_t)Process::GetRemoteModuleBaseAddress(pid, L"kernel32.dll") + ExitProcessOffset;
				HANDLE RemoteThread = CreateRemoteThread(remoteProcHandle, 0, 0, (LPTHREAD_START_ROUTINE)FunctionAddr_ExitProcess, 0, 0, 0);
				triedEndDebugger = true;
				CloseHandle(remoteProcHandle);
#ifdef LOGGING_ENABLED
				Logger::logf(Info, "Created remote thread at %llX address", FunctionAddr_ExitProcess);
#endif
			}
			else
			{
#ifdef LOGGING_ENABLED
				Logger::logf(Warning, "Failed to open process handle for pid %d @ _ExitCommonDebuggers", pid);
#endif
			}
		}
	}

	return triedEndDebugger;
}


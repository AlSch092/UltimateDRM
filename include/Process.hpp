//Process.hpp by Alsch092 @ Github
#pragma once
#include "Definitions.hpp"
#include "NAuthenticode.hpp"
#include "Services.hpp"
#include <Psapi.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <list>
#include <ImageHlp.h>
#include <vector>

#pragma comment(lib, "ImageHlp")

using namespace std;

namespace ProcessData
{
	typedef enum _PROCESS_INFORMATION_CLASS 
	{
		ProcessMemoryPriority,
		ProcessMemoryExhaustionInfo,
		ProcessAppMemoryInfo,
		ProcessInPrivateInfo,
		ProcessPowerThrottling,
		ProcessReservedValue1,
		ProcessTelemetryCoverageInfo,
		ProcessProtectionLevelInfo,
		ProcessLeapSecondInfo,
		ProcessMachineTypeInfo,
		ProcessOverrideSubsequentPrefetchParameter,
		ProcessMaxOverridePrefetchParameter,
		ProcessInformationClassMax
	} PROCESS_INFORMATION_CLASS;

	struct MODULE_DATA
	{
		wstring baseName;
		wstring name;
		MODULEINFO dllInfo;
		HMODULE hModule;
	};

	struct Section
	{
		string name = "";
		unsigned int size;
		UINT64 address;

		union 
		{
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
		} Misc;

		UINT64 PointerToRawData;
		UINT64 PointerToRelocations;
		DWORD NumberOfLinenumbers;
		UINT64 PointerToLinenumbers;
	};

	struct ImportFunction
	{
		HMODULE Module;
		std::string AssociatedModuleName;
		std::string FunctionName;
		UINT64 AddressOfData;
	};
}

/*
	The `Process` class provides a representation of the current process and provides several static utility functions
	Aspects of a process such as sections, modules, threads, etc are contained in this class
*/
class Process final
{
public:

	Process(__in const unsigned int nProgramSections) //we manually set number of program sections in order to spoof it at runtime to 0 or 1, and not have the program be confused
	{
		_PEB = new _MYPEB();
		
		if (!FillModuleList())
		{
#ifdef LOGGING_ENABLED
			Logger::logf(Err, "Unable to traverse loaded modules @ Process::Process()");
#endif
		}

		DWORD parentPid = GetParentProcessId();

		if (parentPid != 0)
		{
			SetParentName(GetProcessName(parentPid));
			SetParentId(parentPid);
		}
		else
		{
#ifdef LOGGING_ENABLED
			Logger::logf(Warning, "Could not fetch parent process ID @ Process::Process");
#endif
		}
	}

	~Process()
	{
		for (ProcessData::MODULE_DATA* s : ModuleList)
			if(s != nullptr)
			    delete s;
	}

	bool FillModuleList();

	static list<ProcessData::Section*> GetSections(__in const string module);

#ifdef _M_IX86
	static _MYPEB* GetPEB() { return (_MYPEB*)__readfsdword(0x30); }
#else
	static _MYPEB* GetPEB() { return (_MYPEB*)__readgsqword(0x60); }
#endif

	static wstring GetProcessName(__in const DWORD pid);
	static DWORD GetProcessIdByName(__in const wstring procName);
	static list<DWORD> GetProcessIdsByName(__in const wstring procName);

	static DWORD GetParentProcessId();
	static BOOL CheckParentProcess(__in const wstring desiredParent, __in const bool bShouldCheckSignature);

	wstring GetParentName() const { return this->_ParentProcessName; }
	uint32_t GetParentId() const { return this->_ParentProcessId; }

	void SetParentName(__in const wstring parentName) { this->_ParentProcessName = parentName; }
	void SetParentId(__in const uint32_t id) { this->_ParentProcessId = id; }

	static bool HasExportedFunction(__in const string dllName, __in const string functionName);

	static FARPROC _GetProcAddress(__in const PCSTR Module, __in const  LPCSTR lpProcName); //GetProcAddress without winAPI call

	static UINT64 GetSectionAddress(__in const HMODULE hMod, __in const  char* sectionName);

	static BYTE* GetBytesAtAddress(__in const UINT64 address, __in const UINT size);

	static DWORD GetModuleSize(__in const HMODULE module);

	static list<ProcessData::ImportFunction*> GetIATEntries(); //start of IAT hook checks

	static bool IsReturnAddressInModule(__in const UINT64 RetAddr, __in const  wchar_t* module);

	static std::vector<ProcessData::MODULE_DATA> GetLoadedModules();
	static ProcessData::MODULE_DATA* GetModuleInfo(__in const  wchar_t* name);
	
	static HMODULE GetModuleHandle_Ldr(__in const  wchar_t* moduleName);

	static DWORD GetTextSectionSize(__in const HMODULE hModule);

	static HMODULE GetRemoteModuleBaseAddress(__in const DWORD processId, __in const  wchar_t* moduleName);

	static bool GetProcessTextSection(__in const HANDLE hProcess, __out uintptr_t& baseAddress, __out SIZE_T& sectionSize);
	static std::vector<BYTE> ReadRemoteTextSection(__in const DWORD pid); //fetch .text of a running process (can improve this by making it any section instead of just .text)

private:

	_MYPEB* _PEB = NULL;

	uint32_t _ProcessId = 0;

	wstring _ProcessName;
	wstring _WindowClassName;
	wstring _WindowTitle;

	wstring _ParentProcessName;
	uint32_t _ParentProcessId = 0;

	list<ProcessData::Section*> MainModuleSections;

	list<ProcessData::MODULE_DATA*> ModuleList; //todo: make routine to fill this member
};
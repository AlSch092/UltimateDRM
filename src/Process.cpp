#include "../include/Process.hpp"

/*
    CheckParentProcess - checks if the parent process is the process name `desiredParent`
    returns TRUE if our parameter desiredParent is the same process name as our parent process ID
*/
BOOL Process::CheckParentProcess(__in const wstring desiredParent, __in const bool bShouldCheckSignature)
{
    std::list<DWORD> pids = GetProcessIdsByName(desiredParent);
    DWORD parentPid = GetParentProcessId();
    
    if (bShouldCheckSignature)
    {
        BOOL bFoundValidSignature = FALSE;

        for (DWORD pid : pids)
        {
            if (parentPid == pid)
            {
                wstring fullPath = Services::GetProcessDirectoryW(pid); //get path of `pid` for cert checking
                fullPath += desiredParent;

                if (Authenticode::HasSignature(fullPath.c_str(), TRUE))
                {
                    bFoundValidSignature = TRUE;
                    break;
                }
            }
        }

		if (!bFoundValidSignature)
#ifdef LOGGING_ENABLED
			Logger::logf(Err, "Parent process %s does not have a valid signature", desiredParent.c_str());
#endif

		return bFoundValidSignature;
    }
    else
        return (std::find(std::begin(pids), std::end(pids), parentPid) != std::end(pids));
}

/*
    HasExportedFunction checks a loaded module if it's exported `functionName`. Useful for anti-VEH debuggers, since these generally inject themselves into the process and export initialization routines
    returns   true if `dllName` has `functionName` exported.
*/
bool Process::HasExportedFunction(__in const string dllName, __in const  string functionName)
{
    DWORD* dNameRVAs(0); //addresses of export names
    _IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
    unsigned long cDirSize;
    _LOADED_IMAGE LoadedImage;
    string sName;

    bool bFound = false;

    if (MapAndLoad(dllName.c_str(), NULL, &LoadedImage, TRUE, TRUE))
    {
        ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

        if (ImageExportDirectory != NULL)
        {
            //load list of function names from DLL, the third parameter is an RVA to the data we want
            dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);

            for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++)
            {
                //get RVA 
                sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);

                if (strcmp(functionName.c_str(), sName.c_str()) == 0)
                    bFound = true;           
            }
        }
        else
#ifdef LOGGING_ENABLED
            Logger::log(Err, " ImageExportDirectory was NULL @ Process::HasExportedFunction");
#endif
        
        UnMapAndLoad(&LoadedImage);
    }
    else
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "MapAndLoad failed: %d @ Process::HasExportedFunction \n", GetLastError());
#endif
    

    return bFound;
}

/*
    GetSections - gathers a list of ProcessData::Section* from the current process
    returns list<ProcessData::Section*>*, and an empty list if the routine fails
*/
list<ProcessData::Section*> Process::GetSections(__in const string module)
{
    list<ProcessData::Section*> Sections;

    PIMAGE_SECTION_HEADER sectionHeader;
    HMODULE hInst = NULL;  
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS64 pNtH;

    hInst= GetModuleHandleA(module.c_str());
    
    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    if (pDoH == NULL || hInst == NULL)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, " PIMAGE_DOS_HEADER or hInst was NULL at Process::GetSections");
#endif
        return Sections;
    }

    pNtH = (PIMAGE_NT_HEADERS64)((PIMAGE_NT_HEADERS64)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));
    sectionHeader = IMAGE_FIRST_SECTION(pNtH);

    int nSections = pNtH->FileHeader.NumberOfSections;

    if (nSections == 0)
        nSections = pNtH->FileHeader.NumberOfSections;

    for (int i = 0; i < nSections; i++)
    {
        ProcessData::Section* s = new ProcessData::Section();

        s->address = sectionHeader[i].VirtualAddress;

        s->name = std::string(reinterpret_cast<const char*>(sectionHeader[i].Name));
      
        if (s->name.size() > 8)
            s->name.resize(8, 0);

        s->Misc.VirtualSize = sectionHeader[i].Misc.VirtualSize;
        s->size = s->Misc.VirtualSize;
        s->PointerToRawData = sectionHeader[i].PointerToRawData;
        s->PointerToRelocations = sectionHeader[i].PointerToRelocations;
        s->NumberOfLinenumbers = sectionHeader[i].NumberOfLinenumbers;
        s->PointerToLinenumbers = sectionHeader[i].PointerToLinenumbers;

        Sections.push_back(s);
    }

    return Sections;
}

/*
GetParentProcessId - Get the process ID of the parents process
returns the pid of the current process parent process. used to check for illegal launchers (an attacker's launcher code spawned our process, for example)
*/
DWORD Process::GetParentProcessId()
{
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0, pid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try 
    {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do 
        {
            if (pe32.th32ProcessID == pid) 
            {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
    __finally 
    {
        if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != 0) 
            CloseHandle(hSnapshot);
    }
    return ppid;
}

/*
    GetProcessIdByName - Get first pid given a process name.
    You should probably use GetProcessIdsByName instead.
    returns a DWORD pid if procName is a running process, otherwise returns 0
*/
DWORD Process::GetProcessIdByName(__in const wstring procName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
            if (wcscmp(entry.szExeFile, procName.c_str()) == 0)
            {
                pid = entry.th32ProcessID;
                break;
            }              
    }

    CloseHandle(snapshot);
    return pid;
}


/*
    GetProcessIdsByName - Get all pids given a process name
    returns a list of DWORD pids of processes running with procName.
*/
list<DWORD> Process::GetProcessIdsByName(__in const wstring procName)
{
    if (procName.size() == 0)
        return {};

    list<DWORD> pids;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
            if (wcscmp(entry.szExeFile, procName.c_str()) == 0)
                pids.push_back(entry.th32ProcessID);

    }

    CloseHandle(snapshot);
    return pids;
}

/*
    GetSectionAddress - Get the address of a named section of the module with the named `moduleName`
    returns a memory address of the section if found, and 0 if no section is found or an error occurs
*/
UINT64 Process::GetSectionAddress(__in const HMODULE hModule, __in const  char* sectionName)
{
    if (hModule == NULL)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, " Failed to get module handle: %d @ GetSectionAddress\n", GetLastError());
#endif
        return 0;
    }

    UINT64 baseAddress = (UINT64)hModule;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, " Invalid DOS header @ GetSectionAddress.\n");
#endif
        return 0;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(baseAddress + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, " Invalid NT header @ GetSectionAddress.\n");
#endif
        return 0;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)  //we are modifying # of sections at runtime to throw attackers off
    {
        if ((const char*)pSectionHeader->Name != nullptr)
        {
            if (strcmp((const char*)pSectionHeader->Name, sectionName) == 0)
            {
                return baseAddress + pSectionHeader->VirtualAddress;
            }
        }

        pSectionHeader++;
    }
#ifdef LOGGING_ENABLED
    Logger::logf(Warning, ".text section not found.\n");
#endif
    return 0;
}

/*
    GetBytesAtAddress - return bytes from an address given `size`.
    returns a BYTE array filled with values from `address` for `size` number of bytes
*/
BYTE* Process::GetBytesAtAddress(__in const UINT64 address, __in const  UINT size) //remember to free bytes if not NULL ret
{
    BYTE* memBytes = new BYTE[size];

    __try
    {
        memcpy((void*)memBytes, (void*)address, size);
        return memBytes;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        delete[] memBytes;
        memBytes = nullptr;
        return nullptr;
    }
}

/*
    GetIATEntries -Returns a list of ImportFunction* from the program IAT , for later hook checks
    returns a list of ProcessData::ImportFunction* such that lists can be compared for modifications 
*/
list<ProcessData::ImportFunction*> Process::GetIATEntries() 
{
    HMODULE hModule = GetModuleHandleW(NULL);

    if (hModule == NULL)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "Couldn't fetch module handle @ Process::GetIATEntries ");
#endif
        return (list<ProcessData::ImportFunction*>)NULL;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;

    if (dosHeader == nullptr)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "Couldn't fetch dosHeader @ Process::GetIATEntries ");
#endif
        return (list<ProcessData::ImportFunction*>)NULL;
    }

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    list <ProcessData::ImportFunction*> importList;

    while (importDesc->OriginalFirstThunk != 0) 
    {    
        const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);

        if (dllName == NULL)
            continue;

        IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->FirstThunk);

        while (iat->u1.AddressOfData != 0) 
        {
            ProcessData::ImportFunction* import = new ProcessData::ImportFunction();
            import->AssociatedModuleName = dllName;
            import->Module = GetModuleHandleA(dllName);
            import->AddressOfData = iat->u1.AddressOfData;         
            importList.push_back(import);
            iat++;
        }

        importDesc++;
    }

    return importList;
}

/*
    GetModuleSize - get size of a module at address `hModule`
    returns the size of hModule, and 0 if hModule is invalid or error occurs
*/
DWORD Process::GetModuleSize(__in const HMODULE hModule)
{
    if (hModule == NULL) 
        return 0;

    MODULEINFO moduleInfo;

    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) 
        return 0;
    
    return moduleInfo.SizeOfImage;
}

/*
    FillModuleList - fills the `ModuleList` class member with a list of module information
    returns true on success
*/
bool Process::FillModuleList()
{
    HMODULE hModules[512];
    DWORD cbNeeded = 0;

    // Get the module handles for the current process
    if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded)) 
    {
        if (this->ModuleList.size() >= (cbNeeded / sizeof(HMODULE))) //already filled previously?
            return false;

        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) 
        {
            ProcessData::MODULE_DATA* module = new ProcessData::MODULE_DATA();
            
            TCHAR szModuleName[MAX_PATH];
            MODULEINFO moduleInfo;

            if (GetModuleFileNameEx(GetCurrentProcess(), hModules[i], szModuleName, sizeof(szModuleName) / sizeof(TCHAR))) 
            {
                module->name = wstring(szModuleName);

                module->hModule = hModules[i];

                if (GetModuleInformation(GetCurrentProcess(), hModules[i], &moduleInfo, sizeof(moduleInfo)))
                {
                    module->dllInfo.lpBaseOfDll = moduleInfo.lpBaseOfDll;
                    module->dllInfo.SizeOfImage = moduleInfo.SizeOfImage;
                }
                else
                {
#ifdef LOGGING_ENABLED
                    Logger::logf(Err, "Unable to parse module information @ Process::FillModuleList");
#endif
                    return false;
                }

                this->ModuleList.push_back(module);
            }
            else
            {
#ifdef LOGGING_ENABLED
                Logger::logf(Err, "Unable to parse module named @ Process::FillModuleList");
#endif
                return false;
            }
        }
    }
    else
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "EnumProcessModules failed @ Process::FillModuleList");
#endif
        return false;
    }

    return true;
}

/*
    _GetProcAddress - Attempt to retrieve address of function of `Module`, given `lpProcName`
    Meant to be used for function lookups without calling GetProcAddress explicitly (may require dynamic analysis instead of static for an attacker)
*/
FARPROC Process::_GetProcAddress(__in const PCSTR Module, __in const LPCSTR lpProcName)
{
    if (Module == nullptr || lpProcName == nullptr)
        return (FARPROC)NULL;

    DWORD* dNameRVAs(0); //array: addresses of export names
    DWORD* dFunctionRVAs(0);
    WORD* dOrdinalRVAs(0);

    _IMAGE_EXPORT_DIRECTORY* ImageExportDirectory = NULL;
    unsigned long cDirSize = 0;
    _LOADED_IMAGE LoadedImage;
    char* sName = NULL;

    UINT64 AddressFound = NULL;

    UINT64 ModuleBase = (UINT64)GetModuleHandleA(Module); //last remaining artifacts for detection. TODO: Use PEB to fetch this instead of API

    if (ModuleBase == NULL)
        return NULL;

    if (MapAndLoad(Module, NULL, &LoadedImage, TRUE, TRUE))
    {
        ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

        if (ImageExportDirectory != NULL)
        {
            dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);
            dFunctionRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfFunctions, NULL);
            dOrdinalRVAs = (WORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNameOrdinals, NULL);

            for (size_t i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
            {
                sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);

                if (strcmp(sName, lpProcName) == 0)
                {
                    AddressFound = ModuleBase + dFunctionRVAs[dOrdinalRVAs[i]];
                    break;
                }
            }
        }
        else
        {
#ifdef LOGGING_ENABLED
            Logger::logf(Err, "ImageExportDirectory was NULL @ Process::_GetProcAddress with module %s and function %s", Module, lpProcName);
#endif
            UnMapAndLoad(&LoadedImage);
            return NULL;
        }

        UnMapAndLoad(&LoadedImage);
    }
    else
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "MapAndLoad failed @ Process::_GetProcAddress with module %s and function %s", Module, lpProcName);
#endif
        return (FARPROC)NULL;
    }

    return (FARPROC)AddressFound;
}

/*
    IsReturnAddressInModule - returns true if RetAddr is module's mem region
    Used to detect attackers calling our functions such as heartbeat generation, since they may try to spoof or emulate the net client
*/
bool Process::IsReturnAddressInModule(__in const UINT64 RetAddr, __in const  wchar_t* module)
{
    if (RetAddr == 0)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "RetAddr was 0 @ : Process::IsReturnAddressInModule");
#endif
        return false;
    }

    HMODULE retBase = 0;

    if (module == NULL)
        retBase = (HMODULE)GetModuleHandleW(NULL);   
    else 
        retBase = (HMODULE)GetModuleHandleW(module);

    if (retBase == 0)
        return false;

    DWORD size = Process::GetModuleSize(retBase);

    if (size == 0)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "size was 0 @ : Process::IsReturnAddressInModule");
#endif
        return false;
    }

    if (RetAddr >= (UINT64)retBase && RetAddr < ((UINT64)retBase + size))    
        return true;
    else
        return false;
}

/*
       GetProcessName - Returns the string name of a process with id `pid`
*/
wstring Process::GetProcessName(__in const DWORD pid)
{
    std::wstring processName;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess) 
    {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) 
        {       
            WCHAR processNameBuffer[MAX_PATH];
            if (GetModuleBaseName(hProcess, hMod, processNameBuffer, sizeof(processNameBuffer) / sizeof(WCHAR))) 
            {
                processName = processNameBuffer;
            }
            else 
            {
#ifdef LOGGING_ENABLED
                Logger::logf(Err, "GetModuleBaseName failed with error %d @  Process::GetProcessName", GetLastError());
#endif
            }
        }
        else 
        {
#ifdef LOGGING_ENABLED
            Logger::logf(Err, "EnumProcessModules failed with error %d @  Process::GetProcessName", GetLastError());
#endif
        }
        CloseHandle(hProcess);
    }
    else 
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "OpenProcess failed with error %d @  Process::GetProcessName", GetLastError());
#endif
    }

    return processName;
}

/*
    GetLoadedModules - returns a vector<MODULE_DATA>*  representing a set of loaded modules in the current process
    returns nullptr on failure
*/
std::vector<ProcessData::MODULE_DATA> Process::GetLoadedModules()
{

#ifdef _M_IX86
    MYPEB* peb = (MYPEB*)__readfsdword(0x30);
#else
    MYPEB* peb = (MYPEB*)__readgsqword(0x60);
#endif

    uintptr_t kernel32Base = 0;

    LIST_ENTRY* current_record = NULL;
    LIST_ENTRY* start = &(peb->Ldr->InLoadOrderModuleList);

    current_record = start->Flink;

    std::vector<ProcessData::MODULE_DATA> moduleList;

    while (true)
    {
        MY_LDR_DATA_TABLE_ENTRY* module_entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current_record, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        ProcessData::MODULE_DATA module;

        module.name =  wstring(module_entry->FullDllName.Buffer);
        module.baseName = wstring(module_entry->BaseDllName.Buffer);

        module.hModule = (HMODULE)module_entry->DllBase;
        module.dllInfo.lpBaseOfDll = module_entry->DllBase;
        module.dllInfo.SizeOfImage = module_entry->SizeOfImage;
        moduleList.push_back(module);

        current_record = current_record->Flink;

        if (current_record == start)
        {
            break;
        }
    }

    return moduleList;
}

/*
    GetModuleInfo - returns a ProcessData::MODULE_DATA* representing the module given `name`.
    returns nullptr on failure/no module found
*/
ProcessData::MODULE_DATA* Process::GetModuleInfo(__in const  wchar_t* name)
{
#ifdef _M_IX86
    MYPEB* peb = (MYPEB*)__readfsdword(0x30);
#else
    MYPEB* peb = (MYPEB*)__readgsqword(0x60);
#endif

    uintptr_t kernel32Base = 0;

    LIST_ENTRY* current_record = NULL;
    LIST_ENTRY* start = &(peb->Ldr->InLoadOrderModuleList);

    current_record = start->Flink;

    while (true)
    {
        MY_LDR_DATA_TABLE_ENTRY* module_entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current_record, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (wcscmp(module_entry->BaseDllName.Buffer, name) == 0)
        {
            ProcessData::MODULE_DATA* module = new ProcessData::MODULE_DATA();

            module->name = wstring(module_entry->FullDllName.Buffer);
            module->baseName =  wstring(module_entry->BaseDllName.Buffer);
            module->hModule = (HMODULE)module_entry->DllBase;
            module->dllInfo.lpBaseOfDll = module_entry->DllBase;
            module->dllInfo.SizeOfImage = module_entry->SizeOfImage;
            return module;
        }

        current_record = current_record->Flink;

        if (current_record == start)
        {
            break;
        }
    }

    return nullptr;
}

/*
    GetModuleHandle_Ldr - returns base address of a module as HMODULE type
    returns NULL on failure
*/
HMODULE Process::GetModuleHandle_Ldr(__in const  wchar_t* moduleName)
{
#ifdef _M_IX86
    MYPEB* peb = (MYPEB*)__readfsdword(0x30);
#else
    MYPEB* peb = (MYPEB*)__readgsqword(0x60);
#endif

    uintptr_t kernel32Base = 0;

    LIST_ENTRY* current_record = NULL;
    LIST_ENTRY* start = &(peb->Ldr->InLoadOrderModuleList);

    current_record = start->Flink;

    while (true)
    {
        MY_LDR_DATA_TABLE_ENTRY* module_entry = (MY_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current_record, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        current_record = current_record->Flink;

        if (wcsstr(module_entry->FullDllName.Buffer, moduleName) != NULL)
        {
            return (HMODULE)module_entry->DllBase;
        }

        if (current_record == start)
        {
            return (HMODULE)NULL;
        }
    }

    return (HMODULE)NULL;
}

DWORD Process::GetTextSectionSize(__in const HMODULE hModule)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "Invalid DOS signature @ GetTextSectionSize");
#endif
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "Invalid NT signature @ GetTextSectionSize");
#endif
        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (strcmp((char*)sectionHeaders[i].Name, ".text") == 0)
        {
            return sectionHeaders[i].Misc.VirtualSize;
        }
    }

    return 0; //failure case, could not find .text section
}

/*
    GetRemoteModuleBaseAddress - fetch module base address of `moduleName` in `processId`
*/
HMODULE Process::GetRemoteModuleBaseAddress(__in const DWORD processId, __in const  wchar_t* moduleName)
{
    HMODULE hModule = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnapshot != INVALID_HANDLE_VALUE) 
    {
        MODULEENTRY32 moduleEntry = { 0 };
        moduleEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &moduleEntry)) 
        {
            do 
            {
                if (_wcsicmp(moduleEntry.szModule, moduleName) == 0) 
                {
                    hModule = moduleEntry.hModule;
                    break;
                }
            } while (Module32Next(hSnapshot, &moduleEntry));
        }
        CloseHandle(hSnapshot);
    }
    return hModule;
}

bool Process::GetProcessTextSection(__in const HANDLE hProcess, __out uintptr_t& baseAddress, __out SIZE_T& sectionSize)
{
    HMODULE hModule = nullptr;
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    if (Module32First(hSnapshot, &me32))
        hModule = me32.hModule;

    if(hSnapshot)
        CloseHandle(hSnapshot);

    if (!hModule)
        return false;

    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProcess, hModule, &dosHeader, sizeof(dosHeader), &bytesRead) || bytesRead != sizeof(dosHeader))
        return false;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProcess, (LPCVOID)((uintptr_t)hModule + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), &bytesRead) || bytesRead != sizeof(ntHeaders))
        return false;

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        return false;

    IMAGE_SECTION_HEADER sectionHeader;
    uintptr_t sectionOffset = (uintptr_t)hModule + dosHeader.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

    for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
    {
        if (!ReadProcessMemory(hProcess, (LPCVOID)sectionOffset, &sectionHeader, sizeof(sectionHeader), &bytesRead) || bytesRead != sizeof(sectionHeader))
            return false;

        if (memcmp(sectionHeader.Name, ".text", 5) == 0)
        {
            baseAddress = (uintptr_t)hModule + sectionHeader.VirtualAddress;
            sectionSize = sectionHeader.Misc.VirtualSize;
            return true;
        }

        sectionOffset += sizeof(IMAGE_SECTION_HEADER);
    }

    return false;
}


std::vector<BYTE> Process::ReadRemoteTextSection(__in const DWORD pid)
{
	if (pid <= 4) //system processes
        return {};

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (!hProcess) 
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "Failed to open process. Error: %d", GetLastError());
#endif
        return {};
    }

    uintptr_t baseAddress = 0;
    SIZE_T sectionSize = 0;

    if (!GetProcessTextSection(hProcess, baseAddress, sectionSize)) 
    {
#ifdef LOGGING_ENABLED
        Logger::log(Err, "Failed to find the .text section.");
#endif
        CloseHandle(hProcess);
        return {};
    }

    std::vector<BYTE> buffer(sectionSize);

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(baseAddress), buffer.data(), sectionSize, &bytesRead)) 
    {
#ifdef LOGGING_ENABLED
        Logger::logf(Err, "Failed to read memory. Error: %d",  GetLastError());
#endif
        CloseHandle(hProcess);
        return {};
    }

    buffer.resize(bytesRead); //resize to actual bytes read
    CloseHandle(hProcess);

    return buffer;
}
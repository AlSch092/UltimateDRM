// DRMTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "../include/DRM.hpp"

#ifdef _M_X64
#ifdef _DEBUG
#pragma comment(lib, "../x64/Debug/UltimateDRM.libUltimateDRM-d.lib")
#else
#pragma comment(lib, "../x64/Release/UltimateDRM.lib")
#endif
#else
#ifdef _RELEASE
#pragma comment(lib, "../Debug/UltimateDRM.libUltimateDRM-d.lib")
#else
#pragma comment(lib, "../Release/UltimateDRM.lib")
#endif
#endif

uintptr_t GetSectionStart(HMODULE hModule, const char* sectionName)
{
	if (!hModule)
		return 0;

	auto base = reinterpret_cast<BYTE*>(hModule);
	auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
	auto section = IMAGE_FIRST_SECTION(ntHeaders);

	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
	{
		if (strcmp((char*)section->Name, sectionName) == 0)
		{
			return (uintptr_t)(base + section->VirtualAddress);
		}
	}

	return 0;
}

int main(int argc, char** argv)
{
	std::list<std::wstring> lAllowedParents = { L"steam.exe", L"explorer.exe", L"VsDebugConsole.exe", L"powershell.exe", L"pwsh.exe", L"cmd.exe" };

	const std::string LicenseServerEndpoint = "https://example.com/api/license"; //replace with your actual license server endpoint
	const bool bAllowOfflineUsage = true;
	const bool bUsingLicensing = false;
	const bool bEnforceHypervisorCheck = false; //having this set to true will cause Github Actions tests to fail, since they run on a VM
	const bool bRequireCodeSigning = false; //in production code, this should be set to true
	const bool bShutdownOnViolation = false; //throws runtime error if integrity violation is found

	DRM* drm = new DRM(LicenseServerEndpoint, bAllowOfflineUsage, bUsingLicensing, bEnforceHypervisorCheck, bRequireCodeSigning, lAllowedParents, bShutdownOnViolation);

	try
	{
		if (drm->Protect())
		{
			std::cout << "DRM protection applied successfully.\n";
		}
		else
		{
			std::cout << "Failed to apply DRM protection.\n"; //this may trigger if our test .exe isn't code signed
			return 1;
		}
	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << "Error during DRM protection: " << ex.what() << std::endl;
		return 2;
	}
	catch (const DRMException& ex)
	{
		std::cerr << "DRM Exception occurred: " << ex.what() << std::endl;
		return 3;
	}

#ifdef _M_X64   //no self remapping in x86
#ifndef _DEBUG
	//TEST: Check if sections page protections can be changed after remap
	uintptr_t textSectionStart = GetSectionStart(GetModuleHandleA(NULL), ".text");

	if (textSectionStart == 0)
	{
		std::cerr << "Failed to find .text section start address.\n";
		return 4;
	}

	DWORD dwOldProt = 0;

	if (VirtualProtect((LPVOID)textSectionStart, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		std::cout << "Text section is writable: test failed\n";
		return 5;
	}
	else
	{
		std::cout << "Failed to make text section writable: test passed\n";
	}
#endif
#endif

	delete drm;

	std::cout << "Closing DRM Test program...\n";

	return 0;
}

// DRMTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "../include/DRM.hpp"

#ifdef _DEBUG
#pragma comment(lib, "../x64/Debug/UltimateDRM-d.lib")
#else
#pragma comment(lib, "../x64/Release/UltimateDRM.lib")
#endif

uint64_t GetTextSectionStart(HMODULE hModule)
{
	if (!hModule) 
		return 0;

	auto base = reinterpret_cast<BYTE*>(hModule);
	auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
	auto section = IMAGE_FIRST_SECTION(ntHeaders);

	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
	{
		if (strncmp((char*)section->Name, ".text", 5) == 0)
		{
			return (uint64_t)(base + section->VirtualAddress);
		}
	}

	return 0;
}

int main()
{
	std::list<std::wstring> lAllowedParents = { L"steam.exe", L"explorer.exe" };

	const std::string LicenseServerEndpoint = "https://example.com/api/license"; //replace with your actual license server endpoint
	const bool bAllowOfflineUsage = true;
	const bool bUsingLicensing = false;
	const bool bEnforceHypervisorCheck = true;
	const bool bRequireCodeSigning = false; //in production code, this should be set to true

	DRM* drm = new DRM(LicenseServerEndpoint, bAllowOfflineUsage, bUsingLicensing, bEnforceHypervisorCheck, bRequireCodeSigning, lAllowedParents);

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

#ifndef _DEBUG
	//TEST: Check if sections page protections can be changed after remap
	uint64_t textSectionStart = GetTextSectionStart(GetModuleHandleA(NULL)); 

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

	delete drm;

	std::cout << "Closing DRM Test program...\n";

	return 0;
}
// DRMTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <fstream>
#include "../include/UltimateDRM.hpp"

#ifdef _M_X64
#ifdef _DEBUG
#pragma comment(lib, "../x64/Debug/UltimateDRM-d.lib")
#else
#pragma comment(lib, "../x64/Release/UltimateDRM.lib")
#endif
#else
#ifdef _RELEASE
#pragma comment(lib, "../Debug/UltimateDRM.lib")
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
	int testResult = 0;

	std::list<std::wstring> lAllowedParents = { L"steam.exe", L"explorer.exe", L"VsDebugConsole.exe", L"powershell.exe", L"pwsh.exe", L"cmd.exe" };

	const std::string LicenseServerEndpoint = "http://localhost:5002/Verify"; //replace with your actual license server endpoint
	const std::string LicenseFilePath = "license.jwt"; //path to license file
	const bool bAllowOfflineUsage = true;
	const bool bUsingLicensing = true;
	const bool bEnforceHypervisorCheck = false; //having this set to true will cause Github Actions tests to fail, since they run on a VM
	const bool bRequireCodeSigning = false; //in production code, this should be set to true
	const bool bShutdownOnViolation = false; //throws runtime error if integrity violation is found
	const bool bEnforceSecureBoot = true;
	const bool bEnforceDSE = true;
	const bool bEnforceNoKdb = true;
	const bool bUseAntiDebugging = false;
	const bool bCheckModulesIntegrity = true;
	const bool bCheckHypervisor = true;
	const bool bForceRunAsAdmin = false;

	DRMSettings* s = new DRMSettings(LicenseServerEndpoint, bShutdownOnViolation, bAllowOfflineUsage, bUsingLicensing, bRequireCodeSigning, bEnforceSecureBoot,
		bEnforceDSE, bEnforceNoKdb, bUseAntiDebugging, bCheckModulesIntegrity, bCheckHypervisor, bForceRunAsAdmin, lAllowedParents);

	UltimateDRM* drm = new UltimateDRM(s);

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

	std::string licenseJWTString;
	std::string line;
	std::ifstream licenseFile(LicenseFilePath);

	while (std::getline(licenseFile, line))
	{
		licenseJWTString += line;
	}

	if(licenseFile.is_open())
	    licenseFile.close();

	if (drm->CheckLicenseVerified(licenseJWTString, bAllowOfflineUsage))
	{
		printf("License OK\n");
	}
	else
	{
		printf("License fail\n");
	}

	DWORD dwOldProt = 0;

#ifdef _M_X64   //no self remapping in x86
#ifndef _DEBUG
	//TEST: Check if sections page protections can be changed after remap
	uintptr_t textSectionStart = GetSectionStart(GetModuleHandleA(NULL), ".text");

	if (textSectionStart == 0)
	{
		std::cerr << "Failed to find .text section start address.\n";
		testResult = 4;
	}

	if (VirtualProtect((LPVOID)textSectionStart, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		std::cout << "Text section is writable: test failed, or you compiled with _DYN_LIB defined\n";
		testResult = 5;
	}
	else
	{
		std::cout << "Failed to make text section writable: test passed\n";
	}
#endif
#endif

	const HMODULE k32hMod = GetModuleHandleW(L"kernel32.dll");
	const uintptr_t	k32_text = GetSectionStart(k32hMod, ".text");

	const HMODULE wintrustMod = GetModuleHandleW(L"wintrust.dll");
	const uintptr_t	wintrust_text = GetSectionStart(wintrustMod, ".text");
	
	if (k32_text && VirtualProtect((LPVOID)k32_text, 1024, PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		*(uint8_t*)k32_text = 0xC3; //patch over k32's .text section to show integrity checks work
	}

	if (wintrust_text && VirtualProtect((LPVOID)wintrust_text, 1024, PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		*(uint8_t*)wintrust_text = 0xC3; //patch over k32's .text section to show integrity checks work
	}

	for (int i = 0; i < 10; i++)
	{
		const auto drmViolation = drm->GetViolations();

		for (const auto& violation : drmViolation)
		{
			std::wcout << L"(T: " << violation.timestamp << L") Violation type: " << violation.type << L", at address: " << std::hex << violation.address;
			
			if (violation.description.length() > 0)
				std::wcout << L", description: " << violation.description << std::endl;
			else
				std::wcout << std::endl;
		}

		Sleep(1000);
	}

	delete drm;

	std::cout << "Closing DRM Test program...\n";

	return testResult;
}
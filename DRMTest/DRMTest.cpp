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

	const std::string LicenseServerEndpoint = "http://localhost:5005/"; //replace with your actual license server endpoint
	const std::string LicenseFilePath = "license.jwt"; //path to license file
	const bool bAllowOfflineUsage = false;
	const bool bUsingLicensing = false;
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

	if (bUsingLicensing)
	{
		std::string licenseJWTString;
		std::string line;
		std::ifstream licenseFile(LicenseFilePath);

		while (std::getline(licenseFile, line))
		{
			licenseJWTString += line;
		}

		if (licenseFile.is_open())
			licenseFile.close();

		//extracted x,y from publicKey.pem (generated from dump_xy.py)
		uint8_t pubX[32] = { 0x67,0x9c,0x29,0xc3,0x19,0x61,0x5e,0x7e,0xa4,0x99,0x10,0x1d,0x69,0x3d,0x7c,0xe7,0xc5,0x27,0x6d,0xc8,0x0a,0xa0,0x07,0xe4,0x92,0xea,0x94,0xa5,0x7b,0x14,0x2a,0x32 };
		uint8_t pubY[32] = { 0xf9,0x01,0xb2,0x23,0x2a,0x95,0xe9,0x2f,0xbf,0x79,0xba,0x7d,0xe4,0xd2,0x3e,0xcf,0xaa,0x4e,0xb7,0xfe,0x94,0x4f,0xd7,0x73,0x35,0xc5,0x53,0xcf,0x58,0xa9,0xb2,0x18 };

		//this will fail github actions runners since it requires a server to be present
		if (drm->CheckLicenseVerified(licenseJWTString, bAllowOfflineUsage, pubX, pubY))
		{
			printf("License OK\n");
		}
		else
		{
			printf("License fail\n");
		}
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

	if (bUsingLicensing && !bAllowOfflineUsage)
	    drm->PushHeartbeat(/*bEncryptBody=*/false); //test heartbeat functionality

	delete drm;

	std::cout << "Closing DRM Test program...\n";

	return testResult;
}
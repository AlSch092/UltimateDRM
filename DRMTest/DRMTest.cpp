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

int main()
{
	std::list<std::wstring> lAllowedParents = { L"steam.exe", L"explorer.exe" };
	const bool bAllowOfflineUsage = true;
	const bool bUsingLicensing = true;
	const bool bEnforceHypervisorCheck = true;
	const bool bRequireCodeSigning = false; //in production code, this should be set to true

	DRM* drm = new DRM(bAllowOfflineUsage, bUsingLicensing, bEnforceHypervisorCheck, bRequireCodeSigning, lAllowedParents);

	try
	{
		if (drm->Protect())
		{
			std::cout << "DRM protection applied successfully.\n";
		}
		else
		{
			std::cout << "Failed to apply DRM protection.\n"; //this may trigger if our test .exe isn't code signed
			return -1;
		}
	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << "Error during DRM protection: " << ex.what() << std::endl;
		return -1;
	}

	//TEST: Check if sections page protections can be changed after remap
	uint64_t textSectionStart = (uint64_t)GetModuleHandleA(NULL) + 0x10000; // the drm library forces section alignment to 0x10000, so .text will be at +0x10000

	DWORD dwOldProt = 0;

	if (VirtualProtect((LPVOID)textSectionStart, 0x1000, PAGE_EXECUTE_READWRITE, &dwOldProt))
	{
		std::cout << "Text section is writable: test failed\n";
		return -1;
	}
	else
	{
		std::cout << "Failed to make text section writable: test passed\n";
	}


	delete drm;

	std::cout << "Closing DRM Test program...\n";

	return 0;
}
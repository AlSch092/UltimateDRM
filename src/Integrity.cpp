#include "../include/Integrity.hpp"

/**
 * @brief Calculates the checksum of the .text and .rdata sections of a module
 *
 * This function computes the checksum of a given
 * module, in its .text and .rdata sections
 *
 * @param hMod The module's base/start address in memory
 * 
 * @return The sum of all bytes in the .text and .rdata sections
 *
 * @details N/A
 *
 *  @example DRM.cpp
 *
 * @usage
 * uint64_t result = Integrity::CalculateChecksum(GetModuleHandleA(NULL));
 */
//const uint64_t Integrity::CalculateChecksum(HMODULE hMod)
//{
//	if (hMod == NULL)
//		return 0;
//
//	uint64_t checksum = 0;
//
//	PIMAGE_DOS_HEADER pDoH = (PIMAGE_DOS_HEADER)(hMod);
//	PIMAGE_NT_HEADERS64 pNtH;
//
//	if (pDoH == NULL)
//	{
//#ifdef LOGGING_ENABLED
//		Logger::logf(Err, " PIMAGE_DOS_HEADER was NULL at Integrity::CalculateChecksum\n");
//#endif
//		return 0;
//	}
//
//	pNtH = (PIMAGE_NT_HEADERS64)((PIMAGE_NT_HEADERS64)((PBYTE)hMod + (DWORD)pDoH->e_lfanew));
//
//	if (pNtH == NULL)
//	{
//#ifdef LOGGING_ENABLED
//		Logger::logf(Err, " PIMAGE_NT_HEADERS64 was NULL at Integrity::CalculateChecksum\n");
//#endif
//		return 0;
//	}
//
//	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNtH);
//
//	int nSections = pNtH->FileHeader.NumberOfSections;
//
//	for (int i = 0; i < nSections; i++)
//	{
//		std::string sectionName(reinterpret_cast<const char*>(sectionHeader[i].Name));
//
//		if (sectionName == ".text" || sectionName == ".rdata")
//		{
//			if (sectionHeader[i].SizeOfRawData > 0)
//			{
//				uint64_t sectionChecksum = 0;
//
//				for (DWORD j = 0; j < sectionHeader[i].Misc.VirtualSize; j++)
//				{
//					sectionChecksum += (uint8_t)(hMod + sectionHeader[i].VirtualAddress + j);
//				}
//
//				checksum += sectionChecksum;
//			}
//		}	
//	}
//
//	return checksum;
//}

/**
 * @brief Calculates the checksum of the .text and .rdata sections of a module
 *
 * This function computes the checksum of a given
 * module, in its .text and .rdata sections
 *
 * @param hMod The module's base/start address in memory
 * @param checksum Previous computed checksum of hMod
 * 
 * @return true/false if newly computed checksum equals `checksum` param
 *
 * @details If return false, the module has been modified or tampered with
 *
 *  @example DRM.cpp
 *
 * @usage
 * bool isModified = Integrity::CompareChecksum(GetModuleHandleA(NULL), previous_checksum);
 */
bool Integrity::CompareChecksum(__in const HMODULE hMod, __in const char* section, __in const uint64_t checksum)
{
	uint64_t calculatedChecksum = CalculateChecksumFromSection(hMod, section);
	return (calculatedChecksum == checksum);
}

/**
 * @brief Thread routine for periodic integrity checks
 *
 * This function computes the checksum of modules and compares it to
 * the checksums grabbed at program startup. Runs continuously
 *
 * @param classThisPtr Pointer to an Integrity class object
 * 
 * @return No return value
 *
 * @details if checksums don't match, throws std::runtime_error
 *
 *  @example 
 *
 * @usage
 * PeriodicIntegrityCheckThread = std::make_unique<Thread>(PeriodicIntegrityCheck, nullptr, true, false);
 */
void Integrity::PeriodicIntegrityCheck(LPVOID classThisPtr)
{
	if (classThisPtr == nullptr)
	{
#ifdef LOGGING_ENABLED
		Logger::logfw(Err, L"PeriodicIntegrityCheck called with null class Ptr");
#endif
		throw std::runtime_error("PeriodicIntegrityCheck called with null class Ptr");
	}

	std::this_thread::sleep_for(std::chrono::seconds(3)); //wait a few seconds before starting the checks

	Integrity* integrity = reinterpret_cast<Integrity*>(classThisPtr);

	bool checking = true;
	int counter = 0;

	while (checking)
	{
		uint64_t checksum_main = 0;
		uint64_t prev_checksum = 0;

		if (counter % 2 == 0)
		{
		    checksum_main = Integrity::CalculateChecksumFromSection(GetModuleHandle(NULL), ".text");
		    prev_checksum = integrity->RetrieveModuleChecksum(GetModuleHandle(NULL), ".text"); //fetch checksum gathered at program startup
		}
		else
		{
			checksum_main = Integrity::CalculateChecksumFromSection(GetModuleHandle(NULL), ".rdata");
			prev_checksum = integrity->RetrieveModuleChecksum(GetModuleHandle(NULL), ".rdata");
		}

		if (checksum_main != prev_checksum && prev_checksum != 0)
		{
			//optionally, log to a remote server
#ifdef LOGGING_ENABLED
			Logger::logfw(Detection, L"Checksum for %s is different, tampering detected", (counter % 2 == 0 ? L".text" : L".rdata"));
#endif
			throw std::runtime_error("Integrity check failed: main module checksum mismatch");
		}

		std::wstring fullProcessPath = Services::GetProcessDirectoryW(GetCurrentProcessId());
		fullProcessPath += Process::GetProcessName(GetCurrentProcessId());

		uint64_t diskFileChecksum = GetSectionChecksumFromDisc(fullProcessPath, (counter % 2 == 0 ? ".text" : ".rdata"));

		if (diskFileChecksum != prev_checksum)
		{
#ifdef LOGGING_ENABLED
			Logger::logfw(Detection, L"Checksum for %s on disk is different, tampering detected", (counter % 2 == 0 ? L".text" : L".rdata"));
#endif
			throw std::runtime_error("Integrity check failed: disk file checksum mismatch");
		}


#ifndef _DEBUG
		uint64_t textSectionAddr = Process::GetSectionAddress(GetModuleHandle(NULL), ".text"); //todo: change this to check all pages in .text

		MEMORY_BASIC_INFORMATION mbi = {};
		if (VirtualQuery((LPCVOID)textSectionAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			if (mbi.AllocationProtect != PAGE_EXECUTE_READ)
			{
#ifdef LOGGING_ENABLED
				Logger::logfw(Detection, L".text page was writable");
#endif
				//optionally, log to a remote server
				//throw std::runtime_error("Integrity check failed: .text page protection mismatch");
			}
		}
#endif

		this_thread::sleep_for(std::chrono::seconds(10));
		counter += 1;
	}
}


/**
* @brief Reads a section of a file from disk and computes its hash
* 
 * @param `path`  path to the file on disk
 * 
 * @param `sectionName`  name of the section to read (e.g., ".text")
 * 
 * @return uint64_t checksum representing the .text section of the file
 * 
 * @details This function reads the specified section from a PE file on disk and computes its hash.
 */
uint64_t Integrity::GetSectionChecksumFromDisc(__in const std::wstring path, __in const char* sectionName)
{
	std::vector<uint8_t> sectionBytes;

	std::ifstream file(path, std::ios::binary);
	if (!file)
	{
#ifdef LOGGING_ENABLED
		Logger::logfw(Detection, L"Error reading file: %s @ GetSectionHashFromDisc", path.c_str());
#endif
		return 0;
	}

	IMAGE_DOS_HEADER dosHeader;
	file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
#ifdef LOGGING_ENABLED
		Logger::logfw(Detection, L"Lacking MZ signature in file: %s @ GetSectionHashFromDisc", path.c_str());
#endif
		return 0;
	}

	file.seekg(dosHeader.e_lfanew, std::ios::beg);
	IMAGE_NT_HEADERS ntHeaders;
	file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
	{
#ifdef LOGGING_ENABLED
		Logger::logfw(Detection, L"Invalid PE signature in file: %s @ GetSectionHashFromDisc", path.c_str());
#endif
		return 0;
	}

	IMAGE_SECTION_HEADER sectionHeader;
	bool found = false;

	for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		file.read(reinterpret_cast<char*>(&sectionHeader), sizeof(IMAGE_SECTION_HEADER));
		if (strcmp((const char*)sectionHeader.Name, sectionName) == 0)
		{
			found = true;
			break;
		}
	}

	if (!found)
	{
#ifdef LOGGING_ENABLED
		Logger::logfw(Detection, L".text section not found in file: %s @ GetSectionHashFromDisc", path.c_str());
#endif
		return 0;
	}

	sectionBytes.resize(sectionHeader.SizeOfRawData);
	file.seekg(sectionHeader.PointerToRawData, std::ios::beg);
	file.read(reinterpret_cast<char*>(sectionBytes.data()), sectionHeader.SizeOfRawData);

	BYTE* sectionMemory = new BYTE[sectionHeader.SizeOfRawData];
	memcpy(sectionMemory, sectionBytes.data(), sectionHeader.SizeOfRawData);

	std::wstring processName = path.substr(path.find_last_of(L"\\") + 1);

	HMODULE hMod = GetModuleHandleW(processName.c_str());

	if (!hMod)
	{
#ifdef LOGGING_ENABLED
		Logger::logfw(Detection, L"Failed to get module handle for %s @ GetSectionChecksumFromDisc", processName.c_str());
#endif
		return 0;
	}

	uint64_t sectionChecksum = CalculateChecksumFromSection(hMod, sectionName);

	if (sectionMemory != nullptr)
		delete[] sectionMemory;

	return sectionChecksum;
}

/**
 * @brief Calculates the checksum of a specific section in a module
 *
 * This function computes the checksum of a given section in a module.
 *
 * @param hMod The module's base/start address in memory
 * @param sectionName The name of the section to calculate the checksum for
 *
 * @return The sum of all bytes in the specified section
 *
 * @details N/A
 *
 * @usage
 * const uint64_t result = Integrity::CalculateChecksumFromSection(GetModuleHandleA(NULL), ".text");
 */
 uint64_t Integrity::CalculateChecksumFromSection(HMODULE hMod, const char* sectionName)
{
	if (hMod == NULL || sectionName == nullptr)
		return 0;

	uint64_t checksum = 0;

	auto SectionList = Process::GetSections(Utility::ConvertWStringToString(Process::GetProcessName(GetCurrentProcessId())));
	
	for (auto section : SectionList)
	{
		if (section.name == std::string(sectionName))
		{
			if (section.size > 0)
			{
				uint64_t sectionChecksum = 0;

				uint64_t sectionAddr = (uint64_t)(section.address) + (uint64_t)hMod;

				for (DWORD j = 0; j < section.size; j++)				
					checksum += *(uint8_t*)(sectionAddr + j);
				
				break;
			}	
		}
	}

	return checksum;
}

/**
 * @brief Checks if the loaded module's section hash matches the disk file's section hash
 *
 * This function compares the checksum of a specific section in a loaded module
 * with the checksum of the same section in a file on disk.
 *
 * @param hMod The handle to the loaded module
 * @param sectionName The name of the section to check
 * @param diskFilePath The path to the file on disk
 *
 * @return true if the checksums match, false otherwise
 *
 * @details N/A
 *
 * @usage
 * bool isValid = Integrity::CheckLoadedModuleHashVersusDiskHash(hMod, ".text", L"C:\\path\\to\\file.exe");
 */
bool Integrity::CheckLoadedModuleHashVersusDiskHash(__in const HMODULE hMod, __in const char* sectionName, __in std::wstring diskFilePath)
{
	if (hMod == NULL || sectionName == nullptr || diskFilePath.empty())
		return false;

	uint64_t diskFileSectionChecksum = GetSectionChecksumFromDisc(diskFilePath, sectionName);
	uint64_t loadedModuleSectionChecksum = CalculateChecksumFromSection(hMod, sectionName);

	return (diskFileSectionChecksum == loadedModuleSectionChecksum);
}
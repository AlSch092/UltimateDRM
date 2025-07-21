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
uint64_t Integrity::CalculateChecksum(HMODULE hMod)
{
	if (hMod == NULL)
		return 0;

	uint64_t checksum = 0;

	PIMAGE_DOS_HEADER pDoH = (PIMAGE_DOS_HEADER)(hMod);
	PIMAGE_NT_HEADERS64 pNtH;

	if (pDoH == NULL)
	{
#ifdef LOGGING_ENABLED
		Logger::logf(Err, " PIMAGE_DOS_HEADER was NULL at Integrity::CalculateChecksum\n");
#endif
		return 0;
	}

	pNtH = (PIMAGE_NT_HEADERS64)((PIMAGE_NT_HEADERS64)((PBYTE)hMod + (DWORD)pDoH->e_lfanew));

	if (pNtH == NULL)
	{
#ifdef LOGGING_ENABLED
		Logger::logf(Err, " PIMAGE_NT_HEADERS64 was NULL at Integrity::CalculateChecksum\n");
#endif
		return 0;
	}

	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNtH);

	int nSections = pNtH->FileHeader.NumberOfSections;

	for (int i = 0; i < nSections; i++)
	{
		std::string sectionName(reinterpret_cast<const char*>(sectionHeader[i].Name));

		if (sectionName == ".text" || sectionName == ".rdata")
		{
			if (sectionHeader[i].SizeOfRawData > 0)
			{
				uint64_t sectionChecksum = 0;

				for (DWORD j = 0; j < sectionHeader[i].Misc.VirtualSize; j++)
				{
					sectionChecksum += (uint8_t)(hMod + sectionHeader[i].VirtualAddress + j);
				}

				checksum += sectionChecksum;
			}
		}	
	}

	return checksum;
}

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
bool Integrity::CompareChecksum(HMODULE hMod, uint64_t checksum)
{
	uint64_t calculatedChecksum = CalculateChecksum(hMod);
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
		throw std::runtime_error("PeriodicIntegrityCheck called with null classThisPtr");
	}

	Integrity* integrity = reinterpret_cast<Integrity*>(classThisPtr);

	bool checking = true;
	
	while (checking)
	{
		uint64_t checksum_main = Integrity::CalculateChecksum(GetModuleHandle(NULL));

		if (checksum_main != integrity->ModuleChecksums[GetModuleHandle(NULL)])
		{
			//optionally, log to a remote server
			throw std::runtime_error("Integrity check failed: main module checksum mismatch");
		}

		this_thread::sleep_for(std::chrono::seconds(10));
	}
}
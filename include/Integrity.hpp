#pragma once
#include <stdint.h>
#include "Process.hpp"
#include <unordered_map>

class Integrity final
{
public:

	static uint64_t CalculateChecksum(HMODULE hMod);

	static bool CompareChecksum(HMODULE hMod, uint64_t checksum);

	void StoreModuleChecksum(HMODULE hMod, uint64_t checksum) { ModuleChecksums[hMod] = checksum; }

	uint64_t RetrieveModuleChecksum(HMODULE hMod) { return ModuleChecksums[hMod] != 0 ? ModuleChecksums[hMod] : 0; }

private:

	unordered_map<HMODULE, uint64_t> ModuleChecksums; //stores module checksums for quick access

};
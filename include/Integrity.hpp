#pragma once
#include <stdint.h>
#include "Process.hpp"
#include "Thread.hpp"
#include <unordered_map>


/**
 * @brief Class that deals with checksums and runtime integrity
 *
 */
class Integrity final
{
public:

	Integrity() 
	{
		try
		{
			PeriodicIntegrityCheckThread = std::make_unique<Thread>((LPTHREAD_START_ROUTINE)&PeriodicIntegrityCheck, (LPVOID)this, true, false);
		}
		catch (const std::bad_alloc& ex)
		{
			throw std::runtime_error("Failed to create PeriodicIntegrityCheckThread: " + std::string(ex.what()));
		}
	}

	~Integrity()
	{
		if (PeriodicIntegrityCheckThread && PeriodicIntegrityCheckThread->IsThreadRunning(PeriodicIntegrityCheckThread->GetHandle()))
		{
			PeriodicIntegrityCheckThread->SignalShutdown(TRUE);
			PeriodicIntegrityCheckThread->JoinThread();
		}
	}

	static uint64_t CalculateChecksum(HMODULE hMod);

	static bool CompareChecksum(HMODULE hMod, uint64_t previous_checksum);

	void StoreModuleChecksum(HMODULE hMod, uint64_t checksum) { ModuleChecksums[hMod] = checksum; }
	uint64_t RetrieveModuleChecksum(HMODULE hMod) { return ModuleChecksums[hMod] != 0 ? ModuleChecksums[hMod] : 0; }

private:

	unordered_map<HMODULE, uint64_t> ModuleChecksums; //stores module checksums for quick access

	std::unique_ptr<Thread> PeriodicIntegrityCheckThread = nullptr; //thread for periodic integrity checks

	static void PeriodicIntegrityCheck(LPVOID thisClassPtr); //performs periodic integrity checks on the process and its modules
};
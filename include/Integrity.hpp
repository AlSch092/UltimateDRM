#pragma once
#include <stdint.h>
#include "Process.hpp"
#include "Thread.hpp"
#include <unordered_map>

struct ModuleChecksumData
{
	HMODULE hMod;
	std::wstring Name;
	unordered_map<std::string, uint64_t> SectionChecksums; //stores checksums for each section in the module
};

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

		this->ModuleList = Process::GetLoadedModules(); //get the list of loaded modules at the time of instantiation

		if (this->ModuleList.empty())
		{
#ifdef LOGGING_ENABLED
			Logger::logf(Err, "Failed to retrieve loaded modules during Integrity class instantiation");
#endif
			throw std::runtime_error("Failed to retrieve loaded modules during Integrity class instantiation");
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

	Integrity& operator=(Integrity&& other) = delete; //delete move assignments
	Integrity operator+(Integrity& other) = delete; //delete all arithmetic operators, unnecessary for context
	Integrity operator-(Integrity& other) = delete;
	Integrity operator*(Integrity& other) = delete;
	Integrity operator/(Integrity& other) = delete;

	static uint64_t FindWritableAddress(__in const std::string moduleName, __in const std::string sectionName);

	//static const uint64_t CalculateChecksum(HMODULE hMod);
	static uint64_t CalculateChecksumFromSection(HMODULE hMod, const char* sectionName);

	static bool CompareChecksum(__in const HMODULE hMod, __in const char* section, __in const uint64_t previous_checksum);
	static uint64_t GetSectionChecksumFromDisc(__in const std::wstring path, __in const char* sectionName);

	bool CheckLoadedModuleHashVersusDiskHash(__in const HMODULE hMod, __in const char* sectionName, __in std::wstring diskFilePath);

	void StoreModuleChecksum(ModuleChecksumData module) 
	{
		auto it = std::find_if(this->ModuleChecksums.begin(), this->ModuleChecksums.end(), [module](const ModuleChecksumData& m) { return (module.hMod == m.hMod); });
		
		if (it == this->ModuleChecksums.end())
		{
			this->ModuleChecksums.push_back(module);
		}
	}

	uint64_t RetrieveModuleChecksum(__in const HMODULE hMod, __in const char* section) const
	{
		auto it = std::find_if(this->ModuleChecksums.begin(), this->ModuleChecksums.end(), [hMod](const ModuleChecksumData& m) { return (hMod == m.hMod); });

		if (it == this->ModuleChecksums.end())
		{
			return 0;
		}

		return it->SectionChecksums.at(std::string(section));
	}

private:

	std::vector<ProcessData::MODULE_DATA> ModuleList;

	std::vector<ModuleChecksumData> ModuleChecksums; //stores module checksums for quick access

	std::unique_ptr<Thread> PeriodicIntegrityCheckThread = nullptr; //thread for periodic integrity checks

	static void PeriodicIntegrityCheck(LPVOID thisClassPtr); //performs periodic integrity checks on the process and its modules
};
#pragma once
#include "DRMViolation.hpp"
#include "EventLog.hpp"
#include "XorStr.hpp"
#include "Process.hpp"
#include "Thread.hpp"
#include "DRMSettings.hpp"
#include <mutex>
#include <unordered_map>

/**
 * @brief IntegrityViolation structure tracks anomalies with module integrity
 */
struct IntegrityViolation : public DRMViolation
{
	std::wstring module;
	std::wstring section;

	IntegrityViolation(std::wstring _module, std::wstring _section, std::wstring _description, uintptr_t _address)
		: module(_module), section(_section)
	{
		this->type = DRMViolation::Integrity;
		this->description = _description;
		this->address = _address;
	}

	bool operator==(const IntegrityViolation& other) const noexcept
	{
		return module == other.module && section == other.section && address == other.address;
	}
};

/**
 * @brief ModuleChecksumData holds information about the checksums of each section of a module
 */
struct ModuleChecksumData
{
	HMODULE hMod;
	std::wstring Name;
	std::wstring Path;
	std::unordered_map<std::string, uintptr_t> SectionChecksums; //stores checksums for each section in the module

	bool operator==(const ModuleChecksumData& other) const noexcept
	{
		return hMod == other.hMod && Name == other.Name && Path == other.Path;
	}
};

/**
 * @brief Class that deals with checksums and runtime integrity
 * @details Tracks changes to unwritable sections of all loaded modules, along with checking for abnormal writable pages
 * @details It also compares loaded modules to their files on disc
 */
class Integrity final
{
public:

	Integrity(DRMSettings* s) : Config(s)
	{
		if (s == nullptr)
		{
			throw std::runtime_error("Null pointer error");
		}

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
#ifdef _LOGGING_ENABLED
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

	static uintptr_t FindWritableAddress(__in const std::string moduleName, __in const std::string sectionName);
	static bool IsReturnAddressInModule(__in const uintptr_t RetAddr, __in const wchar_t* module);

	static uintptr_t CalculateChecksumFromSection(const std::string module, const char* sectionName);

	static bool CompareChecksum(__in const std::string module, __in const char* section, __in const uintptr_t previous_checksum);
	static bool CompareChecksumToFileOnDisc(__in const std::wstring& module, __in const char* section, __in const uintptr_t previous_checksum);

	static uintptr_t GetSectionChecksumFromDisc(__in const std::wstring path, __in const char* sectionName);

	bool CheckLoadedModuleHashVersusDiskHash(__in const std::string module, __in const char* sectionName, __in std::wstring diskFilePath);

	static std::list<ProcessData::ImportFunction> FetchHookedIATEntries();
	static bool DoesIATContainHooked();

	void StoreModuleChecksum(__in const ModuleChecksumData& module) 
	{
		auto it = std::find_if(this->ModuleChecksums.begin(), this->ModuleChecksums.end(), [module](const ModuleChecksumData& m) { return (module.hMod == m.hMod); });
		
		if (it == this->ModuleChecksums.end())
		{
			this->ModuleChecksums.push_back(module);
		}
	}

	uintptr_t RetrieveModuleChecksum(__in const HMODULE hMod, __in const char* section) const
	{
		auto it = std::find_if(this->ModuleChecksums.begin(), this->ModuleChecksums.end(), [hMod](const ModuleChecksumData& m) { return (hMod == m.hMod); });

		if (it == this->ModuleChecksums.end())
		{
			return 0;
		}

		return it->SectionChecksums.at(std::string(section));
	}

	std::vector<IntegrityViolation> GetViolations() const noexcept
	{ 
		std::vector<IntegrityViolation> ViolationsListCpy;
		{
			std::lock_guard<std::mutex> lock(ViolationsMutex);
			ViolationsListCpy = this->Violations;
		}

		return ViolationsListCpy;
	}

	void AddViolation(__in const IntegrityViolation& iv, __in const bool bLogToEventLog)
	{
		if (bLogToEventLog)
		{
			EventLog log(L"UDRM");
			
			std::wstring fullEventMsg;

			if (iv.type == DRMViolation::Type::Integrity)
			{
				constexpr auto eventMsg = make_encrypted(L"Integrity violation: ");
				fullEventMsg = eventMsg.decrypt() + iv.description;
			}
			else if (iv.type == DRMViolation::Type::Debugging)
			{
				constexpr auto eventMsg = make_encrypted(L"Debugging violation: ");
				fullEventMsg = eventMsg.decrypt() + iv.description;
			}
			else if (iv.type == DRMViolation::Type::License)
			{
				constexpr auto eventMsg = make_encrypted(L"License violation: ");
				fullEventMsg = eventMsg.decrypt() + iv.description;
			}

			log.error(fullEventMsg);
		}

		std::lock_guard<std::mutex>  lock(ViolationsMutex);
		if (std::find(Violations.begin(), Violations.end(), iv) == Violations.end())
			Violations.push_back(iv);
	}

	mutable std::mutex ViolationsMutex;

private:

	std::vector<ProcessData::MODULE_DATA> ModuleList;

	std::vector<ModuleChecksumData> ModuleChecksums; //stores module checksums for quick access

	std::unique_ptr<Thread> PeriodicIntegrityCheckThread = nullptr; //thread for periodic integrity checks

	static void PeriodicIntegrityCheck(LPVOID thisClassPtr); //performs periodic integrity checks on the process and its modules

	DRMSettings* Config = nullptr; //non-owning pointer; do not delete at class destruction. 

	std::vector<IntegrityViolation> Violations;

	bool bLogViolationsToEventLog = true;

};
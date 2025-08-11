//By AlSch092 @github
#pragma once
#include "../DRMViolation.hpp"
#include "../Settings.hpp"
#include "../Logger.hpp"
#include "../Thread.hpp"
#include "../Definitions.hpp"
#include "../Process.hpp"
#include "../XorStr.hpp"
#include <vector>
#include <functional>
#include <mutex>

#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7FFE0000)

namespace Debugger
{
    enum DebuggerMethod
    {
        NONE = 0,
        EXECUTION_ERROR,

        DEBUG_WINAPI_DEBUGGER,
        DEBUG_PEB,
        DEBUG_HARDWARE_REGISTERS,
        DEBUG_HEAP_FLAG,
        DEBUG_INT3,
        DEBUG_INT2C,
        DEBUG_CLOSEHANDLE,
        DEBUG_DEBUG_OBJECT,
        DEBUG_VEH_DEBUGGER,
        DEBUG_DBK64_DRIVER,
        DEBUG_KERNEL_DEBUGGER,
        DEBUG_TRAP_FLAG,
        DEBUG_DEBUG_PORT,
        DEBUG_PROCESS_DEBUG_FLAGS,
        DEBUG_REMOTE_DEBUGGER,
        DEBUG_DBG_BREAK,
        DEBUG_KNOWN_DEBUGGER_PROCESS,
    };

    /**
     * @brief IntegrityViolation structure tracks anomalies with module integrity
     */
    struct DebuggerViolation : public DRMViolation
    {
        DebuggerMethod type;

        DebuggerViolation(DebuggerMethod type, std::wstring _description) : type(type)
        {
            this->description = _description;
        }

        bool operator==(const DebuggerViolation& other) const noexcept
        {
            return type == other.type && timestamp == other.timestamp;
        }
    };

    /*
        AntiDebug - The AntiDebug class provides Anti-debugging methods, and should be inherited by a "detections" class which implements a set of monitoring routines.
        In this case, we're using the `DebuggerDetections` class to store our detection routines. The routines are stored in `DetectionFunctionList`, where each of them is called on each monitor iteration in `CheckForDebugger()`
    */
    class AntiDebug
    {
    public:
        
        AntiDebug(Settings* s) : Config(s)
        {
            if (s == nullptr)
            {
#ifdef _LOGGING_ENABLED
                Logger::logf(Warning, "Settings object pointer was somehow nullptr, unknown behavior may take place @ AntiDebug::AntiDebug()");
#endif
            }

			auto x64Dbg_str = make_encrypted(L"x64dbg.exe"); //these will be encrypted at compile time, not leaving plaintext in data sections
            auto CE_str = make_encrypted(L"CheatEngine.exe"); //ideally this would be done with an LLVM pass
			auto idaq64_str = make_encrypted(L"idaq64.exe");
			auto CE_x86_64_str = make_encrypted(L"cheatengine-x86_64-SSE4-AVX2.exe");
			auto kd_str = make_encrypted(L"kd.exe");
			auto dbgX_str = make_encrypted(L"DbgX.Shell.exe");

            this->CommonDebuggerProcesses.push_back(x64Dbg_str.decrypt()); //would be better if we stored them encrypted then decrypted them only when actually used
            this->CommonDebuggerProcesses.push_back(CE_str.decrypt());     //currently this only makes static reversing a bit harder
            this->CommonDebuggerProcesses.push_back(idaq64_str.decrypt());
            this->CommonDebuggerProcesses.push_back(CE_x86_64_str.decrypt());
            this->CommonDebuggerProcesses.push_back(kd_str.decrypt());
            this->CommonDebuggerProcesses.push_back(dbgX_str.decrypt());
        }

        ~AntiDebug()
        {
			if (this->DetectionThread != nullptr)
			{
                this->DetectionThread->SignalShutdown(TRUE);
                this->DetectionThread->JoinThread();
                this->DetectionThread.reset();
			}
        } 

        AntiDebug operator+(AntiDebug& other) = delete; //delete all arithmetic operators, unnecessary for context
        AntiDebug operator-(AntiDebug& other) = delete;
        AntiDebug operator*(AntiDebug& other) = delete;
        AntiDebug operator/(AntiDebug& other) = delete;
        
        Thread* GetDetectionThread() const noexcept { return this->DetectionThread.get(); }

        Settings* GetSettings() const noexcept { return this->Config; }

        void StartAntiDebugThread();

        static void CheckForDebugger(LPVOID AD); //thread looping function to monitor, pass AntiDebug* member as `AD`

        static bool HideThreadFromDebugger(HANDLE hThread);
        static void HideAllThreadsFromDebugger();

        template<typename Func>
        void AddDetectionFunction(Func func) //define detection functions in the subclass, `DebuggerDetections`, then add them to the list using this func
        {
            std::lock_guard<std::mutex> lock(this->DetectionRoutineMutex);
            this->DetectionFunctionList.emplace_back(func);
        }

        void RunDetectionFunctions()  //run all detection functions
        {
            std::lock_guard<std::mutex> lock(this->DetectionRoutineMutex);

            for (auto& func : this->DetectionFunctionList)
            {
                DebuggerMethod DetectedDebugger = NONE;

                if (DetectedDebugger = func()) //call the debugger detection method
                {
                    this->AddFlagged(DebuggerViolation{ DetectedDebugger, L"" });

#ifdef _LOGGING_ENABLED
                    Logger::logf(Info, "Debugger flag detected: %d", DetectedDebugger); //optionally, iterate over DetectedMethods list if you want a more granular logging 
#endif
                }
            }
        }
        
        static void _IsHardwareDebuggerPresent(LPVOID AD); //this func needs to run in its own thread, since it suspends all other threads and checks their contexts for DR's with values. its placed in this class since it doesn't fit the correct definition type for our detection function list

        bool IsDBK64DriverLoaded();

        std::list<DebuggerViolation> GetDetectedMethods() noexcept
        { 
            std::lock_guard<std::mutex> lock(this->FlggedListMutex);
            return this->DetectedMethods;
        }

    protected:
        std::vector<std::function<DebuggerMethod()>> DetectionFunctionList; //list of debugger detection methods, which are contained in the subclass `DebuggerDetections`      
        std::list<std::wstring> CommonDebuggerProcesses;

        void AddFlagged(const DebuggerViolation& method)
        { 
            std::lock_guard<std::mutex> lock(FlggedListMutex);
            if (std::find(this->DetectedMethods.begin(), this->DetectedMethods.end(), method) == this->DetectedMethods.end())
                this->DetectedMethods.push_back(method);
        }
		
    private:      

        std::unique_ptr<Thread> DetectionThread = nullptr; //set in `StartAntiDebugThread`
        std::list<DebuggerViolation> DetectedMethods; //list of detection routines which are each executed once per loop. must have bool return type with no args

        Settings* Config = nullptr;

        const std::wstring DBK64Driver = L"DBK64.sys"; //DBVM debugger, this driver loaded and in a running state may likely indicate the presence of dark byte's VM debugger *todo -> add check on this driver*

        std::mutex DetectionRoutineMutex;
        std::mutex FlggedListMutex;
    };
}
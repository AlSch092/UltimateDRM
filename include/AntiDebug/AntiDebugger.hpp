//By AlSch092 @github
#pragma once

#include "../Settings.hpp"
#include "../Logger.hpp"
#include "../Thread.hpp"
#include "../Definitions.hpp"
#include "../Process.hpp"
#include "../XorStr.hpp"
#include <vector>
#include <functional>

#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7FFE0000)

namespace Debugger
{
    enum DebuggerMethod
    {
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
#ifdef LOGGING_ENABLED
                Logger::logf(Warning, "Settings object pointer was somehow nullptr, unknown behavior may take place @ AntiDebug::AntiDebug()");
#endif
            }

            CommonDebuggerProcesses.push_back(L"x64dbg.exe"); //strings should be encrypted in a live environment
            CommonDebuggerProcesses.push_back(L"CheatEngine.exe");
            CommonDebuggerProcesses.push_back(L"idaq64.exe");
            CommonDebuggerProcesses.push_back(L"cheatengine-x86_64-SSE4-AVX2.exe");
            CommonDebuggerProcesses.push_back(L"kd.exe");
            CommonDebuggerProcesses.push_back(L"DbgX.Shell.exe");
        }

        ~AntiDebug()
        {
			if (DetectionThread != nullptr)
			{
				DetectionThread->SignalShutdown(TRUE);
                DetectionThread->JoinThread();
				DetectionThread.reset();
			}
        } 

        AntiDebug operator+(AntiDebug& other) = delete; //delete all arithmetic operators, unnecessary for context
        AntiDebug operator-(AntiDebug& other) = delete;
        AntiDebug operator*(AntiDebug& other) = delete;
        AntiDebug operator/(AntiDebug& other) = delete;
        
        Thread* GetDetectionThread() const  { return this->DetectionThread.get(); }

        Settings* GetSettings() const { return this->Config; }

        void StartAntiDebugThread();

        static void CheckForDebugger(LPVOID AD); //thread looping function to monitor, pass AntiDebug* member as `AD`

        static bool PreventWindowsDebuggers(); //experimental method, patch DbgBreakpoint + DbgUiRemoteBreakin

        static bool HideThreadFromDebugger(HANDLE hThread);

        template<typename Func>
        void AddDetectionFunction(Func func) //define detection functions in the subclass, `DebuggerDetections`, then add them to the list using this func
        {
            DetectionFunctionList.emplace_back(func);
        }

        bool RunDetectionFunctions()  //run all detection functions
        {
            bool DetectedDebugger = false;

            for (auto& func : DetectionFunctionList)
            {
                if (DetectedDebugger = func()) //call the debugger detection method
                { //...if debugger was found, optionally take further action below (detected flags are already set in each routine, so this block is empty)
                }
            }

            return DetectedDebugger;
        }

        static void _IsHardwareDebuggerPresent(LPVOID AD); //this func needs to run in its own thread, since it suspends all other threads and checks their contexts for DR's with values. its placed in this class since it doesn't fit the correct definition type for our detection function list

        bool IsDBK64DriverLoaded();

    protected:
        std::vector<std::function<bool()>> DetectionFunctionList; //list of debugger detection methods, which are contained in the subclass `DebuggerDetections`      
        std::list<std::wstring> CommonDebuggerProcesses;

        void AddFlagged(DebuggerMethod method) { if (std::find(DetectedMethods.begin(), DetectedMethods.end(), method) == DetectedMethods.end()) DetectedMethods.push_back(method); }
		const std::list<DebuggerMethod>& GetDetectedMethods() { return DetectedMethods; }

    private:      

        std::unique_ptr<Thread> DetectionThread = nullptr; //set in `StartAntiDebugThread`

        Settings* Config = nullptr;

        const std::wstring DBK64Driver = L"DBK64.sys"; //DBVM debugger, this driver loaded and in a running state may likely indicate the presence of dark byte's VM debugger *todo -> add check on this driver*

		std::list<DebuggerMethod> DetectedMethods;
    };
}
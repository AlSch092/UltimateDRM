#pragma once
#include "AntiDebugger.hpp"

using namespace Debugger;

class DebuggerDetections final  : public Debugger::AntiDebug
{
public:
    DebuggerDetections(Settings* s) : Debugger::AntiDebug(s)
    {
        HideAllThreadsFromDebugger();
        
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsDebuggerPresent(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsDebuggerPresent_HeapFlags(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsDebuggerPresent_CloseHandle(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsDebuggerPresent_RemoteDebugger(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsDebuggerPresent_VEH(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsDebuggerPresent_PEB(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsDebuggerPresent_DebugPort(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsDebuggerPresent_ProcessDebugFlags(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsKernelDebuggerPresent(); });
        AddDetectionFunction([this]() -> DebuggerMethod { return _IsKernelDebuggerPresent_SharedKData(); });
        //AddDetectionFunction([this]() -> DebuggerMethod { return _ExitCommonDebuggers(); });
    }

    DebuggerMethod _IsDebuggerPresent();
    DebuggerMethod _IsDebuggerPresent_HeapFlags();
    DebuggerMethod _IsDebuggerPresent_CloseHandle();
    DebuggerMethod _IsDebuggerPresent_RemoteDebugger();
    DebuggerMethod _IsDebuggerPresent_VEH();
    DebuggerMethod _IsDebuggerPresent_PEB();
    DebuggerMethod _IsDebuggerPresent_DebugPort();
    DebuggerMethod _IsDebuggerPresent_ProcessDebugFlags();
    DebuggerMethod _IsKernelDebuggerPresent();
    DebuggerMethod _IsKernelDebuggerPresent_SharedKData();
    DebuggerMethod _ExitCommonDebuggers(); //call ExitProcess in a remote thread on common debuggers
};
//By AlSch092 @github
#include "../../include/AntiDebug/AntiDebugger.hpp"

/*
	StartAntiDebugThread - creates a new thread on `CheckForDebugger`
*/
void Debugger::AntiDebug::StartAntiDebugThread()
{
	if (this->GetSettings() != nullptr && !this->GetSettings()->bUseAntiDebugging)
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Info, "Anti-Debugger was disabled in settings, debugging will be allowed");
#endif
		return;
	}

	this->DetectionThread = make_unique<Thread>((LPTHREAD_START_ROUTINE)Debugger::AntiDebug::CheckForDebugger, (LPVOID)this, true, false);

#ifdef _LOGGING_ENABLED
	Logger::logf(Info, "Created Debugger detection thread with Id: %d", this->DetectionThread->GetId());
#endif
}

/*
	CheckForDebugger - Thread function which loops and checks for the presense of debuggers
*/
void Debugger::AntiDebug::CheckForDebugger(LPVOID AD)
{
	if (AD == nullptr)
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Err, "AntiDbg class was NULL @ CheckForDebugger");
#endif
		return;
	}

	Debugger::AntiDebug* AntiDbg = reinterpret_cast<Debugger::AntiDebug*>(AD);

#ifdef _LOGGING_ENABLED
	Logger::logf(Info, "STARTED Debugger detection thread");
#endif

	bool MonitoringDebugger = true;

	const int MonitorLoopDelayMS = 1000;

	while (MonitoringDebugger)
	{
		if (AntiDbg == NULL)
		{
#ifdef _LOGGING_ENABLED
			Logger::logf(Err, "AntiDbg class was NULL @ CheckForDebugger");
#endif
			return;
		}

		if (AntiDbg->DetectionThread->IsShutdownSignalled())
		{
#ifdef _LOGGING_ENABLED
			Logger::logf(Info, "Shutting down Debugger detection thread with Id: %d", AntiDbg->DetectionThread->GetId());
#endif
			return; //exit thread
		}

		std::thread CheckHardwareRegistersThread = std::thread(&_IsHardwareDebuggerPresent, AntiDbg);
		CheckHardwareRegistersThread.detach();

		AntiDbg->RunDetectionFunctions();

		if (AntiDbg->IsDBK64DriverLoaded())
		{
			AntiDbg->AddFlagged(DebuggerViolation{ DebuggerMethod::DEBUG_DBK64_DRIVER, L"" });
		}

		this_thread::sleep_for(std::chrono::milliseconds(MonitorLoopDelayMS)); //ease the CPU a bit
	}
}

/*
	_IsHardwareDebuggerPresent - suspends threads + Checks debug registers for Dr0-3,6,7 being > 0
*/
void Debugger::AntiDebug::_IsHardwareDebuggerPresent(LPVOID AD)
{
	if (AD == nullptr)
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Err, "AntiDbg class was NULL @ _IsHardwareDebuggerPresent");
#endif
		return;
	}

	Debugger::AntiDebug* AntiDbg = reinterpret_cast<Debugger::AntiDebug*>(AD);

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Err, "Error: unable to create toolhelp snapshot: %d\n", GetLastError());
#endif
		return;
	}

	DWORD currentProcessID = GetCurrentProcessId();

	if (Thread32First(hThreadSnap, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == currentProcessID && te32.th32ThreadID != GetCurrentThreadId())
			{
				HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);

				if (hThread == NULL)
				{
#ifdef _LOGGING_ENABLED
					Logger::logf(Warning, "Error: unable to OpenThread on thread with id %d\n", te32.th32ThreadID);
#endif
					continue;
				}

				SuspendThread(hThread);

				CONTEXT context;
				context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

				if (GetThreadContext(hThread, &context))
				{
					if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3 || context.Dr6 || context.Dr7)
					{
#ifdef _LOGGING_ENABLED
						Logger::logf(Detection, "Found at least one debug register enabled (hardware debugging)");
#endif
						ResumeThread(hThread);

						AntiDbg->AddFlagged(DebuggerViolation{ DebuggerMethod::DEBUG_HARDWARE_REGISTERS, L"" });

						CloseHandle(hThreadSnap);
						CloseHandle(hThread);
						return;
					}
				}
				else
				{
#ifdef _LOGGING_ENABLED
					Logger::logf(Err, "GetThreadContext failed with: %d", GetLastError());
#endif
					ResumeThread(hThread);
					CloseHandle(hThread);
					continue;
				}

				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}
	else
	{
#ifdef _LOGGING_ENABLED
		Logger::logf(Err, "Thread32First Failed: %d\n", GetLastError());
#endif
		return;
	}

	CloseHandle(hThreadSnap);
	return;
}

/*
	HideThreadFromDebugger - hides `hThread` from windows debuggers by calling NtSetInformationThread
	returns `true` on success
*/
bool Debugger::AntiDebug::HideThreadFromDebugger(HANDLE hThread)
{
	typedef NTSTATUS(NTAPI* pNtSetInformationThread) (HANDLE, UINT, PVOID, ULONG);
	NTSTATUS Status;

	HMODULE hMod = GetModuleHandleA("ntdll.dll");

	if (!hMod)
		hMod = LoadLibraryA("ntdll.dll");

	pNtSetInformationThread NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hMod, "NtSetInformationThread");

	if (NtSetInformationThread == NULL)
		return false;

	if (hThread == NULL)
		Status = NtSetInformationThread(GetCurrentThread(), 0x11, 0, 0);
	else
		Status = NtSetInformationThread(hThread, 0x11, 0, 0);

	return (Status == 0);
}

bool Debugger::AntiDebug::IsDBK64DriverLoaded()
{
	return Services::IsDriverRunning(this->DBK64Driver);
}

void Debugger::AntiDebug::HideAllThreadsFromDebugger()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "Failed to create snapshot." << std::endl;
#endif
		return;
	}

	DWORD pid = GetCurrentProcessId();

	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnapshot, &te))
	{
		do
		{
			if (te.th32OwnerProcessID == pid)
			{
				HANDLE hThread = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);

				if (!hThread)
				{
#ifdef _LOGGING_ENABLED
					std::cerr << "Failed to open thread: " << GetLastError() << std::endl;
#endif
					continue;
				}

				if (!Debugger::AntiDebug::HideThreadFromDebugger(hThread)) //hide thread from debuggers, placing this in the TLS callback allows all threads to be hidden
				{
#ifdef _LOGGING_ENABLED
					Logger::logf(Warning, " Failed to hide thread from debugger @ TLSCallback: thread id %d\n", GetCurrentThreadId());
#endif
				}

				CloseHandle(hThread);
			}
		} while (Thread32Next(hSnapshot, &te));
	}
	else 
	{
#ifdef _LOGGING_ENABLED
		std::cerr << "Failed to retrieve thread information." << std::endl;
#endif
	}

	CloseHandle(hSnapshot);
}
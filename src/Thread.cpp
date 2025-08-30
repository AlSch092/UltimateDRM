//By AlSch092 @ Github
#include "../include/Thread.hpp"

/**
 * @brief Starts execution of the current class object's thread
 *
 * @param toExecute The function pointer to the thread routine to execute
 * @param lpOptionalParam Additional argument to pass to the thread routine
 * @param shouldRunForever If true, the thread will run indefinitely until signaled to stop
 * @param shouldDetach If true, the thread will be detached from the caller thread, allowing it to run independently
 * 
 * @return true/false if the thread was successfully started
 *
 * @usage
 * bool threadStarted = ThreadObj->BeginExecution(MyThreadFunction, myParam, true, false);
 */
bool Thread::BeginExecution(LPTHREAD_START_ROUTINE toExecute, LPVOID lpOptionalParam, bool shouldRunForever, bool shouldDetach)
{
    if (toExecute != NULL)
    {
        this->ExecutionAddress = (DWORD_PTR)toExecute;
        this->OptionalParam = lpOptionalParam;
        this->ShouldRunForever = shouldRunForever;

        try
        {
            // Use a lambda to wrap the LPTHREAD_START_ROUTINE for std::thread
            this->t = std::thread([toExecute, lpOptionalParam]() { toExecute(lpOptionalParam); });

            this->handle = t.native_handle(); // Get the native handle
            this->Id = GetThreadId(this->handle); //the std::thread's id won't be the same as windows thread ids, so use the native handle to get the tid which we can use with winapi

            if (shouldDetach)
                t.detach();

            Tick = std::chrono::steady_clock::now();

            return true;
        }
        catch (const std::system_error& e)
        {
#ifdef ENABLE_LOGGING
            Logger::logf(Err, "std::thread failed @ BeginExecution: %s\n", e.what());
#endif
            this->Id = NULL;
            return false;
        }
    }
    else
    {
#ifdef ENABLE_LOGGING
        Logger::logf(Warning, "`toExecute` parameter was NULL @ BeginExecution");
#endif
        return false;
    }
}

/**
 * @brief Checks if object's thread is currently running
 *
 * @param threadHandle Handle to the thread to check
 *
 * @return true/false if the thread is currently running or not
 *
 * @usage
 * bool isThreadRunning = Thread::IsThreadRunning(myThreadHandle);
 */
bool Thread::IsThreadRunning(HANDLE threadHandle)
{
    if (threadHandle == NULL)
        return false;

    DWORD exitCode;

    if (GetExitCodeThread(threadHandle, &exitCode) != 0)
    {
        return (exitCode == STILL_ACTIVE);
    }
#ifdef ENABLE_LOGGING
    Logger::logf(Err, " GetExitCodeThread failed @ IsThreadRunning: %d\n", GetLastError());
#endif
    return false;
}

/**
 * @brief Checks if object's thread is currently suspended
 *
 * @param tid Thread ID of the thread to check
 *
 * @return true/false if the thread is currently suspended or not
 *
 * @usage
 * bool isThreadSuspended = Thread::IsThreadSuspended(GetCurrentThreadId());
 */
bool Thread::IsThreadSuspended(DWORD tid)
{
    if (tid == 0)
        return false;

    bool suspended = false;
    DWORD suspendCount = 0;

    HANDLE threadHandle = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);

    if (threadHandle == INVALID_HANDLE_VALUE || threadHandle == 0)
        return false;

    __try
    {
        suspendCount = SuspendThread(threadHandle); //warning: invalid handle will throw exception here
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }

    if (suspendCount == (DWORD)-1)
    {
        return false;
    }
    else if (suspendCount > 0) //already suspended by someone else
    {
        ResumeThread(threadHandle);
        suspended = true;
    }
    else
    {
        ResumeThread(threadHandle);
    }

    return suspended;
}
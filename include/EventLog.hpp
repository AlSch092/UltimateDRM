#pragma once
#include <windows.h>
#include <string>

class EventLog 
{
    HANDLE h_ = nullptr;
public:
    explicit EventLog(const wchar_t* sourceName) 
    {
        // Writes to "Windows Logs -> Application"
        h_ = RegisterEventSourceW(nullptr, sourceName);
    }

    ~EventLog() 
    { 
        if (h_) 
            DeregisterEventSource(h_); 
    }

    void info(const std::wstring& msg) { write(EVENTLOG_INFORMATION_TYPE, msg); }
    void warn(const std::wstring& msg) { write(EVENTLOG_WARNING_TYPE, msg); }
    void error(const std::wstring& msg) { write(EVENTLOG_ERROR_TYPE, msg); }

private:
    void write(WORD type, const std::wstring& msg) 
    {
        if (!h_) 
            return;

        LPCWSTR strings[1] = { msg.c_str() };

        // EventID=0 is fine; without a message DLL, Viewer shows the text under "Event Data"
        ReportEventW(h_, type, 0, 0, nullptr,1, 0, strings, nullptr);
    }
};


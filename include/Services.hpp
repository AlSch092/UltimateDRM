//By AlSch092 @ Github
#pragma once
#include "Logger.hpp"
#include "NAuthenticode.hpp"
#include "Utility.hpp"
#include "HttpClient.hpp"

#include <Psapi.h>
#include <TlHelp32.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <tchar.h>
#include <intrin.h>
#include <sstream>

#pragma comment(lib, "setupapi.lib")

using namespace std;

extern "C" NTSTATUS NTAPI RtlGetVersion(RTL_OSVERSIONINFOW * lpVersionInformation); //used in GetWindowsVersion

struct Service
{
	wstring displayName;
	wstring serviceName;
	DWORD pid;
	bool isRunning;
};

struct Device
{
	string InstanceID;
	string Description;
};

struct DeviceW
{
	wstring InstanceID;
	wstring Description;
};

enum WindowsVersion
{									//Major,Minor :
	Windows2000 = 50,				//5,0
	WindowsXP = 51,			                //5,1
	WindowsXPProfessionalx64 = 52,	                //5,2
	WindowsVista = 60,				//6,0
	Windows7 = 61,					//6,1
	Windows8 = 62,					//6,2
	Windows8_1 = 63,				//6,3
	Windows10 = 10,					//10
	Windows11 = 11,					//10  -> build number changes 

	ErrorUnknown = 0
};

/*
The Services class deals with keeping track of loaded drivers & services/recurring tasks on the system, along with misc helpful windows functions such as DSE checks, secure boot, device enumeration, etc
*/
class Services final
{
public:

	Services()
	{

		HardwareDevices = GetHardwareDevicesW(); //fetch PCI devices
		GetLoadedDrivers();
		GetServiceModules();	
	}

	~Services()
	{
		for (auto it = ServiceList.begin(); it != ServiceList.end(); ++it) 
			if(*it != nullptr)
				delete* it;
		
		ServiceList.clear();
	}

	Services operator+(Services& other) = delete; //delete all arithmetic operators, unnecessary for context
	Services operator-(Services& other) = delete;
	Services operator*(Services& other) = delete;
	Services operator/(Services& other) = delete;

	BOOL GetLoadedDrivers(); //adds to `DriverPaths`
	BOOL GetServiceModules(); //adds to `ServiceList`

	list<wstring> GetUnsignedDrivers();
	list<wstring> GetUnsignedDrivers(__in list<wstring>& cachedVerifiedDriverList);

	static BOOL IsTestsigningEnabled();
	static BOOL IsDebugModeEnabled();
	static BOOL IsSecureBootEnabled();

	static string GetWindowsDrive();
	static wstring GetWindowsDriveW();

	static BOOL IsRunningAsAdmin();

	static list<DeviceW> GetHardwareDevicesW();
	static BOOL CheckUSBDevices();

	static WindowsVersion GetWindowsVersion();
	
	static bool IsHypervisorPresent();
	static string GetHypervisorVendor();
	static string GetCPUVendor();
	
	static string GetProcessDirectory(__in const DWORD pid); //fetch the directory of `pid`
	static wstring GetProcessDirectoryW(__in const DWORD pid); //fetch the directory of `pid`

	static list<DWORD> EnumerateProcesses(); //fetch process list

	static bool LoadDriver(__in const std::wstring& serviceName, __in const std::wstring& driverPath); //load `driverPath` with service name `driverName`
	static bool UnloadDriver(__in const std::wstring& serviceName);
	static bool IsDriverRunning(__in const std::wstring& serviceName); //check if a driver is loaded & in a running state

private:

	list<Service*> ServiceList;
	list <wstring> DriverPaths; //list of all loaded drivers
	list<DeviceW> HardwareDevices;
};
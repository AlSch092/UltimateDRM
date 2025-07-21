#pragma once
#include "Settings.hpp"

/*
    The PIMPL idiom hides implementation details for static libraries. The actual implementation and members of the class are in DRM.cpp
*/
class DRM 
{
public:
	explicit DRM(
		const std::string& LicenseServerEndpoint,
		const bool bAllowOfflineUsage, 
		const bool bUsingLicensing, 
		const bool bCheckHypervisor, 
		const bool bRequireCodeSigning, 
		const std::list<std::wstring> lAllowedParents);

	bool Protect();

	DRM(DRM&&) = delete;
	DRM& operator=(DRM&&) noexcept = default;
	DRM(const DRM&) = delete;
	DRM& operator=(const DRM&) = delete;

private:
	struct Impl;
	Impl* pImpl;
};
#pragma once
#include "Settings.hpp"

class DRM 
{
public:
	explicit DRM(const bool bAllowOfflineUsage, 
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
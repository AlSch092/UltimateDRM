#pragma once
//#define _TARGET_STATIC_LIB //if you're building this .lib into a .DLL, comment this line and uncomment the below line
#define _TARGET_DYN_LIB
#include "Settings.hpp"
#include "DRMException.hpp"
  
/**
 * @brief DRMViolation struct tracks memory and resource changes in the runtime environment
 *
 * A list of violations can be queried from the DRM class, allowing non-library classes to see detections
 */
struct DRMViolation
{
	uintptr_t address;
	std::string description;
};

/**
 * @brief The PIMPL idiom hides implementation details for static libraries. The actual implementation and members of the class are in DRM.cpp
 *
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
		const std::list<std::wstring> lAllowedParents,
		const bool bShutdownOnViolation
	);

	bool Protect();

	auto GetViolations() const { return this->Violations; } //how to access integrity violations?

	DRM(DRM&&) = delete;
	DRM& operator=(DRM&&) noexcept = default;
	DRM(const DRM&) = delete;
	DRM& operator=(const DRM&) = delete;

private:
	struct Impl;
	Impl* pImpl;

	std::vector<DRMViolation> Violations; //list of violations
};
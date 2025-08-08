#pragma once
#define _TARGET_STATIC_LIB //if you're building this .lib into a .DLL, comment this line and uncomment the below line
//#define _TARGET_DYN_LIB

#include "Settings.hpp"
#include "DRMException.hpp"
  
/**
 * @brief DRMViolation struct tracks memory and resource changes in the runtime environment
 *
 * A list of violations can be queried from the DRM class, allowing non-library classes to see detections
 */
struct DRMViolation
{
	enum Type
	{
		Integrity = 1,
		Debugging,
		License,
		CodeSignature,
	};

	Type type;
	uintptr_t address;
	std::wstring description;
	uint64_t timestamp = 0;
};

/**
 * @brief The PIMPL idiom hides implementation details for static libraries. The actual implementation and members of the class are in DRM.cpp
 *
 */
class UltimateDRM 
{
public:
	explicit UltimateDRM(Settings* s);

	bool Protect();

	std::vector<DRMViolation> GetViolations() const noexcept;

	UltimateDRM(UltimateDRM&&) = delete;
	UltimateDRM& operator=(UltimateDRM&&) noexcept = default;
	UltimateDRM(const UltimateDRM&) = delete;
	UltimateDRM& operator=(const UltimateDRM&) = delete;

private:
	struct Impl;
	Impl* pImpl;

	std::vector<DRMViolation> Violations; //list of violations
};
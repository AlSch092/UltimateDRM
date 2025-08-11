#pragma once
//#define _TARGET_STATIC_LIB //if you're building this .lib into a .DLL, comment this line and uncomment the below line
#define _TARGET_DYN_LIB

#include "Settings.hpp"
#include "DRMException.hpp"
#include "DRMViolation.hpp"
  
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
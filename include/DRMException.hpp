#pragma once
#include <stdexcept>
#include <exception>
#include <string>
#include <unordered_map>

/**
 * @brief DRMException class for handling DRM-related exceptions
 *
 * This class provides a way to throw and catch specific DRM-related errors with detailed descriptions.
 * It inherits from std::exception and overrides the what() method to return error descriptions.
 */
class DRMException final : public std::exception
{
public:

	enum ErrorCode
	{
		UnknownError = 0,
		GenericError,
		LicenseVerificationFailed,
		HypervisorDetected,
		CodeSigningFailed,
		IntegrityCheckFailed,
		DebuggerDetected,
		MultipleInstancesDetected,
		ServiceLoadFailed,
		ServiceUnloadFailed
	};

	DRMException(ErrorCode err) : err(err) {}

	const char* what() const throw()
	{
		return errorDetails.at(err).c_str();
	}

private:

	ErrorCode err = UnknownError;

	const std::unordered_map<ErrorCode, std::string> errorDetails =
	{
        { UnknownError, "Unknown Error" },
		{ GenericError, "Generic error related to memory or information querying" },
		{ LicenseVerificationFailed, "License verification failed" },
		{ HypervisorDetected, "Hypervisor detected" },
		{ CodeSigningFailed, "Code signing verification failed" },
		{ IntegrityCheckFailed, "Integrity check failed" },
		{ DebuggerDetected, "Debugger detected" },
		{ MultipleInstancesDetected, "Multiple instances of the application are not allowed" },
		{ ServiceLoadFailed, "Failed to load required service" },
		{ ServiceUnloadFailed, "Failed to unload required service" }
	};
};

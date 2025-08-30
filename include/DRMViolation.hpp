#pragma once
#include <string>
#include <stdint.h>
#include <chrono>

/**
 * @brief DRMViolation struct tracks memory and resource changes in the runtime environment
 *
 * A list of violations can be queried from the DRM class, allowing non-library classes to see detections
 */
struct DRMViolation
{
public:
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
	uint64_t timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

	//DRMViolation(__in const Type t, __in const uintptr_t addr, __in const std::wstring desc) : type(t), address(addr), description(desc)
	//{
	//}

	bool operator =(const DRMViolation& other)
	{
		return this->type == other.type && this->address == other.address; //can also add == for timestamp but this should be enough
	}
};
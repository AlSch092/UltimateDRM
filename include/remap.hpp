//thanks to changeofpace for remapping method!
//Original Self-Remapping-Code project can be found at: https://github.com/changeofpace/self-remapping-code

#pragma once

#include <Windows.h>

//=============================================================================
// Public Interface
//=============================================================================
_Check_return_ BOOL RmpRemapImage(_In_ ULONG_PTR ImageBase);

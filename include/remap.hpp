//thanks to changeofpace for remapping method!
//Original Self-Remapping-Code project can be found at: https://github.com/changeofpace/self-remapping-code

#pragma once
#ifdef _M_X64
#include <Windows.h>

//=============================================================================
// Public Interface
//=============================================================================
_Check_return_ BOOL RmpRemapImage(_In_ ULONG_PTR ImageBase);

#endif //_M_X64
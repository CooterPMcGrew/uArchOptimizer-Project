#pragma once
#include <string>

// Returns the microarchitecture name based on a known CPU brand string
std::wstring MapBrandToMicroarchitecture(const std::wstring& brand);

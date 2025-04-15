#include "microarch_mapper.h"
#include <algorithm>
#include <string>
#include <locale>
#include <iostream>

// Helper function to convert a wstring to lowercase
std::wstring ToLower(const std::wstring& str)
{
    std::wstring lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), towlower);
    return lowerStr;
}

std::wstring MapBrandToMicroarchitecture(const std::wstring& brand)
{
    std::wstring lower = ToLower(brand); // make lowercase for comparison

    //std::wcout << L"[DEBUG] Lowercase Brand: " << lower << std::endl;

    if (lower.find(L"12900") != std::wstring::npos ||
        lower.find(L"12700") != std::wstring::npos ||
        lower.find(L"12th gen") != std::wstring::npos)
        return L"Alder Lake (Intel 12th Gen)";

    else if (lower.find(L"13700") != std::wstring::npos ||
        lower.find(L"13900") != std::wstring::npos)
        return L"Raptor Lake (Intel 13th Gen)";

    else if (lower.find(L"11700") != std::wstring::npos ||
        lower.find(L"11900") != std::wstring::npos)
        return L"Rocket Lake (Intel 11th Gen)";

    else
        return L"Unknown or Unmapped Microarchitecture";
}
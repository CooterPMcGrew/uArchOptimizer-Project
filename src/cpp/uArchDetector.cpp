#include "microarch_mapper.h"
#include <algorithm>
#include <string>
#include <locale>
#include <iostream>
#include <regex>

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

    // Intel 14th Gen
    if (lower.find(L"14900") != std::wstring::npos ||
        lower.find(L"14700") != std::wstring::npos ||
        lower.find(L"14600") != std::wstring::npos ||
        lower.find(L"14th gen") != std::wstring::npos)
        return L"Meteor Lake (Intel 14th Gen)";

    // Intel 13th Gen
    else if (lower.find(L"13900") != std::wstring::npos ||
        lower.find(L"13700") != std::wstring::npos ||
        lower.find(L"13600") != std::wstring::npos ||
        lower.find(L"13th gen") != std::wstring::npos)
        return L"Raptor Lake (Intel 13th Gen)";

    // Intel 12th Gen
    else if (lower.find(L"12900") != std::wstring::npos ||
        lower.find(L"12700") != std::wstring::npos ||
        lower.find(L"12600") != std::wstring::npos ||
        lower.find(L"12th gen") != std::wstring::npos)
        return L"Alder Lake (Intel 12th Gen)";

    // Intel 11th Gen
    else if (lower.find(L"11900") != std::wstring::npos ||
        lower.find(L"11700") != std::wstring::npos ||
        lower.find(L"11600") != std::wstring::npos ||
        lower.find(L"11th gen") != std::wstring::npos)
        return L"Rocket Lake (Intel 11th Gen)";

    // Intel 10th Gen
    else if (lower.find(L"10900") != std::wstring::npos ||
        lower.find(L"10700") != std::wstring::npos ||
        lower.find(L"10600") != std::wstring::npos ||
        lower.find(L"10th gen") != std::wstring::npos)
        return L"Comet Lake (Intel 10th Gen)";

    // Intel 9th Gen
    else if (lower.find(L"9900") != std::wstring::npos ||
        lower.find(L"9700") != std::wstring::npos ||
        lower.find(L"9600") != std::wstring::npos ||
        lower.find(L"9th gen") != std::wstring::npos)
        return L"Coffee Lake Refresh (Intel 9th Gen)";

    // Intel 8th Gen
    else if (lower.find(L"8700") != std::wstring::npos ||
        lower.find(L"8600") != std::wstring::npos ||
        lower.find(L"8th gen") != std::wstring::npos)
        return L"Coffee Lake (Intel 8th Gen)";

    // AMD Zen 4
    else if (lower.find(L"7950x") != std::wstring::npos ||
        lower.find(L"7900x") != std::wstring::npos ||
        lower.find(L"7800x3d") != std::wstring::npos ||
        lower.find(L"7700x") != std::wstring::npos ||
        lower.find(L"7600x") != std::wstring::npos)
        return L"Zen 4 (AMD Ryzen 7000 Series)";

    // AMD Zen 3
    else if (lower.find(L"5950x") != std::wstring::npos ||
        lower.find(L"5900x") != std::wstring::npos ||
        lower.find(L"5800x") != std::wstring::npos ||
        lower.find(L"5700x") != std::wstring::npos ||
        lower.find(L"5600x") != std::wstring::npos ||
        lower.find(L"5500") != std::wstring::npos)
        return L"Zen 3 (AMD Ryzen 5000 Series)";

    // AMD Zen 2
    else if (lower.find(L"3950x") != std::wstring::npos ||
        lower.find(L"3900x") != std::wstring::npos ||
        lower.find(L"3800x") != std::wstring::npos ||
        lower.find(L"3700x") != std::wstring::npos ||
        lower.find(L"3600x") != std::wstring::npos ||
        lower.find(L"3600") != std::wstring::npos)
        return L"Zen 2 (AMD Ryzen 3000 Series)";

    // AMD Zen+
    else if (lower.find(L"2700x") != std::wstring::npos ||
        lower.find(L"2600x") != std::wstring::npos ||
        lower.find(L"2600") != std::wstring::npos)
        return L"Zen+ (AMD Ryzen 2000 Series)";

    // AMD Zen
    else if (lower.find(L"1800x") != std::wstring::npos ||
        lower.find(L"1700x") != std::wstring::npos ||
        lower.find(L"1600x") != std::wstring::npos ||
        lower.find(L"1600") != std::wstring::npos)
        return L"Zen (AMD Ryzen 1000 Series)";

    // If no specific match, try to extract Intel/AMD generation info using regex
    std::wregex intelRegex(L"intel.*i[3579][-\\s]([0-9]{4,5})", std::regex_constants::icase);
    std::wsmatch intelMatch;
    if (std::regex_search(lower, intelMatch, intelRegex) && intelMatch.size() > 1) {
        std::wstring model = intelMatch[1].str();
        if (!model.empty()) {
            wchar_t gen = model[0]; // First digit indicates generation
            switch (gen) {
                case L'1': return L"Ice Lake / Comet Lake (Intel 10th Gen)";
                case L'9': return L"Coffee Lake Refresh (Intel 9th Gen)";
                case L'8': return L"Coffee Lake (Intel 8th Gen)";
                case L'7': return L"Kaby Lake (Intel 7th Gen)";
                case L'6': return L"Skylake (Intel 6th Gen)";
                case L'5': return L"Broadwell (Intel 5th Gen)";
                case L'4': return L"Haswell (Intel 4th Gen)";
                case L'3': return L"Ivy Bridge (Intel 3rd Gen)";
                case L'2': return L"Sandy Bridge (Intel 2nd Gen)";
            }
        }
    }

    std::wregex amdRegex(L"amd.*ryzen.*([0-9])", std::regex_constants::icase);
    std::wsmatch amdMatch;
    if (std::regex_search(lower, amdMatch, amdRegex) && amdMatch.size() > 1) {
        std::wstring gen = amdMatch[1].str();
        if (!gen.empty()) {
            switch (gen[0]) {
                case L'7': return L"Zen 4 (AMD Ryzen 7000 Series)";
                case L'5': return L"Zen 3 (AMD Ryzen 5000 Series)";
                case L'3': return L"Zen 2 (AMD Ryzen 3000 Series)";
                case L'2': return L"Zen+ (AMD Ryzen 2000 Series)";
                case L'1': return L"Zen (AMD Ryzen 1000 Series)";
            }
        }
    }

    // Check for Intel Atom, Pentium, Celeron
    if (lower.find(L"atom") != std::wstring::npos)
        return L"Intel Atom";
    else if (lower.find(L"pentium") != std::wstring::npos)
        return L"Intel Pentium";
    else if (lower.find(L"celeron") != std::wstring::npos)
        return L"Intel Celeron";
    else if (lower.find(L"xeon") != std::wstring::npos)
        return L"Intel Xeon";

    // Check for AMD Threadripper
    else if (lower.find(L"threadripper") != std::wstring::npos) {
        if (lower.find(L"5") != std::wstring::npos)
            return L"AMD Threadripper (Zen 3)";
        else if (lower.find(L"3") != std::wstring::npos)
            return L"AMD Threadripper (Zen 2)";
        else
            return L"AMD Threadripper";
    }

    // Fallback for Intel/AMD
    else if (lower.find(L"intel") != std::wstring::npos)
        return L"Intel (Unspecified Generation)";
    else if (lower.find(L"amd") != std::wstring::npos)
        return L"AMD (Unspecified Generation)";

    return L"Unknown or Unmapped Microarchitecture";
}